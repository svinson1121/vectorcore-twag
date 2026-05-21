package userplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/gtpu"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	ModeKernelGTP             = "kernel_gtp"
	gtpUEchoModeKernelNetlink = "kernel_netlink"
	gtpUEchoModeKernelSocket  = "kernel_registered_socket"
	genlGTPCmdEchoReq         = 3
	gtpUPort                  = 2152
)

type userEchoObservation struct {
	Peer     *net.UDPAddr
	Sequence uint16
	At       time.Time
}

type UserEchoHealthStatus struct {
	Health              string
	ConsecutiveFailures int
	LastSuccess         time.Time
	LastFailure         time.Time
	LastLatency         time.Duration
	KernelSupported     bool
	Mode                string
}

type UserPlane interface {
	Start(ctx context.Context) error
	Stop() error
	SetErrorIndicationHandler(handler gtpu.ErrorIndicationHandler)
	AddSession(ctx context.Context, sess *session.Session) error
	RemoveSession(ctx context.Context, sess *session.Session) error
	ProbeUserEcho(ctx context.Context) error
	StartUserEchoWatchdog(ctx context.Context)
	Type() string
}

func New(cfg config.Config, log *slog.Logger) (UserPlane, error) {
	return NewKernelGTP(config.UserPlaneConfig{
		Mode:         ModeKernelGTP,
		GTPInterface: cfg.GTP.KernelInterface,
	}, cfg.GTP, cfg.Routing, log), nil
}

type KernelGTP struct {
	cfg          config.UserPlaneConfig
	pgw          config.PGWConfig
	userEchoCfg  config.GTPUserEchoConfig
	routing      config.RoutingConfig
	log          *slog.Logger
	link         netlink.Link
	handle       *netlink.Handle
	nsFile       *os.File
	gtp0         *net.UDPConn
	gtp1         *net.UDPConn
	gtp0FD       int
	gtp1FD       int
	created      bool
	errorHandler gtpu.ErrorIndicationHandler
	ctx          context.Context
	cancel       context.CancelFunc
	readWG       sync.WaitGroup
	echoWG       sync.WaitGroup
	echoMu       sync.Mutex
	echoPending  chan userEchoObservation
	echoSequence uint16
	echoStarted  bool

	healthMu                sync.RWMutex
	gtpuHealth              string
	gtpuEchoSupported       bool
	gtpuEchoDisabled        bool
	gtpuEchoDisableReason   string
	consecutiveEchoFailures int
	lastEchoSuccess         time.Time
	lastEchoFailure         time.Time
	lastEchoLatency         time.Duration
}

func NewKernelGTP(cfg config.UserPlaneConfig, pgw config.PGWConfig, routing config.RoutingConfig, log *slog.Logger) *KernelGTP {
	return &KernelGTP{cfg: cfg, pgw: pgw, userEchoCfg: pgw.UserEcho, routing: routing, log: log, gtpuHealth: "unknown"}
}

func (k *KernelGTP) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	handle, err := netlink.NewHandle(unix.NETLINK_GENERIC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open netlink handle for kernel GTP: %w", err)
	}
	k.handle = handle
	nsFile, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("open current network namespace fd: %w", err)
	}
	k.nsFile = nsFile
	link, err := k.handle.LinkByName(k.cfg.GTPInterface)
	if err == nil {
		if link.Type() != "gtp" {
			return fmt.Errorf("kernel GTP interface %q exists but has type %q", k.cfg.GTPInterface, link.Type())
		}
		return fmt.Errorf("kernel GTP interface %q already exists; delete it before starting TWAG so TWAG can create and own the GTP netdev netlink state", k.cfg.GTPInterface)
	}
	if !isNotFound(err) {
		return fmt.Errorf("lookup kernel GTP interface %q: %w", k.cfg.GTPInterface, err)
	}
	if err := k.createLink(); err != nil {
		return err
	}
	k.log.Info("kernel GTP user plane initialized",
		"gtp_interface", k.cfg.GTPInterface,
		"local_gtpu_ip", k.pgw.LocalGTPUIP,
		"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
		"created", true,
	)
	if err := k.detectUserEchoSupport(); err != nil {
		return err
	}
	k.ctx, k.cancel = context.WithCancel(ctx)
	k.readWG.Add(1)
	go func() {
		defer k.readWG.Done()
		k.readControlLoop(k.ctx)
	}()
	return nil
}

func (k *KernelGTP) Stop() error {
	var errs []error
	k.log.Info("kernel GTP user plane stopping", "gtp_interface", k.cfg.GTPInterface)
	if k.cancel != nil {
		k.cancel()
	}
	k.wakeControlReader()
	k.readWG.Wait()
	k.echoWG.Wait()
	if k.created && k.link != nil {
		if err := k.handle.LinkDel(k.link); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	if k.handle != nil {
		k.handle.Close()
	}
	if k.nsFile != nil {
		errs = append(errs, k.nsFile.Close())
	}
	if k.gtp0 != nil {
		errs = append(errs, k.gtp0.Close())
	}
	if k.gtp1 != nil {
		errs = append(errs, k.gtp1.Close())
	}
	err := errors.Join(errs...)
	if err != nil {
		return err
	}
	k.log.Info("kernel GTP user plane stopped", "gtp_interface", k.cfg.GTPInterface)
	return nil
}

func (k *KernelGTP) wakeControlReader() {
	if k.gtp1 == nil {
		return
	}
	addr, ok := k.gtp1.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return
	}
	_ = k.gtp1.SetReadDeadline(time.Now())
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck
	_, _ = conn.Write([]byte{0})
}

func (k *KernelGTP) AddSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateKernelSession(sess); err != nil {
		return err
	}
	if k.link == nil {
		return fmt.Errorf("kernel GTP user plane is not started")
	}
	link, err := k.currentLink()
	if err != nil {
		return err
	}
	peer := firstIP(sess.PGWUserIP, net.ParseIP(k.pgw.RemotePGWGTPUIP))
	if peer == nil {
		return fmt.Errorf("session %s has no PGW user-plane IP", sess.ID)
	}
	pdp := &netlink.PDP{
		Version:     1,
		PeerAddress: peer,
		MSAddress:   sess.SubscriberIP,
		ITEI:        sess.LocalGTPUTEID,
		OTEI:        sess.RemoteGTPUTEID,
	}
	k.log.Info("kernel GTP PDP add requested",
		"gtp_device_name", k.cfg.GTPInterface,
		"gtp_link_index", link.Attrs().Index,
		"netns", currentNetNS(),
		"userns", currentUserNS(),
		"cap_eff", procStatusField("CapEff"),
		"cap_bnd", procStatusField("CapBnd"),
		"gtp_role", "sgsn",
		"subscriber_ip", sess.SubscriberIP.String(),
		"peer_gtpu_ip", peer.String(),
		"local_rx_teid", sess.LocalGTPUTEID,
		"remote_tx_teid", sess.RemoteGTPUTEID,
		"udp_socket_fd", k.gtp1FD,
		"udp_socket_local_addr", localAddrString(k.gtp1),
		"pdp_attr_version", pdp.Version,
		"pdp_attr_net_ns_fd", fdValue(k.nsFile),
		"pdp_attr_link", link.Attrs().Index,
		"pdp_attr_peer_address", peer.String(),
		"pdp_attr_ms_address", sess.SubscriberIP.String(),
		"pdp_attr_i_tei", pdp.ITEI,
		"pdp_attr_o_tei", pdp.OTEI,
		"netlink_flags", "request|excl|ack",
	)
	if err := k.gtpPDPAdd(link, pdp); err != nil && !isExists(err) {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("add kernel GTP PDP session_id=%s subscriber_ip=%s local_gtpu_teid=%d remote_gtpu_teid=%d peer=%s ifindex=%d netns=%s userns=%s cap_eff=%s udp_socket_fd=%d udp_socket_local_addr=%s: %w; kernel rejected the GTP generic-netlink NEWPDP request before installing the PDP context", sess.ID, sess.SubscriberIP.String(), sess.LocalGTPUTEID, sess.RemoteGTPUTEID, peer.String(), link.Attrs().Index, currentNetNS(), currentUserNS(), procStatusField("CapEff"), k.gtp1FD, localAddrString(k.gtp1), err)
		}
		return fmt.Errorf("add kernel GTP PDP session_id=%s subscriber_ip=%s local_gtpu_teid=%d remote_gtpu_teid=%d peer=%s ifindex=%d netns=%s udp_socket_fd=%d udp_socket_local_addr=%s: %w", sess.ID, sess.SubscriberIP.String(), sess.LocalGTPUTEID, sess.RemoteGTPUTEID, peer.String(), link.Attrs().Index, currentNetNS(), k.gtp1FD, localAddrString(k.gtp1), err)
	}
	installedMainRoute := false
	if !k.routing.PolicyRouting {
		if err := k.handle.RouteReplace(kernelRoute(link, sess.SubscriberIP)); err != nil {
			_ = k.gtpPDPDel(link, &netlink.PDP{Version: 1, ITEI: sess.LocalGTPUTEID})
			return fmt.Errorf("install kernel GTP route for %s: %w", sess.SubscriberIP.String(), err)
		}
		installedMainRoute = true
	}
	if err := k.installPolicyRouting(link, sess); err != nil {
		if installedMainRoute {
			_ = k.handle.RouteDel(kernelRoute(link, sess.SubscriberIP))
		}
		_ = k.gtpPDPDel(link, &netlink.PDP{Version: 1, ITEI: sess.LocalGTPUTEID})
		return err
	}
	k.log.Info("kernel GTP session added",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"subscriber_ip", sess.SubscriberIP.String(),
		"local_gtpu_teid", sess.LocalGTPUTEID,
		"remote_gtpu_teid", sess.RemoteGTPUTEID,
		"pgw_user_ip", peer.String(),
		"gtp_interface", k.cfg.GTPInterface,
	)
	return nil
}

func (k *KernelGTP) RemoveSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	link, linkErr := k.currentLink()
	if linkErr != nil && !isNotFound(linkErr) {
		return linkErr
	}
	if link != nil && sess.SubscriberIP != nil {
		if err := k.removePolicyRouting(sess); err != nil {
			return err
		}
		if !k.routing.PolicyRouting {
			if err := k.handle.RouteDel(kernelRoute(link, sess.SubscriberIP)); err != nil && !isNotFound(err) {
				return fmt.Errorf("remove kernel GTP route for %s: %w", sess.SubscriberIP.String(), err)
			}
		}
	}
	if link != nil && sess.LocalGTPUTEID != 0 {
		peer := firstIP(sess.PGWUserIP, net.ParseIP(k.pgw.RemotePGWGTPUIP))
		pdp := &netlink.PDP{
			Version:     1,
			PeerAddress: peer,
			MSAddress:   sess.SubscriberIP,
			ITEI:        sess.LocalGTPUTEID,
		}
		if err := k.gtpPDPDel(link, pdp); err != nil && !isNotFound(err) {
			return fmt.Errorf("remove kernel GTP PDP session_id=%s local_gtpu_teid=%d: %w", sess.ID, sess.LocalGTPUTEID, err)
		}
	}
	k.log.Info("kernel GTP session removed",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"local_gtpu_teid", sess.LocalGTPUTEID,
		"remote_gtpu_teid", sess.RemoteGTPUTEID,
		"gtp_interface", k.cfg.GTPInterface,
	)
	return nil
}

func (k *KernelGTP) Type() string { return ModeKernelGTP }

func (k *KernelGTP) SetErrorIndicationHandler(handler gtpu.ErrorIndicationHandler) {
	k.errorHandler = handler
}

func (k *KernelGTP) ProbeUserEcho(ctx context.Context) error {
	if !k.userEchoCfg.Enabled || k.gtpuEchoDisabled {
		return nil
	}
	if !k.gtpuEchoSupported {
		return fmt.Errorf("kernel GTP-U Echo support unavailable")
	}
	return k.runUserEchoProbe(ctx)
}

func (k *KernelGTP) UserEchoHealth() UserEchoHealthStatus {
	k.healthMu.RLock()
	defer k.healthMu.RUnlock()
	return UserEchoHealthStatus{
		Health:              k.gtpuHealth,
		ConsecutiveFailures: k.consecutiveEchoFailures,
		LastSuccess:         k.lastEchoSuccess,
		LastFailure:         k.lastEchoFailure,
		LastLatency:         k.lastEchoLatency,
		KernelSupported:     k.gtpuEchoSupported,
		Mode:                k.userEchoCfg.Mode,
	}
}

func (k *KernelGTP) StartUserEchoWatchdog(ctx context.Context) {
	if !k.userEchoCfg.Enabled || k.gtpuEchoDisabled || !k.gtpuEchoSupported {
		return
	}
	k.echoMu.Lock()
	if k.echoStarted {
		k.echoMu.Unlock()
		return
	}
	k.echoStarted = true
	k.echoMu.Unlock()
	k.echoWG.Add(1)
	go func() {
		defer k.echoWG.Done()
		k.runUserEchoWatchdog(ctx)
	}()
}

func (k *KernelGTP) detectUserEchoSupport() error {
	if !k.userEchoCfg.Enabled {
		return nil
	}
	if k.userEchoCfg.Mode != gtpUEchoModeKernelNetlink {
		return fmt.Errorf("unsupported GTP-U echo mode %q", k.userEchoCfg.Mode)
	}
	supported := kernelGTPHeaderHasEchoReq()
	if supported && k.handle != nil {
		if _, err := k.handle.GenlFamilyGet(nl.GENL_GTP_NAME); err != nil {
			supported = false
		}
	}
	if !supported {
		k.gtpuEchoSupported = false
		k.gtpuEchoDisabled = true
		k.gtpuEchoDisableReason = "GTP_CMD_ECHOREQ not supported by running kernel"
		k.log.Warn("GTP-U echo kernel support unavailable",
			"mode", k.userEchoCfg.Mode,
			"user_echo_enabled", false,
			"reason", k.gtpuEchoDisableReason,
		)
		if k.userEchoCfg.RequireKernelSupport {
			return fmt.Errorf("GTP-U echo kernel support unavailable: %s", k.gtpuEchoDisableReason)
		}
		return nil
	}
	k.gtpuEchoSupported = true
	k.log.Info("GTP-U echo kernel support detected",
		"mode", k.userEchoCfg.Mode,
		"gtp_cmd_echoreq", true,
		"kernel_interface", k.cfg.GTPInterface,
	)
	return nil
}

func (k *KernelGTP) runUserEchoWatchdog(ctx context.Context) {
	interval := time.Duration(k.userEchoCfg.IntervalSeconds) * time.Second
	timeout := time.Duration(k.userEchoCfg.TimeoutSeconds) * time.Second
	k.log.Info("GTP-U echo watchdog started",
		"mode", k.userEchoCfg.Mode,
		"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
		"remote_pgw_gtpu_port", gtpUPort,
		"interval_seconds", k.userEchoCfg.IntervalSeconds,
		"timeout_seconds", k.userEchoCfg.TimeoutSeconds,
		"max_failures", k.userEchoCfg.MaxFailures,
	)
	defer func() {
		k.echoMu.Lock()
		k.echoStarted = false
		k.echoMu.Unlock()
		k.log.Info("GTP-U echo watchdog stopped",
			"mode", k.userEchoCfg.Mode,
			"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
			"remote_pgw_gtpu_port", gtpUPort,
		)
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.ctx.Done():
			return
		case <-ticker.C:
			if k.userEchoUnavailable() {
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			_ = k.runUserEchoProbe(probeCtx)
			cancel()
		}
	}
}

func (k *KernelGTP) runUserEchoProbe(ctx context.Context) error {
	pending := k.ensureUserEchoPending()
	defer k.clearUserEchoPending(pending)
	sequence, mode, err := k.triggerUserEchoRequest()
	if err != nil {
		if k.disableUserEchoOnKernelReject(err) {
			return nil
		}
		failures, unhealthy := k.recordUserEchoFailure(err)
		k.log.Warn("GTP-U echo failed",
			"gtpu_peer_health", k.UserEchoHealth().Health,
			"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
			"error", err,
			"consecutive_failures", failures,
			"max_failures", k.userEchoCfg.MaxFailures,
		)
		if unhealthy {
			k.log.Warn("GTP-U peer marked unhealthy",
				"gtpu_peer_health", "unhealthy",
				"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
				"consecutive_failures", failures,
			)
		}
		return err
	}
	start := time.Now()
	k.log.Info("GTP-U echo request triggered",
		"mode", mode,
		"kernel_interface", k.cfg.GTPInterface,
		"local_gtpu_ip", k.pgw.LocalGTPUIP,
		"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
		"sequence", sequence,
	)
	select {
	case obs := <-pending:
		latency := obs.At.Sub(start)
		k.recordUserEchoSuccess(latency)
		k.log.Info("GTP-U echo response observed",
			"mode", mode,
			"gtpu_peer_health", k.UserEchoHealth().Health,
			"remote_pgw_gtpu_ip", obs.Peer.IP.String(),
			"sequence", obs.Sequence,
			"latency_ms", latency.Milliseconds(),
			"consecutive_failures", 0,
		)
		return nil
	case <-ctx.Done():
		err := ctx.Err()
		failures, unhealthy := k.recordUserEchoFailure(err)
		k.log.Warn("GTP-U echo failed",
			"gtpu_peer_health", k.UserEchoHealth().Health,
			"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
			"error", err,
			"consecutive_failures", failures,
			"max_failures", k.userEchoCfg.MaxFailures,
		)
		if unhealthy {
			k.log.Warn("GTP-U peer marked unhealthy",
				"gtpu_peer_health", "unhealthy",
				"remote_pgw_gtpu_ip", k.pgw.RemotePGWGTPUIP,
				"consecutive_failures", failures,
			)
		}
		return err
	}
}

func (k *KernelGTP) clearUserEchoPending(ch chan userEchoObservation) {
	k.echoMu.Lock()
	defer k.echoMu.Unlock()
	if k.echoPending == ch {
		k.echoPending = nil
	}
}

func (k *KernelGTP) ensureUserEchoPending() chan userEchoObservation {
	k.echoMu.Lock()
	defer k.echoMu.Unlock()
	k.echoPending = make(chan userEchoObservation, 1)
	return k.echoPending
}

func (k *KernelGTP) observeUserEchoResponse(peer *net.UDPAddr, sequence uint16) {
	if peer == nil {
		return
	}
	expected := net.ParseIP(k.pgw.RemotePGWGTPUIP)
	if expected != nil && !peer.IP.Equal(expected) {
		k.log.Warn("GTP-U echo response from unexpected peer ignored",
			"remote_ip", peer.IP.String(),
			"remote_port", peer.Port,
			"expected_remote_ip", expected.String(),
			"sequence", sequence,
		)
		return
	}
	k.echoMu.Lock()
	pending := k.echoPending
	k.echoMu.Unlock()
	if pending == nil {
		k.log.Info("GTP-U echo response observed",
			"mode", k.userEchoCfg.Mode,
			"remote_pgw_gtpu_ip", peer.IP.String(),
			"sequence", sequence,
			"latency_ms", 0,
			"consecutive_failures", 0,
		)
		return
	}
	select {
	case pending <- userEchoObservation{Peer: peer, Sequence: sequence, At: time.Now()}:
	default:
	}
}

func (k *KernelGTP) triggerUserEchoRequest() (uint16, string, error) {
	if err := k.triggerUserEchoRequestNetlink(); err == nil {
		return 0, k.userEchoCfg.Mode, nil
	} else if !isKernelEchoUnsupportedError(err) {
		return 0, k.userEchoCfg.Mode, err
	}
	sequence, err := k.triggerUserEchoRequestSocket()
	return sequence, gtpUEchoModeKernelSocket, err
}

func (k *KernelGTP) triggerUserEchoRequestNetlink() error {
	if k.handle == nil {
		return fmt.Errorf("kernel GTP netlink handle is not open")
	}
	link, err := k.currentLink()
	if err != nil {
		return err
	}
	f, err := k.handle.GenlFamilyGet(nl.GENL_GTP_NAME)
	if err != nil {
		return fmt.Errorf("lookup GTP generic netlink family: %w", err)
	}
	peer := net.ParseIP(k.pgw.RemotePGWGTPUIP)
	if peer == nil || peer.To4() == nil {
		return fmt.Errorf("remote PGW GTP-U IP is invalid")
	}
	local := net.ParseIP(k.pgw.LocalGTPUIP)
	if local == nil || local.To4() == nil {
		return fmt.Errorf("local GTP-U IP is invalid")
	}
	msg := &nl.Genlmsg{Command: genlGTPCmdEchoReq, Version: nl.GENL_GTP_VERSION}
	req := nl.NewNetlinkRequest(int(f.ID), unix.NLM_F_ACK)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_VERSION, nl.Uint32Attr(1)))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_NET_NS_FD, nl.Uint32Attr(uint32(fdValue(k.nsFile)))))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_LINK, nl.Uint32Attr(uint32(link.Attrs().Index))))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_PEER_ADDRESS, []byte(peer.To4())))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_MS_ADDRESS, []byte(local.To4())))
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return fmt.Errorf("trigger kernel GTP-U Echo Request: %w", err)
	}
	return nil
}

func (k *KernelGTP) triggerUserEchoRequestSocket() (uint16, error) {
	if k.gtp1 == nil {
		return 0, fmt.Errorf("kernel-associated GTP-U socket is not open")
	}
	peer := net.ParseIP(k.pgw.RemotePGWGTPUIP)
	if peer == nil || peer.To4() == nil {
		return 0, fmt.Errorf("remote PGW GTP-U IP is invalid")
	}
	sequence := k.nextUserEchoSequence()
	packet, err := gtpu.EncodeEchoRequest(sequence)
	if err != nil {
		return 0, err
	}
	remote := &net.UDPAddr{IP: peer, Port: gtpUPort}
	if _, err := k.gtp1.WriteToUDP(packet, remote); err != nil {
		return 0, fmt.Errorf("send GTP-U Echo Request on kernel-associated socket: %w", err)
	}
	return sequence, nil
}

func (k *KernelGTP) nextUserEchoSequence() uint16 {
	k.echoMu.Lock()
	defer k.echoMu.Unlock()
	k.echoSequence++
	if k.echoSequence == 0 {
		k.echoSequence = 1
	}
	return k.echoSequence
}

func (k *KernelGTP) recordUserEchoSuccess(latency time.Duration) {
	k.healthMu.Lock()
	defer k.healthMu.Unlock()
	k.gtpuHealth = "healthy"
	k.consecutiveEchoFailures = 0
	k.lastEchoSuccess = time.Now()
	k.lastEchoLatency = latency
}

func (k *KernelGTP) recordUserEchoFailure(err error) (int, bool) {
	k.healthMu.Lock()
	defer k.healthMu.Unlock()
	k.consecutiveEchoFailures++
	k.lastEchoFailure = time.Now()
	if k.consecutiveEchoFailures >= k.userEchoCfg.MaxFailures && k.gtpuHealth != "unhealthy" {
		k.gtpuHealth = "unhealthy"
		return k.consecutiveEchoFailures, true
	}
	return k.consecutiveEchoFailures, false
}

func (k *KernelGTP) disableUserEchoOnKernelReject(err error) bool {
	if k.userEchoCfg.RequireKernelSupport || !isKernelEchoUnsupportedError(err) {
		return false
	}
	k.echoMu.Lock()
	k.gtpuEchoDisabled = true
	k.gtpuEchoSupported = false
	k.gtpuEchoDisableReason = err.Error()
	k.echoMu.Unlock()
	k.log.Warn("GTP-U echo kernel support unavailable",
		"mode", k.userEchoCfg.Mode,
		"user_echo_enabled", false,
		"reason", err.Error(),
	)
	return true
}

func (k *KernelGTP) userEchoUnavailable() bool {
	k.echoMu.Lock()
	defer k.echoMu.Unlock()
	return k.gtpuEchoDisabled || !k.gtpuEchoSupported
}

func isKernelEchoUnsupportedError(err error) bool {
	return errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ENETDOWN)
}

func (k *KernelGTP) readControlLoop(ctx context.Context) {
	if k.gtp1 == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = k.gtp1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, peer, err := k.gtp1.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			k.log.Warn("GTP-U control receive failed", "error", err)
			return
		}
		msg, err := gtpu.DecodeControlPacket(buf[:n])
		if err != nil {
			continue
		}
		switch msg.Type {
		case 1:
			k.log.Info("GTP-U echo request received", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence)
			resp, err := gtpu.EncodeEchoResponse(msg.Sequence)
			if err != nil {
				k.log.Warn("GTP-U echo response encode failed", "sequence", msg.Sequence, "error", err)
				continue
			}
			if _, err := k.gtp1.WriteToUDP(resp, peer); err != nil {
				k.log.Warn("GTP-U echo response send failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
				continue
			}
			k.log.Info("GTP-U echo response sent", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence)
		case 2:
			k.observeUserEchoResponse(peer, msg.Sequence)
		case 26:
			ind := gtpu.ErrorIndication{RemoteAddr: peer, OffendingTEID: msg.OffendingTEID, RawPayload: append([]byte(nil), msg.Payload...)}
			k.log.Warn("GTP-U Error Indication received",
				"remote_ip", peer.IP.String(),
				"remote_port", peer.Port,
				"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
				"raw_length", len(msg.Payload),
			)
			if k.errorHandler != nil {
				go k.errorHandler(ctx, ind)
			}
		}
	}
}

func (k *KernelGTP) createLink() error {
	localGTP0, err := listenKernelGTPUDP(net.IPv4zero, 3386)
	if err != nil {
		return err
	}
	localGTP1IP := firstIP(net.ParseIP(k.pgw.LocalGTPUIP), net.IPv4zero)
	localGTP1, err := listenKernelGTPUDP(localGTP1IP, 2152)
	if err != nil {
		_ = localGTP0.Close()
		return err
	}
	fd0, err := udpConnFD(localGTP0)
	if err != nil {
		_ = localGTP0.Close()
		_ = localGTP1.Close()
		return fmt.Errorf("get GTPv0 UDP socket fd: %w", err)
	}
	fd1, err := udpConnFD(localGTP1)
	if err != nil {
		_ = localGTP0.Close()
		_ = localGTP1.Close()
		return fmt.Errorf("get GTPv1-U UDP socket fd: %w", err)
	}
	link := &netlink.GTP{
		LinkAttrs: netlink.LinkAttrs{
			Name:      k.cfg.GTPInterface,
			Namespace: netlink.NsFd(fdValue(k.nsFile)),
		},
		FD0:  fd0,
		FD1:  fd1,
		Role: nl.GTP_ROLE_SGSN,
	}
	if err := k.handle.LinkAdd(link); err != nil {
		_ = localGTP0.Close()
		_ = localGTP1.Close()
		return fmt.Errorf("create kernel GTP interface %q: %w", k.cfg.GTPInterface, err)
	}
	created, err := k.handle.LinkByName(k.cfg.GTPInterface)
	if err != nil {
		_ = k.handle.LinkDel(link)
		_ = localGTP0.Close()
		_ = localGTP1.Close()
		return fmt.Errorf("lookup created kernel GTP interface %q: %w", k.cfg.GTPInterface, err)
	}
	if err := k.handle.LinkSetUp(created); err != nil {
		_ = k.handle.LinkDel(created)
		_ = localGTP0.Close()
		_ = localGTP1.Close()
		return fmt.Errorf("set kernel GTP interface %q up: %w", k.cfg.GTPInterface, err)
	}
	k.gtp0 = localGTP0
	k.gtp1 = localGTP1
	k.gtp0FD = fd0
	k.gtp1FD = fd1
	k.link = created
	k.created = true
	return nil
}

func (k *KernelGTP) currentLink() (netlink.Link, error) {
	if k.handle == nil {
		return nil, fmt.Errorf("kernel GTP netlink handle is not open")
	}
	link, err := k.handle.LinkByName(k.cfg.GTPInterface)
	if err != nil {
		return nil, fmt.Errorf("lookup current kernel GTP interface %q: %w", k.cfg.GTPInterface, err)
	}
	if link.Type() != "gtp" {
		return nil, fmt.Errorf("kernel GTP interface %q has type %q", k.cfg.GTPInterface, link.Type())
	}
	k.link = link
	return link, nil
}

func (k *KernelGTP) gtpPDPAdd(link netlink.Link, pdp *netlink.PDP) error {
	nl.EnableErrorMessageReporting = true
	f, err := k.handle.GenlFamilyGet(nl.GENL_GTP_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GENL_GTP_CMD_NEWPDP,
		Version: nl.GENL_GTP_VERSION,
	}
	req := nl.NewNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	k.addPDPCommonAttrs(req, link, pdp)
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_O_TEI, nl.Uint32Attr(pdp.OTEI)))
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func (k *KernelGTP) gtpPDPDel(link netlink.Link, pdp *netlink.PDP) error {
	nl.EnableErrorMessageReporting = true
	f, err := k.handle.GenlFamilyGet(nl.GENL_GTP_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GENL_GTP_CMD_DELPDP,
		Version: nl.GENL_GTP_VERSION,
	}
	req := nl.NewNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	k.addPDPCommonAttrs(req, link, pdp)
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func (k *KernelGTP) addPDPCommonAttrs(req *nl.NetlinkRequest, link netlink.Link, pdp *netlink.PDP) {
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_VERSION, nl.Uint32Attr(pdp.Version)))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_NET_NS_FD, nl.Uint32Attr(uint32(fdValue(k.nsFile)))))
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_LINK, nl.Uint32Attr(uint32(link.Attrs().Index))))
	if pdp.PeerAddress != nil {
		req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_PEER_ADDRESS, []byte(pdp.PeerAddress.To4())))
	}
	if pdp.MSAddress != nil {
		req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_MS_ADDRESS, []byte(pdp.MSAddress.To4())))
	}
	req.AddData(nl.NewRtAttr(nl.GENL_GTP_ATTR_I_TEI, nl.Uint32Attr(pdp.ITEI)))
}

func listenKernelGTPUDP(ip net.IP, port int) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, fmt.Errorf("bind kernel GTP UDP socket %s:%d: %w", ip.String(), port, err)
	}
	return conn, nil
}

func udpConnFD(conn *net.UDPConn) (int, error) {
	if conn == nil {
		return 0, fmt.Errorf("UDP connection is nil")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	if err := rawConn.Control(func(rawFD uintptr) {
		fd = int(rawFD)
	}); err != nil {
		return 0, err
	}
	if fd < 0 {
		return 0, fmt.Errorf("invalid UDP socket fd %d", fd)
	}
	return fd, nil
}

func validateKernelSession(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.SubscriberIP == nil {
		return fmt.Errorf("session %s has no subscriber IP", sess.ID)
	}
	if sess.LocalGTPUTEID == 0 {
		return fmt.Errorf("session %s has no local GTP-U TEID", sess.ID)
	}
	if sess.RemoteGTPUTEID == 0 {
		return fmt.Errorf("session %s has no remote GTP-U TEID", sess.ID)
	}
	return nil
}

func kernelRoute(link netlink.Link, ip net.IP) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       hostNet(ip),
	}
}

func (k *KernelGTP) installPolicyRouting(link netlink.Link, sess *session.Session) error {
	if !k.routing.PolicyRouting {
		return nil
	}
	if err := k.handle.RouteReplace(kernelPolicyDefaultRoute(link, k.routing.PolicyTable)); err != nil {
		return fmt.Errorf("install kernel GTP policy default route table=%d dev=%s: %w", k.routing.PolicyTable, k.cfg.GTPInterface, err)
	}
	rule := kernelPolicyRule(sess.SubscriberIP, k.routing.PolicyTable, k.routing.PolicyPriority)
	if err := k.handle.RuleAdd(rule); err != nil && !isExists(err) {
		return fmt.Errorf("install kernel GTP policy rule from %s table=%d priority=%d: %w", sess.SubscriberIP.String(), k.routing.PolicyTable, k.routing.PolicyPriority, err)
	}
	k.log.Info("kernel GTP policy routing installed",
		"session_id", sess.ID,
		"subscriber_ip", sess.SubscriberIP.String(),
		"gtp_interface", k.cfg.GTPInterface,
		"policy_table", k.routing.PolicyTable,
		"policy_priority", k.routing.PolicyPriority,
	)
	return nil
}

func (k *KernelGTP) removePolicyRouting(sess *session.Session) error {
	if !k.routing.PolicyRouting {
		return nil
	}
	rule := kernelPolicyRule(sess.SubscriberIP, k.routing.PolicyTable, k.routing.PolicyPriority)
	if err := k.handle.RuleDel(rule); err != nil && !isNotFound(err) {
		return fmt.Errorf("remove kernel GTP policy rule from %s table=%d priority=%d: %w", sess.SubscriberIP.String(), k.routing.PolicyTable, k.routing.PolicyPriority, err)
	}
	k.log.Info("kernel GTP policy routing removed",
		"session_id", sess.ID,
		"subscriber_ip", sess.SubscriberIP.String(),
		"policy_table", k.routing.PolicyTable,
		"policy_priority", k.routing.PolicyPriority,
	)
	return nil
}

func kernelPolicyDefaultRoute(link netlink.Link, table int) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     table,
		Dst:       defaultIPv4Net(),
	}
}

func kernelPolicyRule(ip net.IP, table, priority int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Src = hostNet(ip)
	rule.Table = table
	rule.Priority = priority
	return rule
}

func hostNet(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
}

func defaultIPv4Net() *net.IPNet {
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}

func kernelGTPHeaderHasEchoReq() bool {
	for _, path := range []string{"/usr/include/linux/gtp.h"} {
		b, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(b), "GTP_CMD_ECHOREQ") {
			return true
		}
	}
	return false
}

func firstIP(values ...net.IP) net.IP {
	for _, ip := range values {
		if ip != nil {
			return ip
		}
	}
	return nil
}

func isExists(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST)
}

func isNotFound(err error) bool {
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}

func currentNetNS() string {
	target, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ""
	}
	return target
}

func currentUserNS() string {
	target, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		return ""
	}
	return target
}

func procStatusField(name string) string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	prefix := name + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func fdValue(file *os.File) uintptr {
	if file == nil {
		return 0
	}
	return file.Fd()
}

func localAddrString(conn *net.UDPConn) string {
	if conn == nil || conn.LocalAddr() == nil {
		return ""
	}
	return conn.LocalAddr().String()
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
