package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/access"
	"github.com/vectorcore/twag/internal/accessside"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/diameter"
	"github.com/vectorcore/twag/internal/gtpu"
	"github.com/vectorcore/twag/internal/lifecycle"
	"github.com/vectorcore/twag/internal/logging"
	"github.com/vectorcore/twag/internal/pgw"
	radiusserver "github.com/vectorcore/twag/internal/radius"
	"github.com/vectorcore/twag/internal/routing"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vectorcore/twag/internal/userplane"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	var cfgPath string
	var validateOnly bool
	var showVersion bool
	var debug bool

	flag.StringVar(&cfgPath, "c", "config.yaml", "path to YAML config file")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.Parse()

	if showVersion {
		fmt.Fprint(os.Stdout, buildInfo())
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore TWAG: %v\n", err)
		os.Exit(1)
	}
	if validateOnly {
		fmt.Printf("config valid: %s\n", cfgPath)
		return
	}

	log, err := logging.New(cfg.Logging, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore TWAG: %v\n", err)
		os.Exit(1)
	}
	defer log.Close() //nolint:errcheck

	if err := run(cfg, log.Logger); err != nil {
		log.Error("TWAG failed", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("TWAG starting", "version", version, "name", cfg.TWAG.Name, "realm", cfg.TWAG.Realm)
	log.Info("config loaded")
	for _, warning := range cfg.Warnings {
		log.Warn("config warning", "warning", warning)
	}
	log.Info("logging initialized", "level", cfg.Logging.Level, "file", cfg.Logging.File)

	staClient := diameter.NewSTaClient(cfg.AAA.STa, log)
	provider, err := aaa.NewProvider(cfg.AAA, staClient, log)
	if err != nil {
		return err
	}

	sessionMgr := session.NewManager(log)
	accessSide := accessside.New(cfg, sessionMgr, log)

	accessDriver, err := buildAccess(cfg, log)
	if err != nil {
		return err
	}
	pgwClient, err := pgw.NewClient(cfg.GTP, log)
	if err != nil {
		return err
	}
	userPlane, err := userplane.New(*cfg, log)
	if err != nil {
		return err
	}
	if cfg.GTP.ControlEcho.StartupProbe {
		probeCtx, probeCancel := context.WithTimeout(ctx, time.Duration(cfg.GTP.ControlEcho.TimeoutSeconds)*time.Second)
		if err := pgwClient.Probe(probeCtx); err != nil {
			probeCancel()
			return fmt.Errorf("pgw probe failed: %w", err)
		}
		probeCancel()
	}
	pgwClient.StartEchoWatchdog(ctx)
	routingMgr := routing.New(cfg.Routing, log)
	lifecycleSvc := lifecycle.New(cfg, provider, sessionMgr, nil, pgwClient, routingMgr, log)
	staClient.SetDisconnectHandler(func(ctx context.Context, ev diameter.STaDisconnectEvent) {
		if err := lifecycleSvc.HandleAAAInitiatedDisconnect(ctx, ev.IMSI, ev.SessionID); err != nil {
			log.Warn("AAA-initiated STa disconnect cleanup failed",
				"command", ev.Command,
				"session_id", ev.SessionID,
				"user_name", ev.UserName,
				"imsi", ev.IMSI,
				"error", err,
			)
		}
	})
	pgwClient.SetNetworkDeleteHandler(func(ctx context.Context, gtpcTEID uint32) {
		lifecycleSvc.HandlePGWInitiatedDelete(ctx, gtpcTEID)
	})
	lifecycleSvc.SetUserPlane(userPlane)
	lifecycleSvc.SetDynamicAuthorizer(radiusserver.NewDynamicAuthorizer(cfg.Recovery.RadiusDisconnect, log))
	userPlane.SetErrorIndicationHandler(func(ctx context.Context, ind gtpu.ErrorIndication) {
		if err := lifecycleSvc.HandleGTPUErrorIndication(ctx, ind); err != nil {
			log.Warn("GTP-U Error Indication cleanup failed", "error", err)
		}
	})
	accessSide.SetRecoveryAttachHandler(func(ctx context.Context, tombstone *session.RecoveryTombstone) {
		recoverCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if _, err := lifecycleSvc.RecoverFromTombstone(recoverCtx, tombstone); err != nil {
			mac := ""
			if tombstone.MAC != nil {
				mac = tombstone.MAC.String()
			}
			log.Warn("recovery reattach failed",
				"old_session_id", tombstone.OldSessionID,
				"imsi", tombstone.IMSI,
				"mac", mac,
				"error", err,
			)
		}
	})
	accessSide.SetAuthCacheRecoveryHandler(func(ctx context.Context, mac string) {
		recoverCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		lifecycleSvc.HandleDHCPAuthCacheRecovery(recoverCtx, mac)
	})
	lifecycleSvc.SetAccessSessionBinder(accessSide)
	radiusSrv := radiusserver.New(cfg.Radius, cfg.Subscriber, lifecycleSvc, log)

	if err := provider.Start(ctx); err != nil {
		return err
	}

	if err := accessDriver.Start(ctx); err != nil {
		return err
	}

	if err := routingMgr.Start(ctx); err != nil {
		return err
	}
	if err := userPlane.Start(ctx); err != nil {
		return err
	}
	if cfg.GTP.UserEcho.Enabled && cfg.GTP.UserEcho.StartupProbe {
		probeCtx, probeCancel := context.WithTimeout(ctx, time.Duration(cfg.GTP.UserEcho.TimeoutSeconds)*time.Second)
		if err := userPlane.ProbeUserEcho(probeCtx); err != nil {
			probeCancel()
			return fmt.Errorf("GTP-U echo startup probe failed: %w", err)
		}
		probeCancel()
	}
	userPlane.StartUserEchoWatchdog(ctx)
	if err := accessSide.Start(ctx); err != nil {
		return err
	}
	if err := radiusSrv.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	log.Info("TWAG shutting down", "reason", ctx.Err().Error())
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := stopRuntime(shutdownCtx, log, lifecycleSvc, radiusSrv, accessSide, userPlane, pgwClient, provider, accessDriver); err != nil {
		log.Warn("TWAG shutdown incomplete", "error", err)
		if errors.Is(err, context.DeadlineExceeded) {
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
		}
		return err
	}
	log.Info("TWAG shutdown complete")
	return nil
}

func stopRuntime(ctx context.Context, log *slog.Logger, lifecycleSvc *lifecycle.Service, radiusSrv *radiusserver.Server, accessSide *accessside.Manager, userPlane userplane.UserPlane, pgwClient pgw.Client, provider aaa.Provider, accessDriver access.Driver) error {
	var errs []error
	stop := func(name string, fn func(context.Context) error) {
		if ctx.Err() != nil {
			errs = append(errs, fmt.Errorf("%s stop skipped: %w", name, ctx.Err()))
			return
		}
		log.Info("component stopping", "component", name)
		done := make(chan error, 1)
		go func() { done <- fn(ctx) }()
		select {
		case err := <-done:
			if err != nil {
				log.Warn("component stop failed", "component", name, "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				return
			}
			log.Info("component stopped", "component", name)
		case <-ctx.Done():
			err := fmt.Errorf("%s stop timeout: %w", name, ctx.Err())
			log.Warn("component stop timeout", "component", name, "error", err)
			errs = append(errs, err)
		}
	}
	stop("sessions", func(ctx context.Context) error { return lifecycleSvc.Shutdown(ctx) })
	stop("radius", func(ctx context.Context) error { return radiusSrv.Stop(ctx) })
	stop("accessside", func(context.Context) error { return accessSide.Stop() })
	stop("userplane", func(context.Context) error { return userPlane.Stop() })
	stop("pgw", func(context.Context) error { return pgwClient.Close() })
	stop("aaa", func(context.Context) error { return provider.Stop() })
	stop("access_driver", func(context.Context) error { return accessDriver.Stop() })
	return errors.Join(errs...)
}

func buildAccess(cfg *config.Config, log *slog.Logger) (access.Driver, error) {
	return access.NewDriver(cfg.Access, log)
}

func buildInfo() string {
	return fmt.Sprintf("VectorCore TWAG %s\ncommit: %s\nbuild_date: %s\ngo: %s\n", version, commit, buildDate, runtime.Version())
}
