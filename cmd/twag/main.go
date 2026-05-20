package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	var testAttachPath string
	var testDetachPath string
	var testAttachDetach bool
	var testAttachHold bool

	flag.StringVar(&cfgPath, "c", "config.yaml", "path to YAML config file")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.StringVar(&testAttachPath, "test-attach", "", "path to JSON attach request; run one attach lifecycle and exit")
	flag.StringVar(&testDetachPath, "test-detach", "", "path to JSON detach request; run one detach lifecycle and exit")
	flag.BoolVar(&testAttachDetach, "test-attach-detach", false, "detach the test attach session before exiting")
	flag.BoolVar(&testAttachHold, "test-attach-hold", false, "hold a successful test attach until SIGINT/SIGTERM, then detach cleanly")
	flag.Parse()

	if showVersion {
		fmt.Fprint(os.Stdout, buildInfo())
		return
	}
	if testAttachDetach && testAttachPath == "" {
		fmt.Fprintln(os.Stderr, "VectorCore TWAG: -test-attach-detach requires -test-attach")
		os.Exit(1)
	}
	if testAttachHold && testAttachPath == "" {
		fmt.Fprintln(os.Stderr, "VectorCore TWAG: -test-attach-hold requires -test-attach")
		os.Exit(1)
	}
	if testAttachDetach && testAttachHold {
		fmt.Fprintln(os.Stderr, "VectorCore TWAG: use either -test-attach-detach or -test-attach-hold, not both")
		os.Exit(1)
	}
	if testAttachPath != "" && testDetachPath != "" {
		fmt.Fprintln(os.Stderr, "VectorCore TWAG: use either -test-attach or -test-detach, not both")
		os.Exit(1)
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

	if err := run(cfg, log.Logger, testAttachPath, testDetachPath, testAttachDetach, testAttachHold); err != nil {
		log.Error("TWAG failed", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger, testAttachPath, testDetachPath string, testAttachDetach, testAttachHold bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("TWAG starting", "version", version, "name", cfg.TWAG.Name, "realm", cfg.TWAG.Realm)
	log.Info("config loaded")
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
	if cfg.GTP.Echo.StartupProbe {
		probeCtx, probeCancel := context.WithTimeout(ctx, time.Duration(cfg.GTP.Echo.TimeoutSeconds)*time.Second)
		if err := pgwClient.Probe(probeCtx); err != nil {
			probeCancel()
			return fmt.Errorf("pgw probe failed: %w", err)
		}
		probeCancel()
	}
	pgwClient.StartEchoWatchdog(ctx)
	routingMgr := routing.New(cfg.Routing, log)
	lifecycleSvc := lifecycle.New(cfg, provider, sessionMgr, nil, pgwClient, routingMgr, log)
	lifecycleSvc.SetUserPlane(userPlane)
	lifecycleSvc.SetDynamicAuthorizer(radiusserver.NewDynamicAuthorizer(cfg.Recovery.RadiusDisconnect, log))
	userPlane.SetErrorIndicationHandler(func(ctx context.Context, ind gtpu.ErrorIndication) {
		if err := lifecycleSvc.HandleGTPUErrorIndication(ctx, ind); err != nil {
			log.Warn("GTP-U Error Indication cleanup failed", "error", err)
		}
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
	if err := accessSide.Start(ctx); err != nil {
		return err
	}
	if err := radiusSrv.Start(ctx); err != nil {
		return err
	}

	if testAttachPath != "" {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer shutdownCancel()
			if err := stopRuntime(shutdownCtx, log, lifecycleSvc, radiusSrv, accessSide, userPlane, pgwClient, provider, accessDriver); err != nil {
				log.Warn("TWAG shutdown incomplete", "error", err)
			}
		}()
		return runTestAttach(ctx, lifecycleSvc, log, testAttachPath, testAttachDetach, testAttachHold)
	}
	if testDetachPath != "" {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer shutdownCancel()
			if err := stopRuntime(shutdownCtx, log, lifecycleSvc, radiusSrv, accessSide, userPlane, pgwClient, provider, accessDriver); err != nil {
				log.Warn("TWAG shutdown incomplete", "error", err)
			}
		}()
		return runTestDetach(ctx, lifecycleSvc, testDetachPath)
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

func runTestAttach(parent context.Context, lifecycleSvc *lifecycle.Service, log *slog.Logger, path string, detach, hold bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open test attach request: %w", err)
	}
	defer f.Close() //nolint:errcheck
	var req lifecycle.AttachRequest
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("parse test attach request: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	resp, err := lifecycleSvc.Attach(ctx, req)
	if resp != nil {
		_ = json.NewEncoder(os.Stdout).Encode(resp)
	}
	if err != nil {
		return err
	}
	if hold {
		log.Info("test attach hold active", "session_id", resp.SessionID)
		<-parent.Done()
		log.Info("test attach hold stopping", "session_id", resp.SessionID, "reason", parent.Err().Error())
	}
	if !detach && !hold {
		return nil
	}
	detachCtx, detachCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer detachCancel()
	detachResp, detachErr := lifecycleSvc.Detach(detachCtx, lifecycle.DetachRequest{SessionID: resp.SessionID})
	if detachResp != nil {
		_ = json.NewEncoder(os.Stdout).Encode(detachResp)
	}
	return detachErr
}

func runTestDetach(parent context.Context, lifecycleSvc *lifecycle.Service, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open test detach request: %w", err)
	}
	defer f.Close() //nolint:errcheck
	var req lifecycle.DetachRequest
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("parse test detach request: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	resp, err := lifecycleSvc.Detach(ctx, req)
	if resp != nil {
		_ = json.NewEncoder(os.Stdout).Encode(resp)
	}
	return err
}

func buildAccess(cfg *config.Config, log *slog.Logger) (access.Driver, error) {
	return access.NewDriver(cfg.Access, log)
}

func buildInfo() string {
	return fmt.Sprintf("VectorCore TWAG %s\ncommit: %s\nbuild_date: %s\ngo: %s\n", version, commit, buildDate, runtime.Version())
}
