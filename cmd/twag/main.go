package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/access"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/diameter"
	"github.com/vectorcore/twag/internal/ipam"
	"github.com/vectorcore/twag/internal/lifecycle"
	"github.com/vectorcore/twag/internal/logging"
	"github.com/vectorcore/twag/internal/pgw"
	"github.com/vectorcore/twag/internal/routing"
	"github.com/vectorcore/twag/internal/session"
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

	flag.StringVar(&cfgPath, "c", "config.yaml", "path to YAML config file")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.StringVar(&testAttachPath, "test-attach", "", "path to JSON attach request; run one attach lifecycle and exit")
	flag.StringVar(&testDetachPath, "test-detach", "", "path to JSON detach request; run one detach lifecycle and exit")
	flag.BoolVar(&testAttachDetach, "test-attach-detach", false, "detach the test attach session before exiting")
	flag.Parse()

	if showVersion {
		fmt.Fprint(os.Stdout, buildInfo())
		return
	}
	if testAttachDetach && testAttachPath == "" {
		fmt.Fprintln(os.Stderr, "VectorCore TWAG: -test-attach-detach requires -test-attach")
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

	if err := run(cfg, log.Logger, testAttachPath, testDetachPath, testAttachDetach); err != nil {
		log.Error("TWAG failed", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, log *slog.Logger, testAttachPath, testDetachPath string, testAttachDetach bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("TWAG starting", "version", version, "name", cfg.TWAG.Name, "realm", cfg.TWAG.Realm)
	log.Info("config loaded")
	log.Info("logging initialized", "level", cfg.Logging.Level, "file", cfg.Logging.File)

	swxClient := diameter.NewSWxClient(cfg.AAA.SWx, log)
	provider, err := aaa.NewProvider(cfg.AAA, swxClient, log)
	if err != nil {
		return err
	}

	ipamMgr, err := ipam.NewMemory(cfg.IPAM, log)
	if err != nil {
		return err
	}
	sessionMgr := session.NewManager(log)

	accessDriver, err := buildAccess(cfg, log)
	if err != nil {
		return err
	}
	pgwClient, err := pgw.NewClient(cfg.PGW, log)
	if err != nil {
		return err
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := pgwClient.Probe(probeCtx); err != nil {
		probeCancel()
		return fmt.Errorf("pgw probe failed: %w", err)
	}
	probeCancel()
	routingMgr := routing.New(cfg.Routing, log)
	lifecycleSvc := lifecycle.New(cfg, provider, sessionMgr, ipamMgr, pgwClient, routingMgr, log)

	if err := provider.Start(ctx); err != nil {
		return err
	}
	defer provider.Stop() //nolint:errcheck

	if err := accessDriver.Start(ctx); err != nil {
		return err
	}
	defer accessDriver.Stop() //nolint:errcheck

	if err := routingMgr.Start(ctx); err != nil {
		return err
	}

	_ = ipamMgr
	_ = pgwClient

	if testAttachPath != "" {
		return runTestAttach(ctx, lifecycleSvc, testAttachPath, testAttachDetach)
	}
	if testDetachPath != "" {
		return runTestDetach(ctx, lifecycleSvc, testDetachPath)
	}

	<-ctx.Done()
	log.Info("TWAG shutting down", "reason", ctx.Err().Error())
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := lifecycleSvc.Shutdown(shutdownCtx); err != nil {
		log.Warn("session shutdown completed with errors", "error", err)
	}
	return nil
}

func runTestAttach(parent context.Context, lifecycleSvc *lifecycle.Service, path string, detach bool) error {
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
	if err != nil || !detach {
		return err
	}
	detachResp, detachErr := lifecycleSvc.Detach(ctx, lifecycle.DetachRequest{SessionID: resp.SessionID})
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
