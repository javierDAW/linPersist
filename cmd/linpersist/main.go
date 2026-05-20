// Command linpersist collects Linux persistence artifacts and emits
// them as NDJSON records suitable for downstream frequency stacking.
//
// The agent is read-only on the target host. It never writes to the
// host filesystem except for the file passed to --output (if any).
// Output otherwise goes to stdout, one JSON object per line.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
	"github.com/jarmidaw/linpersist/internal/modules/atjobs"
	"github.com/jarmidaw/linpersist/internal/modules/cron"
	"github.com/jarmidaw/linpersist/internal/modules/grub"
	"github.com/jarmidaw/linpersist/internal/modules/kmod"
	"github.com/jarmidaw/linpersist/internal/modules/ldso"
	"github.com/jarmidaw/linpersist/internal/modules/linger"
	"github.com/jarmidaw/linpersist/internal/modules/motd"
	"github.com/jarmidaw/linpersist/internal/modules/netdispatch"
	"github.com/jarmidaw/linpersist/internal/modules/pam"
	"github.com/jarmidaw/linpersist/internal/modules/passwd"
	"github.com/jarmidaw/linpersist/internal/modules/polkit"
	"github.com/jarmidaw/linpersist/internal/modules/profile"
	"github.com/jarmidaw/linpersist/internal/modules/ssh"
	"github.com/jarmidaw/linpersist/internal/modules/sshd"
	"github.com/jarmidaw/linpersist/internal/modules/sudoers"
	"github.com/jarmidaw/linpersist/internal/modules/systemd"
	"github.com/jarmidaw/linpersist/internal/modules/sysusers"
	"github.com/jarmidaw/linpersist/internal/modules/sysv"
	"github.com/jarmidaw/linpersist/internal/modules/tmpfiles"
	"github.com/jarmidaw/linpersist/internal/modules/udev"
	"github.com/jarmidaw/linpersist/internal/modules/xdg"
)

// version and commit are stamped at link time via -ldflags.
// See Makefile: -X main.version=... -X main.commit=...
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("linpersist", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: linpersist [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	var (
		outputPath         = fs.String("output", "", "Write NDJSON to this file instead of stdout")
		includeHostname    = fs.Bool("include-hostname", false, "Include plaintext hostname in host_meta (default: hash only)")
		moduleTimeout      = fs.Duration("module-timeout", core.DefaultModuleTimeout, "Per-module deadline")
		provenanceTimeout  = fs.Duration("provenance-timeout", core.DefaultProvenanceBuildTimeout, "Provenance map-build deadline (dpkg/rpm)")
		disableProvenance  = fs.Bool("no-provenance", false, "Skip package-manager provenance lookups (every exec_target reports as Unknown)")
		liveProcessTimeout = fs.Duration("live-process-timeout", core.DefaultProcLiveBuildTimeout, "/proc snapshot build deadline")
		disableLiveProcess = fs.Bool("no-live-process", false, "Skip /proc snapshot (no live_process_attached signal)")
		logLevel           = fs.String("log-level", "warn", "Log level: debug|info|warn|error")
		showVersion        = fs.Bool("version", false, "Print version and exit")
	)

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError has already printed the error.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "linpersist %s (commit %s)\n", version, commit)
		return 0
	}

	logger := newLogger(stderr, *logLevel)

	// Resolve output sink: file or stdout. We open the output file
	// EARLY so a permission error surfaces before any host I/O.
	var out io.Writer = stdout
	if *outputPath != "" {
		f, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "linpersist: open --output: %v\n", err)
			return 1
		}
		defer f.Close()
		out = f
	}

	emitter := core.NewNDJSONEmitter(out)
	defer func() {
		if err := emitter.Close(); err != nil {
			fmt.Fprintf(stderr, "linpersist: flush output: %v\n", err)
		}
	}()

	hm, hostID, err := core.CollectHostMeta(*includeHostname)
	if err != nil {
		logger.Warn("hostmeta collection partial", "err", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build the provenance resolver and warm it up before any module
	// runs. Warmup has its own deadline so a slow dpkg or rpm build
	// never eats into a module budget. If --no-provenance is set, we
	// skip the resolver entirely and modules receive a NoopProvenance
	// that returns Unknown for every lookup.
	var prov core.Provenance = core.NoopProvenance{}
	if !*disableProvenance {
		resolver := core.NewResolver(logger,
			core.WithProvenanceBuildTimeout(*provenanceTimeout))
		warmCtx, warmCancel := context.WithTimeout(ctx, *provenanceTimeout)
		resolver.Warmup(warmCtx)
		warmCancel()
		prov = resolver
	}

	// Build the /proc snapshot scanner and warm it up. Same lifecycle
	// pattern as provenance: bounded ctx separate from module budgets,
	// NoopLiveProcessSet when --no-live-process is set so the
	// live_process_attached signal is never emitted.
	var liveProcs core.LiveProcessSet = core.NoopLiveProcessSet{}
	if !*disableLiveProcess {
		scanner := core.NewProcLiveScanner(logger,
			core.WithProcLiveBuildTimeout(*liveProcessTimeout))
		warmCtx, warmCancel := context.WithTimeout(ctx, *liveProcessTimeout)
		scanner.Warmup(warmCtx)
		warmCancel()
		liveProcs = scanner
	}

	// Modules registered with the runner. Adding a module is a
	// one-line change here plus the new package under
	// internal/modules/<name>/.
	runner := core.NewRunner(
		atjobs.New(atjobs.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		cron.New(cron.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		ldso.New(ldso.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		linger.New(linger.Options{}),
		tmpfiles.New(tmpfiles.Options{}),
		sysusers.New(sysusers.Options{}),
		ssh.New(ssh.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sudoers.New(sudoers.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sshd.New(sshd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		passwd.New(passwd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		pam.New(pam.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		profile.New(profile.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		systemd.New(systemd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		sysv.New(sysv.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		motd.New(motd.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		kmod.New(kmod.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		udev.New(udev.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		polkit.New(polkit.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		netdispatch.New(netdispatch.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		grub.New(grub.Options{Provenance: prov, LiveProcessSet: liveProcs}),
		xdg.New(xdg.Options{Provenance: prov, LiveProcessSet: liveProcs}),
	)

	agentVersion := fmt.Sprintf("linpersist-%s", version)
	sink := func(rec core.Record) {
		rec.SchemaV = core.SchemaVersion
		rec.HostID = hostID
		rec.HostMeta = hm
		rec.AgentVersion = agentVersion
		rec.AgentCommit = commit
		if rec.CollectedAt.IsZero() {
			rec.CollectedAt = time.Now().UTC()
		}
		if err := emitter.Emit(rec); err != nil {
			logger.Error("emit", "err", err)
		}
	}

	if err := runner.Run(ctx, core.RunOptions{
		ModuleTimeout: *moduleTimeout,
		Logger:        logger,
	}, sink); err != nil {
		logger.Warn("run completed with module errors", "err", err)
		// Module errors are non-fatal at the process level: we still
		// want partial NDJSON on disk. Exit 0 unless something
		// catastrophic happened.
	}

	return 0
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelWarn
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
}
