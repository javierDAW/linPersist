// Command linpersist collects Linux persistence artifacts and emits
// them as NDJSON records suitable for downstream frequency stacking.
//
// The agent is read-only on the target host. It never writes to the
// host filesystem except for the file passed to --output (if any).
// Output otherwise goes to stdout, one JSON object per line.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jarmidaw/linpersist/internal/core"
	"github.com/jarmidaw/linpersist/internal/modset"
)

// version and commit are stamped at link time via -ldflags.
// See Makefile: -X main.version=... -X main.commit=...
var (
	version = "dev"
	commit  = "unknown"
)

// tagsFlag accumulates --tag key=value arguments. Each Set call
// validates the input via core.ParseTag and appends the canonical
// form; final canonicalization (sort + dedup) happens after Parse
// returns so callers see deterministic output regardless of CLI
// order. See ADR-0015 for the validation contract.
type tagsFlag struct {
	values []string
}

func (t *tagsFlag) String() string {
	if t == nil || len(t.values) == 0 {
		return ""
	}
	return strings.Join(t.values, ",")
}

func (t *tagsFlag) Set(raw string) error {
	canon, err := core.ParseTag(raw)
	if err != nil {
		return err
	}
	t.values = append(t.values, canon)
	return nil
}

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
		showSelfSHA256     = fs.Bool("self-sha256", false, "Print sha256sum of the running binary to stdout and exit. Use for chain-of-custody: an operator can confirm the binary executing on the client matches the binary handed over.")
	)
	var tags tagsFlag
	fs.Var(&tags, "tag", "Repeatable host tag (key=value). See ADR-0015 for the format.")

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError has already printed the error.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "linpersist %s (commit %s)\n", version, commit)
		return 0
	}

	if *showSelfSHA256 {
		return printSelfSHA256(stdout, stderr)
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
	hm.Tags = core.CanonicalizeTags(tags.values)

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

	// Modules registered with the runner come from internal/modset,
	// which is the single source of truth shared with cmd/matrix-audit.
	// Adding a new module is one edit in modset/modset.go.
	runner := core.NewRunner(modset.All(prov, liveProcs)...)

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

// printSelfSHA256 streams the running binary into sha256 and prints
// the hex digest to stdout in `sha256sum`-compatible format. Used by
// operators in consultoría engagements to confirm the binary the
// client is about to run is byte-identical to the one shipped in the
// engagement kit.
//
// Output format example (so it can be piped into `sha256sum -c`):
//
//	d8e1...  /usr/local/bin/linpersist
func printSelfSHA256(stdout, stderr io.Writer) int {
	me, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "linpersist: os.Executable: %v\n", err)
		return 1
	}
	f, err := os.Open(me)
	if err != nil {
		fmt.Fprintf(stderr, "linpersist: open %s: %v\n", me, err)
		return 1
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Fprintf(stderr, "linpersist: read %s: %v\n", me, err)
		return 1
	}
	fmt.Fprintf(stdout, "%x  %s\n", h.Sum(nil), me)
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
