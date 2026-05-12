package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultModuleTimeout is the per-module deadline applied by the runner
// when the caller does not set one explicitly. Chosen empirically: most
// modules complete in tens of milliseconds; 30s leaves headroom for
// slow disks and large /home trees without letting a stuck module
// dominate total wall time on a fleet host.
const DefaultModuleTimeout = 30 * time.Second

// RunOptions controls a single Runner.Run invocation.
type RunOptions struct {
	// ModuleTimeout bounds the time each module may spend inside its
	// Collect call. Zero means DefaultModuleTimeout.
	ModuleTimeout time.Duration

	// Logger is the structured logger used for per-module
	// success/timeout/error events. Nil means slog.Default().
	Logger *slog.Logger
}

// Runner executes a set of modules concurrently and forwards every
// emitted Record to a single sink. The sink is invoked from multiple
// goroutines; callers must serialize writes if their sink is not
// goroutine-safe (the NDJSON emitter in emit.go already does this).
type Runner struct {
	modules []Module
}

// NewRunner returns a Runner that will execute the given modules.
// The slice is captured by reference; the caller should not mutate it
// concurrently with Run.
func NewRunner(modules ...Module) *Runner {
	return &Runner{modules: modules}
}

// Run executes every module in its own goroutine with a per-module
// timeout. The sink is invoked once per emitted Record. Run blocks
// until all modules have completed or ctx is canceled.
//
// A module that returns a non-nil error or times out is logged but
// does NOT abort the run; one bad module never sinks the whole
// collection. Run returns a joined error containing every per-module
// failure, or nil if all modules succeeded.
func (r *Runner) Run(ctx context.Context, opts RunOptions, sink func(Record)) error {
	if opts.ModuleTimeout <= 0 {
		opts.ModuleTimeout = DefaultModuleTimeout
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		errs     []error
		sinkMu   sync.Mutex
		safeSink = func(rec Record) {
			sinkMu.Lock()
			defer sinkMu.Unlock()
			sink(rec)
		}
	)

	for _, m := range r.modules {
		m := m
		wg.Add(1)
		go func() {
			defer wg.Done()
			mctx, cancel := context.WithTimeout(ctx, opts.ModuleTimeout)
			defer cancel()

			start := time.Now()
			err := m.Collect(mctx, safeSink)
			elapsed := time.Since(start)

			switch {
			case err == nil:
				logger.Debug("module ok",
					"module", m.Name(), "elapsed", elapsed)
			case errors.Is(mctx.Err(), context.DeadlineExceeded):
				wrapped := fmt.Errorf("module %s: timeout after %s", m.Name(), opts.ModuleTimeout)
				logger.Warn("module timeout",
					"module", m.Name(), "elapsed", elapsed)
				errMu.Lock()
				errs = append(errs, wrapped)
				errMu.Unlock()
			default:
				wrapped := fmt.Errorf("module %s: %w", m.Name(), err)
				logger.Warn("module error",
					"module", m.Name(), "err", err, "elapsed", elapsed)
				errMu.Lock()
				errs = append(errs, wrapped)
				errMu.Unlock()
			}
		}()
	}

	wg.Wait()
	return errors.Join(errs...)
}
