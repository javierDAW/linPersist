# ADR-0010: Live-process correlation via /proc

- Status: accepted
- Date: 2026-05-19
- Deciders: Jarmi
- Related: ADR-0009 (provenance dpkg+rpm),
  `internal/core/signals.go` (`SignalLiveProcessAttached`),
  `internal/core/proclive.go`.

## Context

Provenance answers the question "is this exec_target a package
binary or an intruder?". It does not answer "is this exec_target
running on the host right now?". The two together are the IR
analyst's mental filter: a persistence record whose target is
unmanaged AND currently has a live PID is several orders of
magnitude more interesting than a target that satisfies only one of
the two predicates.

Linux exposes the running-process universe through `/proc/<pid>/exe`,
a magic symlink that resolves to the absolute path of the binary
that was `execve()`d into the process. Reading the link is a single
`readlink(2)` per PID; walking `/proc` to enumerate every PID is a
single readdir of an in-memory filesystem. The whole-host snapshot
costs single-digit milliseconds on a quiet host and tens of
milliseconds on a busy container host with thousands of PIDs.

v0.2.0 adds that snapshot to the agent and exposes its membership
check to every module that emits an `exec_target`, exactly parallel
to how provenance is exposed.

## Decision

### Snapshot is one-shot at agent startup, not continuous

The agent is a one-shot tool. It walks `/proc` exactly once,
near the start of the run, and freezes the resulting set in memory.
Modules query that set by exact-path lookup. The set is never
refreshed during the run, even though processes start and exit
constantly: a continuously refreshing scanner would race against
the modules and introduce non-determinism into the NDJSON output
that frequency stacking depends on.

The trade-off: a process that started after the snapshot but before
the module emitted its record is invisible to the agent. Acceptable
because the agent's contract is "snapshot of persistence at time T",
not "real-time monitor". The backend reconciles state over time.

### Read-only inspection only — no eBPF, no ptrace, no kernel hooks

The whole project charter rules these out (no CGO, no kernel
loading). For `/proc/<pid>/exe` no escalation is needed: every uid
can read its own processes' `/exe` symlinks. Reading another user's
`/exe` requires either privilege OR `hidepid` to allow it; the
scanner gracefully degrades when `EACCES` is returned.

### Graceful degrade on hidepid, ESRCH, dangling symlinks

Three failure modes the scanner MUST tolerate without aborting:

1. **`hidepid=1` or `hidepid=2`.** Common on hardened servers and
   inside container namespaces. The walker sees `/proc/<pid>` only
   for processes the agent's effective uid can see. The scanner
   skips entries that `readlink` fails on; the resulting set is a
   subset of the full universe but is the universe the agent has
   permission to observe. The agent makes no claim about
   processes it cannot see.
2. **`ESRCH` during the walk.** A process exits between the
   `readdir` and the `readlink`. The scanner treats this exactly
   like `EACCES`: skip silently.
3. **Dangling exe symlinks.** When a running process's binary has
   been deleted (`unlink` while held open), Linux returns the
   original path with `" (deleted)"` appended. The scanner strips
   the suffix before inserting into the set, so a persistence
   record pointing at the original path still matches. (The signal
   that the binary was deleted is captured elsewhere via the
   existing `exec_target_orphan` flag when the path no longer
   exists on disk.)

### Symlink resolution at lookup, not at build

The set is keyed by the path returned by `readlink(2)` on
`/proc/<pid>/exe`, which the kernel ALREADY resolves to the
canonical executable path (it is the inode the kernel exec'd, not
the symlink the user typed). Persistence records may carry an
`exec_target` that is a symlink to that binary: for example a cron
job that invokes `/usr/bin/python` which is a symlink to
`/usr/bin/python3.10`, and the live process shows the latter.

Lookup tries the path verbatim first; on miss, calls
`filepath.EvalSymlinks` once and retries. Mirrors the provenance
resolver's policy. The single EvalSymlinks call is bounded by
best-effort I/O; a hostile symlink that hangs resolves to a miss
rather than blocking the caller.

### Container hosts and PID namespaces

The scanner reads `/proc` from the namespace the agent runs in. On
a container host, that is the host namespace — the scanner sees
every process on the box including those inside containers. Inside
a container, the scanner sees only the container's own processes
(by namespace design). Both modes are correct for their context;
the agent makes no attempt to escape its namespace.

### Lifecycle parallels provenance

`LiveProcessSet` is an interface with `Warmup(ctx)` and
`Has(path) bool`. `NoopLiveProcessSet` is the zero-value default
when a module's `Options.LiveProcessSet` is nil. The real
`ProcLiveScanner` exposes a `WithProcLiveRoot` option for tests so
unit tests build a fake `/proc` tree under `t.TempDir()`. The
warmup is bounded by `--live-process-timeout` (default 5 s; the
walk is fast enough that this is a generous ceiling).

### Signal contract

Modules call `core.AnnotateLiveProcess(rec, lps, target)`
immediately AFTER `core.AnnotateExecTargetProvenance`. The helper
appends `SignalLiveProcessAttached` ("live_process_attached") if
and only if the resolved target is in the live set. The signal is
informational; pair with `non_package_path` for the high-precision
"unmanaged binary, currently running" pattern that defines an
active implant.

## Consequences

Positive:

- Closes the "armed vs dormant" axis of triage in a single
  cheap pass. Q7 (implant roll-call) gains a new clause; the
  cookbook gains query Q12 in v0.3.0 if the lab-realistic
  validation shows enough discriminating power.
- Zero schema bump. The new signal is appended to the existing
  open-ended `signals[]` array. Downstream consumers that don't
  recognize it ignore it.
- Disk and memory footprint negligible. A typical Linux host has
  100–1000 distinct executables running at once; the set fits in
  tens of kilobytes.

Negative:

- The snapshot is racy by construction: a process that started
  microseconds before or after the walk may be visible or not.
  Treated as inherent to the one-shot collection model.
- Container introspection is asymmetric: an agent inside a
  container sees only the container's processes; an agent on the
  host sees everything. This is correct by namespace semantics
  but operators should not compare records across the two
  positions without accounting for it.

## Alternatives considered

- **Continuous /proc polling.** Rejected: introduces
  non-determinism into the NDJSON output, breaks reproducibility,
  and goes against the one-shot collection charter.
- **eBPF program loading.** Rejected: violates the no-kernel-load
  rule from the project charter. A future plugin binary may add
  this as an opt-in capability outside `linpersist` proper.
- **Use `ps` shell-out.** Rejected: brittle output formats, fork
  overhead, lower portability than direct `/proc` reads.
- **Defer to v0.3.0.** Rejected: the value compounds with
  provenance (the two are most useful together). Shipping
  provenance without live correlation leaves the most precise
  combined signal on the table for an entire release cycle.
