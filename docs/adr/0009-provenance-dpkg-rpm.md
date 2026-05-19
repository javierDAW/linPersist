# ADR-0009: Provenance resolution against dpkg and rpm

- Status: accepted
- Date: 2026-05-19
- Deciders: Jarmi
- Related: ADR-0002 (record granularity), `internal/core/signals.go`
  (`SignalNonPackagePath`), `internal/core/record.go`
  (`ExecTargetPkg`, `ExecTargetPkgStatus`).

## Context

Every record the agent emits may include an `exec_target` path: the
binary or script that the persistence site causes to run. In v0.1.0
this field is populated but the two companion fields,
`exec_target_pkg` and `exec_target_pkg_status`, are always empty
because `internal/core/provenance.go` ships a stub that returns
`PkgStatusUnknown` unconditionally. The signal
`SignalNonPackagePath`, declared in the core signal catalogue, is
therefore never emitted by any module.

Without provenance, a downstream stack on `exec_target_pkg_status =
'orphan'` cannot run, and the cookbook query Q4 (orphan implants in
tmp-class directories) survives only on the `interpreter_in_tmp`
half of its predicate. The single highest-leverage enrichment the
agent can add, retroactively across every existing module, is
turning the stub into a real resolver.

v0.2.0 ships that resolver. This ADR documents the design.

## Decision

Three orthogonal choices.

### Detection: how does the agent know which package manager to ask?

Detection runs once per agent process, lazily on first call.
Algorithm:

1. Read `/etc/os-release`. If `ID=` (or any token in `ID_LIKE=`)
   matches `debian` / `ubuntu` / `kali` / `raspbian` / `mint`, the
   candidate is dpkg. If it matches `rhel` / `centos` / `fedora` /
   `amzn` / `rocky` / `almalinux` / `ol` / `opensuse*` / `sles`, the
   candidate is rpm.
2. Confirm with filesystem evidence: dpkg requires
   `/var/lib/dpkg/info/` to exist and be a directory; rpm requires
   `/var/lib/rpm/` to exist and be a directory.
3. If `/etc/os-release` is unreadable, fall back to filesystem
   evidence alone: dpkg if `/var/lib/dpkg/info/` exists, otherwise
   rpm if `/var/lib/rpm/` exists, otherwise `PkgMgrNone`.
4. If both are present (uncommon but seen on hybrid systems like
   crossgrade transitions), prefer the one that `/etc/os-release`
   names. If neither is named, prefer dpkg as the cheaper bulk
   builder.

Hosts with no detected package manager (Alpine, custom embedded
distros, certain minimal containers) get `PkgStatusUnknown` from
every lookup. The agent emits no `non_package_path` signal on those
hosts; the downstream pipeline must filter them out for any LFA
that depends on provenance.

### dpkg backend: pure-Go list parser

Build a `map[string]string` (path -> `<name>-<version>`) by walking
`/var/lib/dpkg/info/*.list` and, for each entry, reading every line
as a single absolute path. The list files are flat text. No
parsing of `/var/lib/dpkg/status` is required for this lookup; the
list files cover both installed and de-configured-but-still-listed
packages, which matches the operational definition of "owned by a
package" the agent wants to surface.

Per-list extras:

- The package version is taken from the matching
  `/var/lib/dpkg/status` entry when available, otherwise the list
  filename minus `.list` is used as the name with version empty.
  The agent never blocks on the status file; if it cannot be
  parsed, the name-only form ships.
- File-conflict resolution: if the same path appears in two list
  files, the first one wins. Document the policy; do not try to
  detect conflicts at agent run time.
- Diversions (`/var/lib/dpkg/diversions`) are out of scope for
  v0.2.0. If a diverted binary surfaces as `orphan` because the
  original list still names the pre-diversion path, the downstream
  pipeline can correct it. Diversions are rare on a typical fleet
  host.

The map is built once, kept in memory, and discarded at process
exit. Empirical target on a typical Ubuntu 22.04 server (~1500
packages, ~150 000 path entries): under 500 ms wall-clock and
under 30 MB resident.

### rpm backend: bounded shell-out to `rpm -qa`

Pure-Go parsing of the rpm DB is technically possible but
unattractive:

- RHEL 7 / CentOS 7 / Amazon Linux 2 store the DB in BerkeleyDB
  format. Pure-Go BDB readers exist (e.g. `knqyf263/go-rpmdb`) but
  pull in their own transitive deps that need to be re-audited
  against the project's no-CGO and minimal-deps charter on every
  upgrade.
- RHEL 8+, Fedora, Amazon Linux 2023, Rocky, Alma store the DB in
  SQLite. The only pure-Go SQLite is `modernc.org/sqlite`, a
  multi-megabyte transpiled C library that conflicts with the
  agent's <12 MB static-binary target.
- openSUSE Tumbleweed and recent SLES use the ndb format, which
  has the thinnest library coverage of the three.

Shell-out sidesteps all three: every rpm host has `/usr/bin/rpm`
because rpm is how the system installs and removes packages. The
bulk-mode invocation, updated 2026-05-19 after the v0.2.0
lab-realistic run, is:

```
rpm -qa --filesbypkg --nosignature --nodigest
```

The original v0.2.0 design used a queryformat:

```
rpm -qa --queryformat '[%{FILENAMES}\t%{NAME}-%{VERSION}-%{RELEASE}\n]'
```

That form worked on rpm 4.14 and earlier but produced silently
incomplete output on rpm 4.16+ in minimized container images: the
bracket-iteration over `%{FILENAMES}` returned only the first
filename per package, or sometimes the empty string. The
lab-realistic v0.2.0 run surfaced this as a 27-host systemd
false-positive flood (RHEL 12 + Amazon Linux 15 hosts on which the
queryformat silently failed; the 43 dpkg hosts were unaffected).

`--filesbypkg` is the canonical rpm flag for the "list every file
of every package" use case. It has been stable since rpm 4.4 (2005)
and uses a simpler output format that does not depend on
queryformat bracket-iteration semantics. Each line emitted is:

```
<package-name>  <whitespace-padding>  <file-path>
```

`<package-name>` is the bare NAME (no NVR; see `trimNVRSuffix` in
provenance.go for a defensive strip if a future rpm version
changes that). `--nosignature --nodigest` suppress sig/digest
verification chatter that goes to stderr (we discard stderr but
the flags also avoid the verification cost).

The resolver parses the stream into the same `map[string]string`
shape the dpkg backend produces. Empirical wall-clock on a RHEL 9
host with ~900 rpms: roughly 800 ms. A 30 s ceiling on the build
covers the worst-case hosts seen in IR practice; longer than that
returns `PkgStatusError` for every lookup and logs at WARN.

### Container-image caveat

On minimized container images (UBI minimal, `amazonlinux:minimal`,
hand-crafted slim Debian/Ubuntu variants), the package database may
have been deliberately stripped to reduce image size. In that case
the resolver receives partial data and legitimately
package-installed binaries return `PkgStatusOrphan`. This is not
an agent bug -- the resolver answers truthfully against the data
the host provides. Operators running the agent inside such
containers should expect `non_package_path` records on system
binaries and either run with `--no-provenance` or filter
downstream by `host_meta.tags` once the agent gains a
container-detection signal (planned for v0.3.0).

Safety:

- The resolver invokes `rpm` with an absolute path, trying
  `/usr/bin/rpm` first and `/bin/rpm` second. It never honors `PATH`
  for this lookup, which mitigates trivial `PATH` poisoning by an
  attacker who got far enough to plant a fake `rpm` binary. A
  determined attacker can still replace `/usr/bin/rpm` itself; the
  ADR accepts that risk as inherent to running an agent on a
  compromised host (the same risk applies to every helper the agent
  could call) and documents it.
- The shell-out is wrapped in `exec.CommandContext`; killing the
  bounding context kills the rpm process.
- If both `/usr/bin/rpm` and `/bin/rpm` are absent, the resolver
  records the build error and degrades all lookups to
  `PkgStatusError`.

### Lifecycle: warmup is explicit, lookup is lock-free

The resolver exposes:

```go
type Provenance interface {
    Warmup(ctx context.Context)
    LookupPath(path string) (pkg string, status PkgStatus)
}
```

`Warmup` is idempotent. `main.go` calls it before launching the
runner, charged against its own deadline (default 60 s, configurable
via `--provenance-timeout`). If a module calls `LookupPath` before
warmup completes, the call returns `PkgStatusUnknown`. This
preserves the per-module 30 s ceiling: provenance builds do not eat
into module budgets, and they never block a module that does not
care about provenance.

Read path is a guarded `map[string]string` lookup. Path
canonicalization at lookup time:

1. Try the path verbatim.
2. If absent and the path is a symlink, call `filepath.EvalSymlinks`
   exactly once and retry against the resolved target. The retry is
   bounded by the existing module ctx; a hostile symlink that hangs
   I/O degrades to `PkgStatusOrphan` rather than `PkgStatusOwned`,
   which is the safer default.
3. If both probes miss and the map is non-empty, the path is
   `PkgStatusOrphan`. If the map is empty (build failed), the path
   is `PkgStatusError`. If no package manager was detected, the
   path is `PkgStatusUnknown`.

### Signal emission

Modules call `Provenance.LookupPath(execTarget)` whenever they set
`Record.ExecTarget`. The returned `pkg` populates
`Record.ExecTargetPkg`; the returned status (as its string form)
populates `Record.ExecTargetPkgStatus`. The module appends
`SignalNonPackagePath` to `Record.Signals` if and only if status ==
`PkgStatusOrphan`. No signal is emitted for `Unknown` or `Error`:
the absence is intentional, the backend can filter on the status
string when it needs the distinction.

## Consequences

Positive:

- Q4 (orphan implants in tmp-class dirs) becomes precise: today it
  filters on `interpreter_in_tmp` alone; with provenance live it
  intersects with `non_package_path`, eliminating false positives
  from legitimate tools shipped under `/tmp` in unusual setups.
- The cookbook gains a new high-precision query "orphan exec
  targets outside tmp-class" — the implant pattern that drops
  payloads under `/opt`, `/var/lib`, `/srv`, etc. Today the agent
  has no signal for that pattern at all.
- Every existing module benefits without changing its records'
  semantics, only by populating fields that were already in the
  schema.

Negative:

- The agent gains its first runtime dependency on a host binary
  (`rpm`) for rpm hosts. The dependency is soft: missing-rpm
  degrades to `Error`, not panic. Documented as a known risk.
- The first cron-like agent invocation on a fresh host pays a
  1-3 s warmup. Subsequent cached invocations in the same process
  do not. For a one-shot agent run on a fleet, this is acceptable;
  for a long-running agent (not the v0.2 model) the resolver would
  need TTL-based rebuilds.
- Symlink-aware lookup adds I/O at lookup time. Mitigated by the
  module-ctx bound and by the policy of only retrying once per
  miss.

## Alternatives considered

- **Pure-Go rpm parsing.** Rejected for the reasons enumerated in
  the rpm backend section. May be revisited in v0.3 if a single
  pure-Go library covers BDB + SQLite + ndb under acceptable
  dependency cost.
- **Lazy lookup, no bulk build.** Each LookupPath shells out to
  `rpm -qf <path>` or greps `/var/lib/dpkg/info/*.list` for the
  path. Rejected: ~50 ms per lookup times thousands of records per
  host is two orders of magnitude slower than the bulk model and
  defeats the per-module timeout.
- **Persistent cache on disk.** Rejected on principle: the agent
  is read-only on the host. Caching would require writing to a
  controllable location, which violates the no-side-effects rule.
- **Skip provenance until v0.3.** Rejected: every other v0.2
  enhancement (new modules, /proc correlation) compounds in value
  with provenance, and the field is already in the schema with no
  consumer.
