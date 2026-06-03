# ADR-0016: Coverage is enumerative and bounded — the coverage philosophy

- Status: Accepted
- Date: 2026-06-03

## Context

Three adversarial red/blue/architect duels (duel-1, duel-2, duel-3)
have each surfaced many uncovered persistence sites, which we then
closed with gated, lab-validated detections. The recurring, legitimate
question this raises:

> If every duel finds this many gaps, is the tool approaching complete
> coverage, or is the gap space effectively unbounded?

Without a written answer, two failure modes follow. (1) A future
maintainer or duel reads a new finding as "the tool is broken" rather
than "a point on a known long tail / a deliberate boundary". (2) A
consulting client over-trusts the tool, not understanding what it is and
is not. This ADR names the coverage model and its boundaries so neither
happens. It is the architectural-canon companion to the client-facing
`docs/scope.md` §8.2.

## Decision: name the model — coverage is ENUMERATIVE

A persistence site is covered **iff a module walks its locus and parses
its grammar**. The Linux persistence surface is open-ended — every
daemon/framework that reads a config and executes something is a
potential site — so the set of findable gaps is **unbounded but
long-tailed**. The duels do not converge to zero; they descend a long
tail of decreasing prevalence and severity. We accept this and frame
coverage in three regimes.

### Regime 1 — the tool's domain (high recall, low FP)

On-disk artifacts at **known loci** carrying a **structural tell**
(`non_package_path` / `exec_target_orphan` / `interpreter_in_tmp` /
`package_file_tampered` / `recent_{mtime,ctime}_*`), surfaced by LFA
rarity on a heterogeneous fleet. The shipped 56 site_classes across 27
modules live here (see `matrix.yaml`). This is where recall is high and
FPs are calibrated low.

### Regime 2 — the long tail INSIDE the model (diminishing returns)

Every other config-embedded exec edge and known-locus parser not yet
written: language-runtime auto-exec (python `sitecustomize`/`.pth`/
`PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5LIB`, PHP `auto_prepend_file`,
`RUBYOPT`, `.Rprofile`), obscure scheduler/init variants, per-app hooks
(CUPS backends, git `core.hooksPath`, MTA milters, ...), more container
/ runtime surfaces. The `confexec` module (ADR-introduced duel-3)
generalizes the *pattern* — walk locus, parse grammar, lift the absolute
command/.so to `ExecTarget`, reuse the central provenance pipeline — but
**each grammar is bespoke and software-dependent**. We descend this tail
by ROI; we explicitly do **not** claim to exhaust it.

### Regime 3 — OUTSIDE the model BY DESIGN (never, correctly)

A point-in-time, agentless, disk-walk collector cannot and must not
cover:

- **In-memory / fileless**: process injection (T1055), `memfd_create`
  payloads, an `LD_PRELOAD` already loaded into a running process whose
  on-disk config is gone. The agent reads disk, not RAM.
- **Runtime view ≠ disk view**: bind-mount / overlay shadowing of a
  packaged path, a deleted-but-open file, mount-namespace tricks,
  rootkit-hidden directory entries (the agent's `readdir` is told a
  lie). The agent `Stat()`s the underlying inode and trusts the kernel
  it queries.
- **Kernel-level**: eBPF programs, loaded-then-deleted modules, syscall
  table hooks.
- **Firmware / pre-OS**: UEFI, a bootkit below the initrd, option ROMs.
- **Temporal blindness**: a payload installed and removed between scans;
  persistence that materializes only at trigger time (downloads itself),
  leaving only a benign-looking loader on disk.

Covering Regime 3 requires becoming an **EDR** (resident agent, CGO /
eBPF, false positives, runtime cost) and **breaks the founding
invariants** (ADR-0001 module model; "no CGO, no daemons, pure Go";
point-in-time; agentless). It is deliberately the territory of a
different class of tool, paired alongside linpersist, not absorbed into
it.

## Decision: two load-bearing assumptions, stated as conditions of validity

These are the silent-defeat conditions every operator and analyst must
know:

1. **Provenance trust.** `non_package_path` / `package_file_tampered`
   trust that the dpkg/rpm/apk database tells the truth. A
   malicious-but-package-OWNED binary — a poisoned repo, a trojaned
   package, or an attacker who controls the package DB's view — resolves
   `owned` and stays **silent**. linpersist is a *trust oracle over
   package metadata*, NOT a supply-chain attestation tool (SBOM /
   signature verification). When the package manager's view is
   compromised, every "owned" verdict is wrong.

2. **LFA needs a heterogeneous, sized fleet.** Singleton stacking is the
   durable discriminator, and it degrades on N=1 or on a homogeneous
   golden-image fleet where the implant is baked into the image (then it
   is fleet-common, not rare). The **packaged-LOLBin / semantic-malice**
   boundary — persistence achieved with only owned binaries on owned
   paths (an sshd `ForceCommand=/usr/bin/python`, a cron line invoking
   `systemd-run`), or malicious *arguments* to an otherwise-legitimate
   directive — emits no structural tell and is intentionally signal+LFA
   only. The signals are structural, not semantic.

## Decision: how to triage a future duel finding

- **Regime 3?** → document it as a boundary (`scope.md` §8.1/§8.2),
  do NOT build.
- **Regime 2 with real prevalence AND a clean orphan/non-package tell?**
  → build it (a `confexec` grammar or a focused module), gated on the
  co-indicator, lab-validated, FP class documented.
- **Regime 2 long-tail-niche, OR resting on a false-evasion premise the
  code already catches** (e.g. the symlink/owned-directory "laundering"
  implants — provenance is an exact-path set, so resolving into `/opt`
  is the opposite of laundering) → no-op, record why. Do NOT add
  directory-prefix ownership shortcuts to `LookupPath`: that would *open*
  the laundering hole, not close it.

## Consequences

- A duel finding gaps is the adversarial coverage-expansion model
  **working as intended**, not evidence the tool is failing or near
  "done". There is no "done" — the tail is infinite.
- "How much of real-world Linux persistence does linpersist cover?" has
  an honest answer in *kind*, not in percentage: **a well-defined slice
  — on-disk, known-locus, structural-tell persistence surfaced by fleet
  rarity — and explicitly nothing in Regime 3.**
- **Stop criterion for the tail (Regime 2):** descend until the
  ROI-per-grammar (prevalence × severity of the vector) drops below the
  cost of writing and maintaining the grammar. There is no obligation to
  cover a vector merely because a duel can name it.

## Out of scope (this ADR mandates no construction)

- Any Regime 3 capability (those would be a different product).
- A generic content / library scanner (the LFA model is not a whole-tree
  scanner — collect the *config token*, e.g. the nsswitch service name or
  the `LD_PRELOAD` value, and resolve only the *named* target).
- The Tier-3 deferred items from duel-3 (`getty_autologin` signal,
  `mount_shadows_path` `/proc/self/mountinfo` enrichment) — those are
  Regime 1/2 candidates tracked in the handoff, not precluded here.
