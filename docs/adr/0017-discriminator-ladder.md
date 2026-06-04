# ADR-0017: The discriminator ladder — homogeneity is per-(host, site_class), not per-host

- Status: Accepted
- Date: 2026-06-03

## Context

ADR-0016 assumption #2 states that "LFA needs a heterogeneous, sized
fleet" and degrades on N=1. A cross-disciplinary architecture/DFIR/
Linux-systems consensus exercise (9 specialists → 31 candidate
approaches → adversarial cross-lens evaluation → discipline leads → a
synthesizing chair) sharpened that assumption and exposed it as
**stated at the wrong granularity**.

The triggering observation: the "single web server floods Q1" problem
(closed for `webroot` in the duel-final patch — co-indicator emission
gate + Q1 co-indicator ranking) is **not** webroot-specific. It is a
general property of the LFA discriminator. **Any** single-purpose host
in a fleet — the one database server, the one bastion/jump host, the one
CI builder, the one monitoring box — carries host-specific files (its
data dir, its bespoke config, its keys, its deployed app tree) that are
**unique in the fleet by design**, even when 100 other identical hosts
exist elsewhere. Each such unique-but-benign file is a `(module,
content_norm_sha256)` singleton and surfaces in Q1. For a host with no
homogeneous peer — the common real-world case, since most fleets are a
mix of roles — pure fleet-content-rarity collapses into noise and floods
the analyst.

The naive reading of ADR-0016 ("LFA degrades on N=1") under-describes
this: the same bastion host **does** have a valid comparand population
for `cron.d` (every server shares the base crontab) while having **none**
for its bespoke `authorized_keys`. Homogeneity is therefore not a
property of a *host*; it is a property of a **`(host, site_class)`
pair**.

## Decision: name the discriminator ladder

Fleet content-rarity is a discriminator **only where a valid comparand
population exists**. Everywhere else linpersist must **rank and inform
honestly, never adjudicate — and never delete the forensic artifact to
buy quiet.** Concretely, the backend descends a fixed precedence ladder
per `(host, site_class)`:

1. **Rung 1 — structural co-indicator present.** A record carrying any
   of `non_package_path` / `package_file_tampered` / `exec_target_orphan`
   / `interpreter_in_tmp` / tmp-class / `world_writable` / `immutable` /
   `append_only` / `mount_shadows_path` / `recent_{mtime,ctime}_*` is
   **actionable regardless of population**. The locus + tell is the
   signal; rarity only ranks it.

2. **Rung 2 — a sized homogeneous cohort exists.** When the host's
   `(os_id, tag_set)` cohort has ≥ peer-floor `k` members (Q3), use
   **cohort-LFA**: a singleton *within the cohort* is the signal. Cohort
   membership must only ever **add** a view, never remove the global Q1
   singleton.

3. **Rung 3 — a prior snapshot of this host exists.** Use **within-host
   delta** (diff mode): cross-time novelty is the one denominator an
   attacker cannot pre-seed by owning a reference host. Scoped strictly
   as rung 3 — see the rejected-alternatives note; it is **not** the
   primary answer.

4. **Rung 4 — none of the above.** A bare fleet content-novelty
   singleton (`co=0`, no cohort, no prior snapshot) is emitted as
   **INFORMATIONAL ONLY**. It is **never suppressed and never deleted** —
   the row stays in the corpus as a scannable forensic artifact — but it
   is presented as triage material, not a verdict.

### Two refinements the consensus adopted

- **Collector discriminator class is a backend-derived property of
  `(module, site_class)`, never agent-emitted.** Whether content-novelty
  is the *only* load-bearing signal for a site_class — i.e. provenance is
  *structurally inapplicable* (always-true, as on a docroot walk) — is a
  pure function of `(module, site_class)`, both already on every record.
  Deriving it backend-side (over a curated table with a build-failing
  exhaustiveness check) avoids importing discriminator-selection
  **policy** into the agent, which would force a fleet-wide redeploy per
  retune — the exact coupling the agent/backend split exists to prevent.
  The axis is deliberately **NOT** "open-ended walker vs known-locus"
  (`suidbits` is open-ended yet gates correctly on `suid`+`non_package`;
  `k8s.static-pod`/`cloudinit`/`confexec` are known-locus yet
  unique-by-design). The right predicate is *"is provenance structurally
  inapplicable here so content-novelty is the only signal?"* — today only
  `webroot.script`; the table is the seam by which the **next** such
  collector inherits the rung-4 treatment instead of re-discovering the
  flood.

- **Demotion is always rank-only.** Moving a `co=0` singleton to the
  informational partition is a presentation decision, never a drop. The
  genuinely-rare single-host implant is, by construction, *also* a `co=0`
  singleton — so any mechanism whose net effect is to remove `co=0` rows
  from the analyst's view (suppression, manifest subtraction, or a banner
  that says "look away") trades blindness for quiet and is forbidden.

## Decision: extend ADR-0016 assumption #2

ADR-0016 §"two load-bearing assumptions" assumption #2 ("LFA needs a
heterogeneous, sized fleet") is **refined**: homogeneity is a
per-`(host, site_class)` property, and the silent-defeat condition is
stated precisely as:

> **The settled, structural-tell-free implant on a peerless single-role
> host, seen on first contact (no prior snapshot), is irreducibly out of
> reach.** On such a host package provenance can be inapplicable or
> satisfied (admin-authored config is `non_package_path` by design at a
> canonical locus), there is no cohort for rung 2, no own-past for rung 3,
> and the implant — benign-looking, owned-path, mtime/ctime-backdated, no
> tmp/orphan tell — is by construction a `co=0` content-singleton
> indistinguishable from the dozens of benign-unique-by-design files at
> the same loci. linpersist's honest position there is **triage, not
> adjudication**: it ranks and informs, and the engagement deliverable
> must state the mitigations that restore verdict-power — deploy across
> role replicas (≥ peer-floor `k`) to enable cohort-LFA, re-scan over time
> to enable own-baseline diff, or pair with host-baselining / EDR.

This is a sibling of the existing packaged-LOLBin and golden-image
silent-defeat conditions, not a defect.

## Decision: the doc must not outrun the mechanism

ADR-0016 exists partly to prevent a confident claim outrunning the
code. Before this ADR, `computeQ1` only **sorted** by co-indicator count
and never **partitioned** — so a prose claim of "demotion on peerless
hosts" would have lied. Therefore the rung-4 informational partition is
**rendered as a real, separate section** in both the text and HTML
report (an Actionable group for rung-1 rows, and an explicitly-labelled
Informational / bare-novelty group for `co=0` rows that names the rungs
which would restore verdict-power). The coverage-degraded banner
(provenance-blind hosts) and the peerless-host framing are worded to
**intensify** scrutiny (manual review + EDR pairing), never to license
de-prioritizing those hosts.

## Alternatives evaluated and rejected

- **Golden-image / expected-baseline manifests** (subtract a registered
  per-role known-benign-unique set; surface only the residual).
  **Rejected, unanimously and most emphatically.** It inverts the
  trust direction onto the **most attacker-controllable key (content)**:
  a poisoned reference host blesses a baked-in implant fleet-wide with an
  audit trail that *manufactures false confidence* — strictly worse than
  the honest N=1 boundary. The allowlist must choose between narrow
  (rots on every legitimate deploy → re-floods → abandoned) and broad
  (swallows the malicious member of the same path-class, which is the
  literal hunt target). Diff mode already supplies, honestly, the
  per-host denominator the manifest pretends to.

- **Agent-emitted role / collector-class / baseline-class hints.**
  **Rejected.** Every bit they propose is either a pure function of
  `module`/`site_class` already on the wire (zero new information, costs
  a fleet-wide agent release) or *is* agent-side role classification
  (a separation-of-concerns regression; the agent collects faithfully,
  the backend infers).

- **Doc-only ("name the boundary, change no rows").** **Rejected as
  insufficient on its own.** Honest framing that changes zero report rows
  relabels the flood as "expected" and risks the analyst skipping the
  `co=0` list where the true positive lives. Superseded by the ladder,
  which actually partitions.

- **Promote within-host diff to the PRIMARY discriminator.**
  **Rejected as primary; adopted as rung 3.** The modal engagement is
  agentless first-touch with no prior snapshot; self-history is
  adversary-influenced on the compromised peerless host; and on churny
  hosts (CI/k8s/post-patch-window) diff converts a uniqueness flood into
  a temporal-churn flood. A valuable rung, never the answer.

## Consequences

- The report partitions Q1 into Actionable (rung-1) and Informational
  (rung-4) groups; the informational group is never suppressed.
- A backend-side `(module, site_class)` discriminator-class table exists,
  with a test that **fails the build** if any matrix.yaml site_class is
  unclassified — so a new module is a conscious classification decision,
  not a silent default.
- `scope.md` §8.1 documents the peerless-host boundary and the ladder as
  a client-facing condition of validity.
- **Open questions** (tracked, not yet decided): the precise
  machine-readable predicate for "content-novelty is the only signal"
  beyond `webroot.script`; whether "no sized homogeneous cohort" is even
  computable per host given linpersist has no role taxonomy (likely only
  knowable per `(host, site_class)`); the identity/retention/integrity
  requirements of a rung-3 history store and how its attacker-reachability
  on a compromised host is bounded; and whether auto-discovered cohorts
  (if ever added) need a higher peer-floor than operator-tagged ones.
