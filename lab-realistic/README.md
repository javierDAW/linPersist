# lab-realistic v2

This directory holds the realistic-fleet validation lab for
`linpersist`. It replaces the v1 lab (75 minimal containers) with
a 50-host fleet that simulates the messy reality of long-lived
Linux infrastructure: full software stacks per role, drift over
time, dotfile abundance on developer workstations, vendor
non-package binaries, distro-specific quirks.

The lab exists in the repo as of v0.3.3 (the v1 policy of keeping
the entire directory gitignored is documented as a v0.1.0
expedient in `.gitignore`). Only the generated outputs under
`out/` remain ignored.

## Quick start

```sh
cd lab-realistic

# 1. Materialize Dockerfiles from policy + roles + implants.
python3 scripts/generate.py

# 2. Build the fleet (cached layers make this ~5-10 min after
#    the first run; cold start ~25 min).
./build.sh

# 3. Run the agent inside every container and aggregate the NDJSON.
LINPERSIST_HOST_BINARY="$PWD/../dist/linpersist-linux-amd64" ./collect.sh

# 4. Render the fleet report.
../dist/linpersist-report -i out/fleet-realistic.ndjson \
  -format html -o out/report.html

# 5. Score the report against the ground truth (precision /
#    recall per query).
python3 scripts/score.py
```

## Spec

The full design lives in `docs/lab-realistic-v2-spec.md` at the
repo root. Read it first if you intend to add or modify roles.

## Iteration loop

Edit a role template under `roles/<name>/role.Dockerfile.tmpl`,
re-run `python3 scripts/generate.py`, then `./build.sh`. Docker
layer cache keeps the rebuild cheap when only one role changed.

For a single-host edit, target it directly:

```sh
docker build -t "linpersist-lab/${HOSTNAME}:latest" \
  -f "out/dockerfiles/${HOSTNAME}.Dockerfile" .
```

## See also

- `docs/lab-realistic-v2-spec.md` — full design rationale.
- `docs/benchmarks/v0.3.3-realistic.md` — measured numbers.
- `docs/stacking-cookbook.md` — what each query means.
