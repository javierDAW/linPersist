#!/usr/bin/env bash
# collect.sh -- run linpersist in each lab container and aggregate.
#
# Iterate-fast: set LINPERSIST_HOST_BINARY=<absolute path> to
# bind-mount a fresh agent over the container's /opt/linpersist
# binary without rebuilding any image.
#
# Tags are loaded per-host from out/hostlist.yaml and passed via
# the agent's --tag flag (ADR-0015), so the resulting NDJSON
# reflects realistic peer-group axes.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOCKER_EXTRA=()
if [[ -n "${LINPERSIST_HOST_BINARY:-}" ]]; then
    if [[ ! -x "$LINPERSIST_HOST_BINARY" ]]; then
        echo "collect.sh: LINPERSIST_HOST_BINARY=$LINPERSIST_HOST_BINARY is not executable" >&2
        exit 1
    fi
    echo ">>> Bind-mounting $LINPERSIST_HOST_BINARY into every container"
    DOCKER_EXTRA+=(-v "${LINPERSIST_HOST_BINARY}:/opt/linpersist/linpersist:ro")
fi

mkdir -p out/per-host-ndjson
: > /tmp/.collect.errors

ok=0; fail=0; total=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Each line in out/host-tags.tsv is: hostname<TAB>tag1<TAB>tag2...
    IFS=$'\t' read -r hostname tags <<< "$line"
    total=$((total+1))

    tag_args=()
    if [[ -n "${tags:-}" ]]; then
        IFS=$'\t' read -ra tag_list <<< "$tags"
        for t in "${tag_list[@]}"; do
            tag_args+=(--tag "$t")
        done
    fi

    if docker run --rm \
        --name "linpersist-collect-${hostname}" \
        --hostname "${hostname}" \
        "${DOCKER_EXTRA[@]}" \
        "linpersist-lab/${hostname}:latest" \
        /opt/linpersist/linpersist --include-hostname "${tag_args[@]}" \
        > "out/per-host-ndjson/${hostname}.ndjson" 2>/tmp/.collect.stderr
    then
        records=$(wc -l < "out/per-host-ndjson/${hostname}.ndjson")
        echo "    ${hostname}: ${records} records"
        ok=$((ok+1))
    else
        echo "    ${hostname}: FAILED" >&2
        cat /tmp/.collect.stderr >&2
        echo "$hostname" >> /tmp/.collect.errors
        fail=$((fail+1))
    fi
done < out/host-tags.tsv

cat out/per-host-ndjson/*.ndjson > out/fleet-realistic.ndjson
total_records=$(wc -l < out/fleet-realistic.ndjson)
echo ""
echo ">>> Done. ${ok}/${total} host(s) collected, ${total_records} record(s)"
if (( fail > 0 )); then
    echo "    Failed hosts:" >&2
    cat /tmp/.collect.errors >&2
fi
echo "    Aggregated: out/fleet-realistic.ndjson"
