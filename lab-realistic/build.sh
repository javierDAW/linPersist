#!/usr/bin/env bash
# build.sh -- build the lab-realistic v2 Docker images.
#
# Reads out/hostnames.txt (produced by scripts/generate.py) and
# builds the per-host Docker images in risk order (most likely
# to fail distros first).
#
# Modes:
#   ./build.sh                  full build of every host
#   ./build.sh --validate       build one representative per (distro, role)
#   ./build.sh --hosts <h1,h2>  build only the named hosts
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="full"
ONLY_HOSTS=""
for arg in "$@"; do
    case "$arg" in
        --validate)        MODE="validate" ;;
        --hosts=*)         ONLY_HOSTS="${arg#*=}"; MODE="hosts" ;;
        --hosts)           shift; ONLY_HOSTS="$1"; MODE="hosts" ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
    esac
done

if [[ ! -d out/dockerfiles ]]; then
    echo "build.sh: out/dockerfiles missing; run scripts/generate.py first" >&2
    exit 1
fi

# ---- Step 1: ensure distro base images exist ---------------------------
# distro filenames look like:
#   ubuntu2204.base.Dockerfile  -> distro = ubuntu2204
#   amzn2.legacy.Dockerfile     -> distro = amzn2
# We extract the leading segment before the first dot. That is also the
# convention generate.py uses when picking the FROM line.
echo ">>> Building distro base images (cached if unchanged)"
for distro_file in distros/*.Dockerfile; do
    fname=$(basename "$distro_file")
    distro=${fname%%.*}
    echo "    base: $distro  ($fname)"
    docker build \
        -t "linpersist-lab/${distro}-base:latest" \
        -f "$distro_file" . \
        || { echo "build.sh: distro base FAILED for $distro" >&2; exit 1; }
done

# ---- Step 2: select build list -----------------------------------------
build_list_file=$(mktemp)
trap 'rm -f "$build_list_file"' EXIT

case "$MODE" in
    validate)
        echo ">>> [validate] one representative host per (distro, role)"
        python3 - "$build_list_file" <<'PY'
import sys, yaml
hosts = yaml.safe_load(open("out/hostlist.yaml")).get("hosts", [])
seen, reps = set(), []
for h in hosts:
    k = (h["distro"], h["role"])
    if k in seen: continue
    seen.add(k); reps.append(h)
risk = {"rhel9": 0, "amzn2023": 1, "amzn2": 2, "alpine320": 3, "ubuntu2204": 4, "debian12": 5}
reps.sort(key=lambda h: (risk.get(h["distro"], 99), h["role"]))
with open(sys.argv[1], "w") as f:
    for h in reps: f.write(h["hostname"] + "\n")
PY
        ;;
    hosts)
        echo ">>> [hosts] $ONLY_HOSTS"
        printf '%s\n' ${ONLY_HOSTS//,/ } > "$build_list_file"
        ;;
    *)
        echo ">>> [full] all hosts in risk order"
        python3 - "$build_list_file" <<'PY'
import sys, yaml
hosts = yaml.safe_load(open("out/hostlist.yaml")).get("hosts", [])
risk = {"rhel9": 0, "amzn2023": 1, "amzn2": 2, "alpine320": 3, "ubuntu2204": 4, "debian12": 5}
hosts.sort(key=lambda h: (risk.get(h["distro"], 99), h["role"], h["hostname"]))
with open(sys.argv[1], "w") as f:
    for h in hosts: f.write(h["hostname"] + "\n")
PY
        ;;
esac

total=$(wc -l < "$build_list_file")
echo ">>> Building $total host(s)"
n=0
while IFS= read -r hostname; do
    [[ -z "$hostname" ]] && continue
    n=$((n+1))
    df="out/dockerfiles/${hostname}.Dockerfile"
    if [[ ! -f "$df" ]]; then
        echo "build.sh: missing Dockerfile $df" >&2
        exit 1
    fi
    echo "    [$n/$total] $hostname"
    docker build \
        -t "linpersist-lab/${hostname}:latest" \
        -f "$df" . \
        || { echo "build.sh: FAILED at $hostname" >&2; exit 1; }
done < "$build_list_file"

echo ">>> Done. $total image(s) ready."
