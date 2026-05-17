#!/usr/bin/env bash
# tools/ingest.sh -- load a directory of linpersist NDJSON outputs
# into DuckDB. Optional Parquet export and SQL execution.
#
# Typical fleet pipeline:
#
#   1. Every host writes its NDJSON to a shared store named
#      <host_id>.ndjson.
#   2. A cron job pulls the day's files into a local directory.
#   3. This script materializes them into DuckDB and runs the
#      canonical stacking queries.
#
# Pure-bash dependency on the `duckdb` CLI; no Python, no Docker.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [-o PARQUET_OUT] [-d DB_OUT] [-q QUERIES_SQL] INPUT_DIR

Reads every *.ndjson file directly under INPUT_DIR, materializes a
DuckDB table named "r", and optionally exports it to Parquet and/or
runs a SQL file against it.

Options:
  -o PARQUET_OUT   Export to Parquet at this path (e.g. fleet.parquet).
                   Useful for repeat-query workflows: subsequent
                   sessions can attach the Parquet without rescanning
                   the NDJSON.
  -d DB_OUT        Persist the DuckDB database to this file (e.g.
                   fleet.duckdb). Without -d, the database is
                   in-memory and only the Parquet export survives the
                   script's exit.
  -q QUERIES_SQL   Run this SQL file against r after loading. The
                   shipped tools/stack_demo.sql is the canonical
                   choice.
  -h               This message.

The script prints a single summary row to stderr after loading:
  records=<N> hosts=<H> modules=<M>
so a wrapping cron job can detect zero-result loads.

Examples:

  # Load one day's NDJSON and run the six demo queries:
  $0 -q tools/stack_demo.sql ./fleet-2026-05-17/

  # Build a Parquet export for repeat analysis:
  $0 -o fleet.parquet ./fleet-2026-05-17/

  # Persist a DuckDB file an analyst can attach interactively:
  $0 -d fleet.duckdb ./fleet-2026-05-17/
  duckdb fleet.duckdb -c "SELECT module, count(*) FROM r GROUP BY 1;"
EOF
}

PARQUET_OUT=""
DB_OUT=""
QUERIES_SQL=""

while getopts ":o:d:q:h" opt; do
    case "$opt" in
        o) PARQUET_OUT="$OPTARG" ;;
        d) DB_OUT="$OPTARG" ;;
        q) QUERIES_SQL="$OPTARG" ;;
        h) usage; exit 0 ;;
        \?) echo "Unknown option: -$OPTARG" >&2; usage >&2; exit 2 ;;
        :)  echo "Option -$OPTARG requires an argument" >&2; usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

INPUT_DIR="$1"

if ! command -v duckdb >/dev/null 2>&1; then
    echo "ingest.sh: duckdb CLI not found in PATH" >&2
    echo "ingest.sh: install from https://duckdb.org/docs/installation/" >&2
    exit 1
fi

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "ingest.sh: $INPUT_DIR is not a directory" >&2
    exit 1
fi

# Resolve INPUT_DIR to an absolute path so the glob in
# read_ndjson_auto works regardless of duckdb's cwd. The glob is
# expanded by duckdb, NOT by the shell.
ABS_INPUT="$(cd "$INPUT_DIR" && pwd)"
PATTERN="${ABS_INPUT}/*.ndjson"

# Sanity check: at least one file matches.
shopt -s nullglob
matched=( "${ABS_INPUT}"/*.ndjson )
shopt -u nullglob
if [[ ${#matched[@]} -eq 0 ]]; then
    echo "ingest.sh: no *.ndjson files under $INPUT_DIR" >&2
    exit 1
fi

DB_ARG=":memory:"
if [[ -n "$DB_OUT" ]]; then
    DB_ARG="$DB_OUT"
fi

# Build the SQL program incrementally. Each chunk ends with a
# semicolon so duckdb treats it as one statement at a time.
SQL=$(cat <<EOF
CREATE TABLE r AS
  SELECT * FROM read_ndjson_auto('${PATTERN}', ignore_errors=true);
SELECT
  'records=' || count(*)
  || ' hosts=' || count(DISTINCT host_id)
  || ' modules=' || count(DISTINCT module)        AS summary
FROM r;
EOF
)

if [[ -n "$PARQUET_OUT" ]]; then
    SQL+="
COPY (SELECT * FROM r) TO '${PARQUET_OUT}' (FORMAT PARQUET, COMPRESSION 'ZSTD');
"
fi

if [[ -n "$QUERIES_SQL" ]]; then
    if [[ ! -f "$QUERIES_SQL" ]]; then
        echo "ingest.sh: queries file not found: $QUERIES_SQL" >&2
        exit 1
    fi
    SQL+="
$(cat "$QUERIES_SQL")"
fi

echo "ingest.sh: ${#matched[@]} input files under $ABS_INPUT" >&2
duckdb "$DB_ARG" -c "$SQL"
