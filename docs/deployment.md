# Deployment guide

`linpersist` is a single static binary that the operator runs on
each host they want collected. It reads the filesystem, computes
NDJSON records, and writes them to stdout (or to `--output <file>`).
It does NOT make network calls, NOT write to the host filesystem
outside `--output`, and NOT need a long-running daemon. Transport
of the resulting NDJSON to a backend is the operator's problem,
solved with the tools the operator already has.

This document covers the lifecycle: place the binary, decide how
to invoke it, tag the host so the backend can peer-group it,
ship the NDJSON.

## Quick start

```sh
# 1. Drop the binary in PATH.
install -m 0755 linpersist-linux-amd64 /usr/local/bin/linpersist

# 2. Run once, write to stdout.
/usr/local/bin/linpersist --tag role=web --tag env=prod > /tmp/lp.ndjson

# 3. Inspect.
wc -l /tmp/lp.ndjson      # one record per line
head -1 /tmp/lp.ndjson | python3 -m json.tool
```

That is the complete contract. Everything below is the operator's
guide for doing the same thing at scale.

## Invocation patterns

The agent does not require a specific scheduler. Pick whichever
matches the rest of the fleet.

### Ansible / Salt / Chef / Puppet

The standard pattern in flotas tradicionales. The orchestration
tool already knows the host's role and environment from its
inventory, so the tags are a direct substitution. Example with
Ansible:

```yaml
- name: Run linpersist
  ansible.builtin.command: >
    /usr/local/bin/linpersist
    --tag role={{ host_role }}
    --tag env={{ environment }}
    --tag datacenter={{ inventory_hostname.split('.')[1] }}
    --output /var/log/linpersist/{{ ansible_date_time.iso8601_basic }}.ndjson
  register: lp_run
  changed_when: false   # collection is idempotent; do not flag as a change
```

Saltstack (`cmd.run` state) and Chef (`execute` resource) are
direct translations.

### cron, per-host

Provisioning drops `/etc/cron.d/linpersist` with the host-specific
tags hardcoded by the same provisioning step that decides the
host's role:

```cron
# /etc/cron.d/linpersist
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin
0 2 * * * root /usr/local/bin/linpersist \
  --tag role=database --tag env=prod --tag datacenter=fra-02 \
  --output /var/log/linpersist/$(date +\%Y\%m\%d).ndjson
```

The host produces one collection per day at 02:00 local time. A
log shipper picks up `/var/log/linpersist/*.ndjson` and forwards
to the backend.

### systemd timer

Cron's modern equivalent. Two units:

```ini
# /etc/systemd/system/linpersist.service
[Unit]
Description=linpersist collector
ConditionPathExists=/usr/local/bin/linpersist

[Service]
Type=oneshot
Environment="LINPERSIST_ROLE=web" "LINPERSIST_ENV=prod"
ExecStart=/usr/local/bin/linpersist \
  --tag role=${LINPERSIST_ROLE} \
  --tag env=${LINPERSIST_ENV} \
  --output /var/log/linpersist/%i.ndjson
```

```ini
# /etc/systemd/system/linpersist.timer
[Unit]
Description=linpersist collector daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

`RandomizedDelaySec=2h` spreads the load when a 5000-host fleet
all timer-triggers near midnight.

### Wrapper script reading host metadata

Sometimes the orchestration is upstream of the host (cloud-init,
Packer, an image build) and the agent's command line cannot
embed the tags directly. A small wrapper reads them from local
files:

```sh
#!/bin/sh
# /usr/local/bin/linpersist-collect.sh
ROLE=$(cat /etc/linpersist/role 2>/dev/null || echo unknown)
ENV=$(cat /etc/linpersist/env 2>/dev/null || echo unknown)
DC=$(cat /etc/linpersist/datacenter 2>/dev/null || echo unknown)
exec /usr/local/bin/linpersist \
  --tag role=$ROLE --tag env=$ENV --tag datacenter=$DC \
  "$@"
```

Image-build drops the three `/etc/linpersist/*` files; cron or
systemd calls the wrapper. The agent itself never reads those
files (ADR-0015: no auto-detection of tags), so corrupt or
missing metadata produces `unknown` and is visible to the
analyst rather than silently hidden.

### Containers / Kubernetes

The agent works inside a container that has `/proc` and the
target rootfs visible. Two deployment shapes:

**DaemonSet**, one collector pod per node, bind-mounting the
host's rootfs read-only:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: linpersist
spec:
  selector:
    matchLabels: { app: linpersist }
  template:
    metadata:
      labels: { app: linpersist }
    spec:
      hostPID: true
      containers:
      - name: linpersist
        image: ghcr.io/example/linpersist:v0.3.1
        command: ["/linpersist"]
        args:
          - "--tag"
          - "cluster=$(CLUSTER_NAME)"
          - "--tag"
          - "node=$(NODE_NAME)"
          - "--output"
          - "/output/lp.ndjson"
        env:
        - name: CLUSTER_NAME
          value: "prod-eu"
        - name: NODE_NAME
          valueFrom:
            fieldRef: { fieldPath: spec.nodeName }
        volumeMounts:
        - { name: host, mountPath: /host, readOnly: true }
        - { name: out,  mountPath: /output }
      volumes:
      - { name: host, hostPath: { path: / } }
      - { name: out,  emptyDir: {} }
```

**Job triggered by a CronJob**, for periodic collection without
a long-running pod. Same args; CronJob owns the schedule.

The `hostPID: true` and host rootfs mount are the K8s shape of
the same privileges a cron+root deployment has on bare metal.

## Host tags

Tags are operator-supplied metadata that the backend uses to
peer-group hosts for LFA. Adding `--tag role=build --tag env=prod`
puts the host into the `(os_id, env=prod,role=build)` peer-group;
hosts with byte-identical canonical tag sets stack together and
their `(module, content_norm_sha256)` distributions compete with
each other rather than with the whole fleet. The motivating case
is CI sudoers: 30 build hosts each shipping `/etc/sudoers.d/20-jenkins`
collapse from 30 Q1 singletons to one Q3 row when they share a
`role=build` tag.

### Format contract

Per ADR-0015:

| field | grammar                                          | length |
|-------|--------------------------------------------------|--------|
| key   | `[a-z][a-z0-9_-]{0,62}`                          | 1-63   |
| value | `[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?` or empty  | 0-63   |

Tags with uppercase, whitespace, leading hyphen or trailing
punctuation are rejected at parse time. Reserved keys (`hostname`,
`hostname_hash`, `os_id`, `os_version`, `kernel`, `arch`,
`boot_id`, `host_id`) are rejected because they already exist as
top-level `host_meta` fields.

### Multi-value

The same key may appear multiple times. `--tag role=build --tag
role=ci` produces `host_meta.tags = ["role=build", "role=ci"]`,
sorted alphabetically. Use this for hosts that legitimately
serve two roles or are mid-migration between environments.

### Determinism

Order of `--tag` flags on the CLI does NOT affect the output.
The agent sorts and deduplicates before writing
`host_meta.tags`. Two invocations with the same logical tag set
produce byte-identical NDJSON.

### What the agent does NOT do

- **No environment-variable inheritance** (`LINPERSIST_TAGS=`).
- **No YAML/JSON config file** (`/etc/linpersist/tags.yaml`).
- **No auto-detection** from hostname patterns, `/etc/role`,
  cloud metadata APIs, K8s downward API, etc.

The CLI flag is the single source of truth. This is deliberate:
auto-detection trades a small operator convenience for a large
class of FP scenarios (host mis-tagged because provisioning
partially failed, two different auto-detection sources
disagreeing, etc.) that the analyst then has to debug from the
NDJSON. Read the wrapper-script pattern above for the
recommended way to integrate with local metadata files.

### Useful tag axes

The taxonomy is up to the operator. Common useful axes:

| key          | example values             | rationale                                                |
|--------------|----------------------------|----------------------------------------------------------|
| `role`       | `web`, `db`, `build`, `ci` | the host's job, the most useful peer-group axis          |
| `env`        | `prod`, `staging`, `dev`   | separates ephemeral CI noise from production stability   |
| `datacenter` | `lhr-01`, `fra-02`, `aws-eu-west-1` | regional sub-grouping if the fleet is geo-distributed |
| `tier`       | `edge`, `core`, `archive`  | criticality axis for risk prioritisation                 |
| `compliance` | `pci`, `hipaa`, `none`     | regulatory scope                                         |
| `team`       | `ops`, `sre`, `data`       | escalation routing                                       |
| `infra_type` | `bare-metal`, `vm`, `k8s`  | useful for hybrid fleets                                 |

Three to five tags per host is the sweet spot. More tags shrinks
peer-groups; the `peer_hosts > 2` floor in Q3 excludes
peer-groups too small to learn a baseline from, so over-tagging
reintroduces the Q1 fragmentation problem peer-group LFA was
meant to solve.

### Backward compatibility

A host invoked without `--tag` writes an empty
`host_meta.tags`. Q3 puts it in the "untagged" peer-group of its
`os_id` family, exactly as v0.3.0 did with `os_id`-only Q3. You
can roll out tags incrementally: tag a few hosts, ship them
through to the backend, observe Q3 split into tagged + untagged
peer-groups, then continue tagging.

## Transport

The agent prints NDJSON to stdout. From there, transport is the
operator's existing log pipeline. Three common shapes:

### File-based with a log shipper

```sh
linpersist --tag ... --output /var/log/linpersist/$(date +%Y%m%d).ndjson
```

Filebeat, Vector, Fluent Bit, rsyslog (imfile module) all pick
up `/var/log/linpersist/*.ndjson` and forward to the backend.
The shipper retries on backend-side failures; the agent does not
need to know.

### Piped into the shipper directly

```sh
linpersist --tag ... | vector --config /etc/vector.toml
```

For deployments where you do not want to persist the NDJSON to
disk on the host (forensic posture: "no agent artifacts on
disk"). The shipper's config file owns the forwarding.

### S3 / object store, via aws-cli or equivalent

```sh
linpersist --tag ... \
  | aws s3 cp - "s3://lp-fleet/$(hostname)/$(date +%Y%m%d).ndjson"
```

For cloud-native fleets without a centralised log pipeline. The
backend ingests from the bucket on a schedule.

### What the agent does NOT do

- No HTTP/HTTPS output.
- No syslog/Kafka/AMQP output.
- No retry, no buffering, no in-memory queue.

Every one of these is the log-shipper's job. The agent's NDJSON
contract is intentionally narrow so it stays a leaf node of the
infrastructure.

## Verification after rollout

After deploying the agent to a fleet, verify three things:

1. **Coverage**: each host produces NDJSON at the expected
   cadence. `Q10` in `linpersist-report` flags hosts with zero or
   anomalously few records.

2. **Tagging**: spot-check `host_meta.tags` in a sample of
   records.

   ```sh
   head -100 collected.ndjson \
     | python3 -c "
   import json, sys, collections
   c = collections.Counter()
   for line in sys.stdin:
       for t in json.loads(line)['host_meta'].get('tags', []) or ['<untagged>']:
           c[t] += 1
   for t, n in c.most_common(20): print(f'{n:6d} {t}')"
   ```

3. **Peer-group shape**: run the report and confirm `Q3`'s peer
   distribution matches your fleet's expected segmentation.

   ```sh
   linpersist-report -i collected/ -format text -color=off \
     | awk '/^Q3 /,/^Q4 /'
   ```

If Q3 collapses everything to one giant `(os_id, "")` peer-group,
the tags did not land -- check the orchestration tool's
substitution. If Q3 fragments into hundreds of tiny peer-groups,
the tag set is too narrow -- drop tags or coarsen values until
peer-groups have at least the `peer_hosts > 2` threshold of
members.

## Troubleshooting

| Symptom                                          | First thing to check                                                         |
|--------------------------------------------------|------------------------------------------------------------------------------|
| `linpersist: invalid value "..." for flag -tag`  | tag format failed validation; check the grammar table above                  |
| `host_meta.tags` empty in NDJSON                 | tags not passed on CLI; check the orchestration tool's argument expansion    |
| Q3 row count balloons after tagging              | over-fragmented peer-groups; coarsen tag values or drop a dimension          |
| Q3 row count drops to zero after tagging         | every peer-group fell below `peer_hosts > 2`; tag too narrow for fleet size  |
| Agent exits with code 2 and prints Usage         | flag parsing failed; the error line above the Usage explains why             |
| NDJSON has zero records                          | run with `--log-level debug 2>>/tmp/lp.log`; per-module errors land in errors[] |
| `permission denied` reading `/etc/foo`           | run as root; the agent does not invoke any escalation primitives             |
