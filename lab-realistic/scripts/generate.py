#!/usr/bin/env python3
"""Generate the lab-realistic v2 fleet artifacts.

Reads policies/realistic-50.yaml, roles/<role>/role.Dockerfile.tmpl,
and implants/catalog.yaml, and emits under out/:

    dockerfiles/<hostname>.Dockerfile  -- per-host build instructions
    hostlist.yaml                       -- {hostname, distro, role, tags, implants}
    host-tags.tsv                       -- <hostname>\t<tag1>\t<tag2>...  (consumed by collect.sh)
    ground_truth.jsonl                  -- one line per implant placement

The generator is deterministic given the policy `seed`.

Usage: python3 scripts/generate.py

Vars exposed to role templates:
    ${hostname}, ${distro}, ${env}, ${datacenter}, ${provisioned_at_iso},
    ${runtime}, ${engine}, ${team}, ${log_shipper},
    ${primary_user}, ${old_user_a}, ${old_user_b},
    ${cluster_name}
"""
from __future__ import annotations
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from string import Template

import yaml

LAB = Path(__file__).resolve().parent.parent
POLICY = LAB / "policies" / "realistic-50.yaml"
ROLES_DIR = LAB / "roles"
CATALOG = LAB / "implants" / "catalog.yaml"
TEMPLATES_DIR = LAB / "implants" / "templates"
OUT = LAB / "out"

NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=timezone.utc)


def weighted_pick(rng, distribution):
    """distribution: {key: weight}. Returns one key sampled by weight."""
    keys = list(distribution.keys())
    weights = [distribution[k] for k in keys]
    return rng.choices(keys, weights=weights, k=1)[0]


def random_user_name(rng, taken):
    """Generate a plausible username that is not yet taken."""
    pool = ["alice", "bob", "carol", "dave", "eve", "frank", "grace",
            "henry", "irene", "jack", "karen", "leo", "maya", "nick",
            "olivia", "pat", "quinn", "rosa", "sam", "tess", "uma",
            "victor", "wendy", "xena", "yusuf", "zoe"]
    while True:
        c = rng.choice(pool)
        if c not in taken:
            taken.add(c)
            return c


def provisioned_at(rng, role_pa, default_pa):
    pa = role_pa or default_pa
    days = rng.randint(pa["min_days_ago"], pa["max_days_ago"])
    return NOW - timedelta(days=days)


def generate_host(rng, role, host_index, datacenters, default_pa):
    """Build the host record. Does NOT render the Dockerfile yet."""
    distro = weighted_pick(rng, role["distros"]) if "distros" in role \
        else weighted_pick(rng, default_distro_mix)

    role_id = role["id"]
    short_distro = {"ubuntu2204": "ubu", "debian12": "deb",
                    "rhel9": "rhel", "amzn2023": "amzn",
                    "alpine320": "alp", "amzn2": "amzn2"}.get(distro, distro)
    hostname = f"r-{role_id}-{short_distro}-{host_index:02d}"

    pa = provisioned_at(rng, role.get("provisioned_at"), default_pa)
    pa_iso = pa.strftime("%Y-%m-%dT%H:%M:%SZ")

    host = {
        "hostname": hostname,
        "distro": distro,
        "role": role_id,
        "provisioned_at_iso": pa_iso,
        "datacenter": rng.choice(datacenters),
        "tags": dict(role.get("tags", {})),
    }
    host["tags"]["datacenter"] = host["datacenter"]

    # Per-role variant axes.
    if "env_mix" in role:
        host["env"] = weighted_pick(rng, role["env_mix"])
        host["tags"]["env"] = host["env"]
    else:
        host["env"] = host["tags"].get("env", "prod")
    if "runtime_mix" in role:
        host["runtime"] = weighted_pick(rng, role["runtime_mix"])
        host["tags"]["runtime"] = host["runtime"]
    if "engine_mix" in role:
        host["engine"] = weighted_pick(rng, role["engine_mix"])
        host["tags"]["engine"] = host["engine"]
    if "team_mix" in role:
        host["team"] = weighted_pick(rng, role["team_mix"])
        host["tags"]["team"] = host["team"]

    # web-edge log_shipper 50/50.
    if role_id == "web-edge":
        host["log_shipper"] = rng.choice(["vector", "filebeat"])

    # dev-workstation users.
    if role_id == "dev-workstation":
        taken = set()
        host["primary_user"] = random_user_name(rng, taken)
        host["old_user_a"] = random_user_name(rng, taken)
        host["old_user_b"] = random_user_name(rng, taken)

    return host


def render_role_template(role_id, host):
    tmpl_path = ROLES_DIR / role_id / "role.Dockerfile.tmpl"
    text = tmpl_path.read_text(encoding="utf-8")
    return Template(text).safe_substitute(host)


def render_implant_template(implant, host):
    tmpl_path = TEMPLATES_DIR / implant["template"]
    text = tmpl_path.read_text(encoding="utf-8")
    return Template(text).safe_substitute({**host, **implant.get("vars", {})})


def assign_implants(rng, hosts, catalog):
    """Round-robin placement: each implant is spread across its declared
    roles before any role is doubled-up.

    Pre-v0.5.x this was a flat shuffle-and-take-first-N which let the
    deterministic seed bias all placements into one role (the v0.3.4
    handoff documented ssh-forced-tmp landing all 3 on build-ci + web-edge
    with zero on bastion despite the [bastion, build-ci, web-edge]
    declaration). Round-robin fixes the bias while staying deterministic
    under the same seed.

    Returns implants_by_host: {hostname: [implant_id, ...]}."""
    by_role = {}
    for h in hosts:
        by_role.setdefault(h["role"], []).append(h)

    assignments = {}
    implant_by_id = {i["id"]: i for i in catalog["implants"]}
    for implant_id, plan in catalog.get("placements", {}).items():
        count = plan["count"]
        roles = plan["roles"]
        # Per-role pool, shuffled so the seed picks vary across roles
        # but the rotation across roles is deterministic.
        pools = {r: by_role.get(r, []).copy() for r in roles}
        for r in pools:
            rng.shuffle(pools[r])
        picked = []
        i = 0
        # Rotate through roles in declaration order; each rotation takes
        # one host from that role's pool. Skip roles whose pool is empty.
        # Stop when count is met or every pool is exhausted.
        while len(picked) < count:
            role = roles[i % len(roles)]
            i += 1
            pool = pools[role]
            if pool:
                picked.append(pool.pop(0))
            if all(len(p) == 0 for p in pools.values()):
                break
        for h in picked:
            assignments.setdefault(h["hostname"], []).append(implant_id)

    return assignments, implant_by_id


def main():
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))

    global default_distro_mix
    default_distro_mix = policy["distro_mix_default"]
    default_pa = policy["provisioned_at_default"]

    rng = random.Random(policy.get("seed", 42))

    hosts = []
    for role in policy["roles"]:
        n = role["count"]
        for i in range(1, n + 1):
            hosts.append(generate_host(rng, role, i, policy["datacenters"], default_pa))

    print(f"generate.py: {len(hosts)} hosts", file=sys.stderr)

    assignments, implant_by_id = assign_implants(rng, hosts, catalog)

    OUT.mkdir(exist_ok=True)
    (OUT / "dockerfiles").mkdir(exist_ok=True)

    hostlist_data = {"hosts": []}
    hostnames_out = []
    host_tags_lines = []
    ground_truth_lines = []

    for h in hosts:
        impls = assignments.get(h["hostname"], [])

        # Render role template body.
        body = render_role_template(h["role"], h)

        # Stamp the role-template configs to provisioned_at BEFORE
        # implants land. Two reasons for this order:
        #   1. Without the stamp, every host would emit a ~100-record
        #      cluster carrying recent_mtime_7d, drowning Q8.
        #   2. Stamping AFTER implants (as pre-v0.5.x did) erases the
        #      recent_mtime_7d signal on the implant itself — implants
        #      should look fresh because they ARE fresh, and Q1/Q7/Q9
        #      catalogue entries that expect recent_mtime_7d must
        #      actually observe it. Bug closed in v0.5.x consolidation.
        body += (
            "\n# Stamp every operator-shaped config to provisioned_at\n"
            "# BEFORE implants land — implants get build-time (recent) mtime.\n"
            "RUN find /etc /home -type f 2>/dev/null "
            f"| xargs -r -I{{}} touch -d \"{h['provisioned_at_iso']}\" {{}} 2>/dev/null ; true\n"
        )

        # Append implant snippets AFTER the stamp.
        for impl_id in impls:
            impl = implant_by_id[impl_id]
            body += "\n\n# ---- Implant: " + impl_id + " ----\n"
            body += render_implant_template(impl, h)
            # Ground truth.
            gt = {
                "host": h["hostname"],
                "implant": impl_id,
                "module": impl["module"],
                "site_class": impl["site_class"],
                "expected_signals": impl.get("expected_signals", []),
                "expected_caught_by": impl.get("expected_caught_by", []),
                "expected_q7_rule": impl.get("expected_q7_rule"),
            }
            ground_truth_lines.append(json.dumps(gt, sort_keys=True))
        # Write Dockerfile.
        dockerfile = OUT / "dockerfiles" / f"{h['hostname']}.Dockerfile"
        dockerfile.write_text(body, encoding="utf-8")

        # hostlist entry.
        hostlist_data["hosts"].append({
            "hostname": h["hostname"],
            "distro": h["distro"],
            "role": h["role"],
            "implants": impls,
            "provisioned_at": h["provisioned_at_iso"],
            "tags": [f"{k}={v}" for k, v in sorted(h["tags"].items())],
        })

        hostnames_out.append(h["hostname"])

        # host-tags.tsv: hostname<TAB>tag1<TAB>tag2...
        # Note: datacenter is excluded from the emitted tagset to avoid
        # over-fragmenting Q3 peer-groups. The datacenter dimension is
        # still recorded in hostlist.yaml for documentation but does
        # not affect the agent's host_meta.tags slice.
        tag_strs = [f"{k}={v}" for k, v in sorted(h["tags"].items())
                    if k != "datacenter"]
        host_tags_lines.append(h["hostname"] + "\t" + "\t".join(tag_strs))

    (OUT / "hostlist.yaml").write_text(
        yaml.safe_dump(hostlist_data, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    (OUT / "hostnames.txt").write_text(
        "\n".join(hostnames_out) + "\n", encoding="utf-8")
    (OUT / "host-tags.tsv").write_text(
        "\n".join(host_tags_lines) + "\n", encoding="utf-8")
    (OUT / "ground_truth.jsonl").write_text(
        "\n".join(ground_truth_lines) + "\n", encoding="utf-8")

    n_impl = sum(len(v) for v in assignments.values())
    print(f"generate.py: {n_impl} implants placed across "
          f"{len(assignments)} hosts", file=sys.stderr)
    print(f"generate.py: wrote {OUT}/{{dockerfiles/, hostlist.yaml, "
          f"hostnames.txt, host-tags.tsv, ground_truth.jsonl}}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
