#!/bin/sh
# roles/monitoring/packages.sh -- install realistic observability-tier packages.
#
# Modules linpersist will see drop new content:
#   - systemd.unit (prometheus, node_exporter, alertmanager, grafana)
#   - systemd.timer (prometheus-server provisions some)
#   - passwd.user (prometheus, grafana service accounts)
#   - profile.d (grafana-server completion in some distros)
#   - cron.d (typically none)
#   - logrotate.d / cron.daily (prometheus log rotation)
#
# Monitoring hosts are mtime-spike candidates for Q8: config-management
# touches all the per-target scrape config files at every push.

set -eu

case "${DISTRO:-}" in
    debian12 | ubuntu2204)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            prometheus \
            prometheus-node-exporter \
            prometheus-alertmanager
        apt-get clean
        rm -rf /var/lib/apt/lists/*
        ;;

    rhel9)
        # UBI9 + EPEL9 slim do NOT ship prometheus2 or
        # golang-github-prometheus-* packages. Full RHEL with
        # subscription does (via modular streams) but UBI9 strips
        # them. Real RHEL monitoring hosts use full RHEL or pull
        # prometheus from the upstream tarball. Lab decision: monitoring
        # role isn't viable on UBI9 -- policy file reassigns these
        # slots to debian/ubuntu.
        echo "roles/monitoring/packages.sh: rhel9 not supported" >&2
        echo "  Reason: UBI9 lacks prometheus packages." >&2
        exit 1
        ;;

    amzn2023)
        # AmazonLinux 2023 has golang-github-prometheus-node-exporter
        # but the prometheus server itself is not in repos. Install
        # what's available.
        dnf install -y \
            golang-github-prometheus-node-exporter \
         || true
        dnf clean all
        ;;

    alpine320)
        apk add --no-cache \
            prometheus \
            prometheus-node-exporter
        ;;

    *)
        echo "roles/monitoring/packages.sh: unknown DISTRO=${DISTRO:-<unset>}" >&2
        exit 1
        ;;
esac
