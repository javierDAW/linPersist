#!/bin/sh
# roles/k8s-node/packages.sh -- install realistic Kubernetes node packages.
#
# Modules linpersist will see drop new content:
#   - kmod  (modules-load.d/k8s.conf for overlay + br_netfilter is the
#            biggest source -- a real k8s install drops this file with
#            ~5 modules to autoload)
#   - sysctl.d (k8s drops /etc/sysctl.d/99-kubernetes-cri.conf)
#   - systemd.unit (containerd.service, kubelet.service)
#   - cron (none new typically -- k8s does log rotation in-cluster)
#
# We do NOT install kubelet/kubeadm/kubectl from the upstream k8s.io
# repo because adding a third-party repo to every distro multiplies
# the failure surface. We install containerd + the kernel module
# config that mimics what kubeadm would emit. That captures the
# kmod / sysctl noise floor without needing the actual cluster tooling.

set -eu

case "${DISTRO:-}" in
    debian12 | ubuntu2204)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            containerd \
            ipset \
            iptables \
            socat \
            conntrack
        apt-get clean
        rm -rf /var/lib/apt/lists/*
        ;;

    rhel9)
        # UBI9 (Red Hat Universal Base Image 9) ships none of the
        # k8s-node convenience packages: containerd.io comes from
        # Docker's own repo; conntrack-tools is in CRB which UBI9
        # doesn't expose; the rest live in BaseOS. Install only the
        # available subset. Real RHEL k8s nodes use full RHEL repos
        # or the Kubernetes upstream packages from k8s.io.
        dnf install -y \
            ipset \
            iptables \
            socat
        dnf clean all
        ;;

    amzn2023)
        # Amazon Linux 2023 ships containerd as a separate package.
        dnf install -y \
            containerd \
            ipset \
            iptables \
            socat \
            conntrack-tools
        dnf clean all
        ;;

    alpine320)
        apk add --no-cache \
            containerd \
            ipset \
            iptables \
            socat \
            conntrack-tools
        ;;

    *)
        echo "roles/k8s-node/packages.sh: unknown DISTRO=${DISTRO:-<unset>}" >&2
        exit 1
        ;;
esac

# Drop the modules-load.d entry that kubeadm would create. This is
# realistic config: any k8s node needs overlay + br_netfilter at boot.
mkdir -p /etc/modules-load.d
cat > /etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
chmod 0644 /etc/modules-load.d/k8s.conf

# And the matching sysctl.d entry. Not collected by linpersist v0.1.0
# (sysctl module is not in v0.1.0), but the file presence is part of
# the realistic role baseline so future versions detect it.
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<'EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
chmod 0644 /etc/sysctl.d/99-kubernetes-cri.conf
