#!/bin/sh
# Drops the six dbus system-bus *.service files that every modern
# Linux distro ships from packages (NetworkManager, polkit,
# accountsservice, systemd-{hostnamed,localed,timedated}). The lab
# containers never actually run dbus-daemon, but the agent walks the
# directory at filesystem level so static drops are sufficient.
#
# Contents are identical across all four distros that COPY+RUN this
# script (ubuntu, debian, rhel9, amzn2023). That is the whole point:
# six identical content_norm_sha256 stacks across ~all hosts in the
# fleet, leaving the dbus-system-impostor implant as the only Q1
# singleton fleet-wide. Real fleets have minor exec-path variation
# between distros, but for the stacking model the canonical-form
# collapse is what matters.
set -eu

DIR=/usr/share/dbus-1/system-services
mkdir -p "$DIR"

cat > "$DIR/org.freedesktop.NetworkManager.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.NetworkManager
Exec=/usr/sbin/NetworkManager
User=root
SystemdService=NetworkManager.service
EOF

cat > "$DIR/org.freedesktop.PolicyKit1.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.PolicyKit1
Exec=/usr/lib/polkit-1/polkitd --no-debug
User=root
SystemdService=polkit.service
EOF

cat > "$DIR/org.freedesktop.Accounts.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.Accounts
Exec=/usr/libexec/accounts-daemon
User=root
SystemdService=accounts-daemon.service
EOF

cat > "$DIR/org.freedesktop.hostname1.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.hostname1
Exec=/usr/lib/systemd/systemd-hostnamed
User=root
SystemdService=systemd-hostnamed.service
EOF

cat > "$DIR/org.freedesktop.locale1.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.locale1
Exec=/usr/lib/systemd/systemd-localed
User=root
SystemdService=systemd-localed.service
EOF

cat > "$DIR/org.freedesktop.timedate1.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.timedate1
Exec=/usr/lib/systemd/systemd-timedated
User=root
SystemdService=systemd-timedated.service
EOF

chmod 0644 "$DIR"/*.service
