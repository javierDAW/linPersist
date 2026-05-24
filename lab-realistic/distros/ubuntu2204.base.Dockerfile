# Ubuntu 22.04 base for lab-realistic v2.
# Minimal package set: only what linpersist's agent and the
# generated config files need at filesystem level. Role
# templates ship config files via `cat > /etc/.../foo.conf`,
# not via apt install -- the agent reads the filesystem, not
# the running services, so binaries are unnecessary.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cron openssh-server sudo bash-completion zsh ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Drop the dbus system-bus baseline files (NetworkManager, polkit,
# accountsservice, systemd-{hostnamed,localed,timedated}). Mirrors a
# stock package install at filesystem level; needed for fleet-scale
# Q1 stacking on dbus.system to behave realistically.
COPY distros/_dbus-system-baseline.sh /tmp/_dbus-system-baseline.sh
RUN /bin/sh /tmp/_dbus-system-baseline.sh && rm /tmp/_dbus-system-baseline.sh

RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
