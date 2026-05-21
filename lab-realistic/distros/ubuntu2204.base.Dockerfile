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

RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
