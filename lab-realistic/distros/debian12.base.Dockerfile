FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cron openssh-server sudo bash-completion zsh ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
