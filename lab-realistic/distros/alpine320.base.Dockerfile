FROM alpine:3.20
RUN apk add --no-cache \
      bash zsh coreutils util-linux shadow sudo \
      openssh-server openrc dcron ca-certificates
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
