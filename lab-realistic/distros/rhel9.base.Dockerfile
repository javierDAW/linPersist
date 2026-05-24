FROM redhat/ubi9:latest
RUN dnf install -y --allowerasing --setopt=install_weak_deps=False \
      crontabs openssh-server sudo bash-completion zsh \
 && dnf clean all
COPY distros/_dbus-system-baseline.sh /tmp/_dbus-system-baseline.sh
RUN /bin/sh /tmp/_dbus-system-baseline.sh && rm /tmp/_dbus-system-baseline.sh
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
