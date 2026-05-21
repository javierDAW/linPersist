FROM redhat/ubi9:latest
RUN dnf install -y --allowerasing --setopt=install_weak_deps=False \
      crontabs openssh-server sudo bash-completion zsh \
 && dnf clean all
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
