FROM amazonlinux:2023
RUN dnf install -y --allowerasing --setopt=install_weak_deps=False \
      cronie openssh-server sudo bash-completion zsh shadow-utils \
 && dnf clean all
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
