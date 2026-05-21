# Amazon Linux 2 (yum, no --allowerasing support).
FROM amazonlinux:2
RUN yum install -y \
      cronie openssh-server sudo at bash-completion zsh shadow-utils initscripts \
 && yum clean all
RUN mkdir -p /opt/linpersist && touch /opt/linpersist/linpersist
WORKDIR /opt/linpersist
