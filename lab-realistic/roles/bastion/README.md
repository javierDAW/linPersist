# Role: bastion

SSH bastion. 2FA, audit logging, restricted shell. PAM-yubikey
or PAM-duo, auditd rules, rsyslog forwarding, restricted shell
wrapper. AuthorizedKeysCommand pointing at vault-cli (vendor
non-package). Splunk Forwarder under /opt/splunkforwarder.
Tags: role=bastion env={prod,corp} tier=access.
