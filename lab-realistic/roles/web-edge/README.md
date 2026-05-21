# Role: web-edge

HTTP termination layer. nginx as reverse proxy + certbot for TLS
+ fail2ban + log shipper (vector or filebeat, 50/50 mix per host).

## What this host ships

- `nginx` with multiple vhosts under `/etc/nginx/sites-enabled/`,
  a `nginx.conf` with `worker_processes` tuned by the operator,
  `ssl_protocols` line edited to drop TLSv1.1.
- `certbot` with a cron job under `/etc/cron.d/certbot` for
  renewal, including an operator-added webhook on success.
- `fail2ban` with a `jail.local` admin override.
- Log shipper:
  - 50% of hosts get `vector` (`/opt/vector/bin/vector`,
    non-package vendor binary).
  - 50% get `filebeat` (apt/dnf-installed).
- `logrotate` drop-ins for nginx access/error logs.

## Drift sources

- Three vhost files added at different dates over the host's
  provisioning history.
- `nginx.conf` `worker_processes` adjusted twice (mtime spread).
- `fail2ban` `jail.local` with custom IP allowlist appended by
  the operator.
- `certbot` renewal cron edited to add a Slack webhook on
  success.

## Tags landed (ADR-0015)

- `role=web-edge`
- `env={prod,staging,canary}` (per env_mix in policy)
- `tier=edge`
- `datacenter={lhr-01,fra-02,dub-03,ams-01}` (random)

## Expected query behaviour

- Q1 / Q3: vhost files vary per host -> a small number of
  singletons per host (their unique vhosts). The cross-host
  baseline (nginx.conf default chunks) stacks normally.
- Q9 / Q11: nginx itself is package-managed -> no orphan
  exec_target rows.
- The `vector` binary is `non_package_path` on hosts that ship
  it -> Q11 candidate (legitimate FP that the analyst learns to
  ignore).
