# Role: monitoring

Prometheus + Grafana + Alertmanager + node-exporter. Realistic
scrape_configs targeting the fleet, provisioned dashboards under
/etc/grafana/provisioning/, alert rules, blackbox_exporter on
these hosts specifically. DataDog agent under /opt/datadog-agent
as the vendor non-package binary.
Tags: role=monitoring tier=observability env=ops.
