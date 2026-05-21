# Role: db-replica

Read replicas + streaming replication consumers. Like db-primary
but with replica connection configs, no backup cron, monitoring
exporter the same. Tags: role=db-replica env=... engine={pg,mysql}.
