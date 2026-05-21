# Role: db-primary

Primary database. PostgreSQL or MySQL (66/33 split per policy).
Ships full server config, WAL archiving cron (pg) or binlog
config (mysql), backup tooling (pgbackrest / wal-g), and the
prometheus exporter as a vendor non-package binary under
/opt/prometheus-exporters/.

pg_hba.conf has been edited multiple times over months adding
replica connection entries; backup cron carries JIRA-2104 style
operator comments. Tags: role=db-primary env=... engine={pg,mysql}.
