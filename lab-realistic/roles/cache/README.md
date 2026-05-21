# Role: cache

Redis or Memcached, plus monitoring. redis.conf with realistic
eviction policy, AOF/RDB persistence, Sentinel config. Vendor
non-package redis_exporter under /opt/prometheus-exporters/.
tuned-adm active profile on RHEL hosts. sysctl.d drop-ins.
Tags: role=cache tier=data engine={redis,memcached}.
