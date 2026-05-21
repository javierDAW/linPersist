# Role: web-app

Application tier behind the edge. Mix of PHP-FPM and Node.js
between hosts (60/40 split per policy).

PHP hosts ship php-fpm + composer + redis-cli + custom systemd
service per app. Node hosts ship node + pm2 (systemd-managed) +
npm global binaries under /usr/lib/node_modules/. Both kinds get
app-specific cron jobs (cache warmup, queue workers) and systemd
unit overrides under <unit>.d/local.conf.

Tags: role=web-app env={prod,staging,dev} tier=app runtime={php,node}
