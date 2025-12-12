#!/bin/sh
set -e
CRON_DIR=${CRON_DIR:-/cron}
if [ -f "$CRON_DIR/mycron" ]; then
  crontab "$CRON_DIR/mycron"
  echo "Installed crontab from $CRON_DIR/mycron"
else
  echo "No cron file at $CRON_DIR/mycron"
fi
mkdir -p /data
crond -b -l 8
exec node src/server.js

