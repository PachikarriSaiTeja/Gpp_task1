#!/bin/sh
if [ -f /cron/mycron ]; then
  crontab /cron/mycron
  echo "installed"
else
  echo "no cron file"
fi

