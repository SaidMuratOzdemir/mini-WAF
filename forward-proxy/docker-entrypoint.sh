#!/bin/sh
set -eu

CONFIG_PATH="${FORWARD_PROXY_CONFIG_PATH:-/etc/squid/generated/squid.conf}"
BOOTSTRAP_PATH="/opt/squid/bootstrap-squid.conf"

mkdir -p "$(dirname "$CONFIG_PATH")" /var/run/squid /var/log/squid /var/spool/squid

if [ ! -f "$CONFIG_PATH" ]; then
  cp "$BOOTSTRAP_PATH" "$CONFIG_PATH"
fi

# ── Phase 9A.1-D: Squid log rotation via cron-like background loop ──
# Rotates access.log + cache.log every 6 hours, keeps 7 generations.
(
  while true; do
    sleep 21600  # 6 hours
    squid -k rotate -f "$CONFIG_PATH" 2>/dev/null || true
    # Prune old rotated logs beyond 7 generations
    for logfile in /var/log/squid/access.log /var/log/squid/cache.log; do
      for old in $(ls "${logfile}".* 2>/dev/null | sort -rn | tail -n +8); do
        rm -f "$old"
      done
    done
  done
) &

exec squid -N -f "$CONFIG_PATH"
