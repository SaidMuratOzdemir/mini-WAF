#!/bin/sh
set -eu

CONFIG_PATH="${FORWARD_PROXY_CONFIG_PATH:-/etc/squid/generated/squid.conf}"
BOOTSTRAP_PATH="/opt/squid/bootstrap-squid.conf"

mkdir -p "$(dirname "$CONFIG_PATH")" /var/run/squid /var/log/squid /var/spool/squid

if [ ! -f "$CONFIG_PATH" ]; then
  cp "$BOOTSTRAP_PATH" "$CONFIG_PATH"
fi

exec squid -N -f "$CONFIG_PATH"
