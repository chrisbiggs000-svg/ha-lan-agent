#!/usr/bin/env bash
set -e

CONFIG_PATH=/data/options.json

echo "Starting LAN Agent add-on v2..."
echo "Config: $(cat $CONFIG_PATH | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: ("..." if k in ("ha_token","unifi_pass","command_secret","ntfy_token") and v else v) for k,v in d.items()})')"

exec python3 /app/agent.py
