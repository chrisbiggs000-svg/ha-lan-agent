#!/usr/bin/env bash
set -e

CONFIG_PATH=/data/options.json

echo "Starting LAN Agent add-on..."
echo "Config: $(cat $CONFIG_PATH | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: (v[:8]+"..." if k in ("ha_token","unifi_pass","command_topic","result_topic") and v else v) for k,v in d.items()})')"

exec python3 /app/agent.py
