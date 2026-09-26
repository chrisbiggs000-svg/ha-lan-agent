#!/usr/bin/env python3
"""
LAN Agent — runs inside Home Assistant as an add-on.
Polls ntfy.sh for commands from Muse, executes them on the local network,
and posts results back.

Commands are JSON: {"id": "uuid", "action": "ha_api", "method": "GET", "path": "/api/states", "body": {...}}
Actions: ha_api, ha_ws, unifi_api, shell, wol
"""

import json
import os
import sys
import time
import uuid
import subprocess
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config from HA add-on options
CONFIG_PATH = "/data/options.json"

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

CONFIG = load_config()
HA_URL = CONFIG.get("ha_url", "http://homeassistant:8123").rstrip("/")
HA_TOKEN = CONFIG.get("ha_token", "")
UNIFI_URL = CONFIG.get("unifi_url", "https://192.168.1.1").rstrip("/")
UNIFI_USER = CONFIG.get("unifi_user", "")
UNIFI_PASS = CONFIG.get("unifi_pass", "")
POLL_INTERVAL = CONFIG.get("poll_interval", 15)
CMD_TOPIC = CONFIG["command_topic"]
RESULT_TOPIC = CONFIG["result_topic"]
NTFY_BASE = "https://ntfy.sh"

SEEN_IDS = set()
UNIFI_SESSION = None


def log(msg):
    print(f"[lan-agent] {msg}", flush=True)


def ntfy_poll():
    """Poll the command topic for new messages."""
    try:
        r = requests.get(
            f"{NTFY_BASE}/{CMD_TOPIC}/json?since=all",
            timeout=30,
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return []
        commands = []
        for line in r.text.strip().split("\n"):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
                if msg.get("event") != "message":
                    continue
                cmd_id = msg.get("id")
                if cmd_id in SEEN_IDS:
                    continue
                SEEN_IDS.add(cmd_id)
                body = msg.get("message", "")
                try:
                    cmd = json.loads(body)
                    cmd["_ntfy_id"] = cmd_id
                    commands.append(cmd)
                except json.JSONDecodeError:
                    log(f"Skipping non-JSON message: {body[:80]}")
            except json.JSONDecodeError:
                continue
        return commands
    except Exception as e:
        log(f"Poll error: {e}")
        return []


def ntfy_publish(result):
    """Publish a result to the result topic."""
    try:
        requests.post(
            f"{NTFY_BASE}/{RESULT_TOPIC}",
            data=json.dumps(result),
            headers={"Content-Type": "application/json", "Title": "lan-agent-result"},
            timeout=15,
        )
    except Exception as e:
        log(f"Publish error: {e}")


def do_ha_api(cmd):
    """Call the Home Assistant REST API."""
    method = cmd.get("method", "GET").upper()
    path = cmd.get("path", "/api/")
    body = cmd.get("body")
    url = HA_URL + path
    headers = {"Content-Type": "application/json"}
    if HA_TOKEN:
        headers["Authorization"] = f"Bearer {HA_TOKEN}"
    r = requests.request(method, url, json=body, headers=headers, timeout=30)
    try:
        return {"status": r.status_code, "data": r.json()}
    except Exception:
        return {"status": r.status_code, "data": r.text[:2000]}


def do_ha_ws(cmd):
    """Call the Home Assistant WebSocket API."""
    import websocket
    ws_url = HA_URL.replace("http://", "ws://").replace("https://", "wss://") + "/api/websocket"
    ws = websocket.create_connection(ws_url, timeout=15)
    # Auth phase
    msg = json.loads(ws.recv())
    if msg.get("type") == "auth_required":
        ws.send(json.dumps({"type": "auth", "access_token": HA_TOKEN}))
        msg = json.loads(ws.recv())
        if msg.get("type") != "auth_ok":
            ws.close()
            return {"error": f"WS auth failed: {msg}"}
    req = cmd.get("ws_message", {})
    req_id = req.get("id", 1)
    req["id"] = req_id
    ws.send(json.dumps(req))
    # Collect responses until we get our id
    result = None
    for _ in range(10):
        msg = json.loads(ws.recv())
        if msg.get("id") == req_id:
            result = msg
            break
    ws.close()
    return result or {"error": "No response with matching id"}


def unifi_login():
    """Login to UniFi OS and return a session."""
    global UNIFI_SESSION
    if UNIFI_SESSION:
        return UNIFI_SESSION
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{UNIFI_URL}/api/auth/login",
        json={"username": UNIFI_USER, "password": UNIFI_PASS},
        timeout=15,
    )
    if r.status_code in (200, 204):
        UNIFI_SESSION = s
        # Get CSRF token if present
        token = r.headers.get("X-CSRF-Token") or (r.json().get("csrfToken") if r.text else None)
        if token:
            s.headers["X-CSRF-Token"] = token
        return s
    # Try legacy Network app login
    r = s.post(
        f"{UNIFI_URL}/api/login",
        json={"username": UNIFI_USER, "password": UNIFI_PASS},
        timeout=15,
    )
    if r.status_code == 200:
        UNIFI_SESSION = s
        return s
    raise Exception(f"UniFi login failed: {r.status_code} {r.text[:200]}")


def do_unifi_api(cmd):
    """Call the UniFi local API."""
    global UNIFI_SESSION
    method = cmd.get("method", "GET").upper()
    path = cmd.get("path", "/")
    body = cmd.get("body")
    try:
        s = unifi_login()
    except Exception as e:
        return {"error": str(e)}
    url = UNIFI_URL + path
    r = s.request(method, url, json=body, timeout=30)
    if r.status_code == 401:
        UNIFI_SESSION = None  # force re-login next time
        return {"error": "UniFi session expired, retry"}
    try:
        return {"status": r.status_code, "data": r.json()}
    except Exception:
        return {"status": r.status_code, "data": r.text[:2000]}


def do_shell(cmd):
    """Run a shell command (allowlisted)."""
    command = cmd.get("command", "")
    # Basic allowlist — block dangerous patterns
    BLOCKED = ["rm -rf /", "mkfs", "dd if=", ":(){", "shutdown", "reboot", "halt", "poweroff"]
    for b in BLOCKED:
        if b in command:
            return {"error": f"Blocked command pattern: {b}"}
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout[:5000],
            "stderr": result.stderr[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out after 60s"}
    except Exception as e:
        return {"error": str(e)}


def do_wol(cmd):
    """Send a Wake-on-LAN magic packet."""
    import socket
    import struct
    mac = cmd.get("mac", "").replace(":", "").replace("-", "")
    if len(mac) != 12:
        return {"error": "Invalid MAC address"}
    data = b"\xff" * 6 + bytes.fromhex(mac) * 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(data, ("<broadcast>", 9))
    # Also try subnet broadcasts
    for bcast in ["192.168.1.255", "192.168.50.255"]:
        try:
            sock.sendto(data, (bcast, 9))
        except Exception:
            pass
    return {"status": "WOL packet sent", "mac": cmd.get("mac")}


def execute(cmd):
    """Execute a command and return the result."""
    action = cmd.get("action")
    cmd_id = cmd.get("id", str(uuid.uuid4()))
    log(f"Executing {action} (id={cmd_id})")
    try:
        if action == "ha_api":
            data = do_ha_api(cmd)
        elif action == "ha_ws":
            data = do_ha_ws(cmd)
        elif action == "unifi_api":
            data = do_unifi_api(cmd)
        elif action == "shell":
            data = do_shell(cmd)
        elif action == "wol":
            data = do_wol(cmd)
        elif action == "ping":
            data = {"status": "pong", "agent": "lan-agent", "version": "1.0.0"}
        else:
            data = {"error": f"Unknown action: {action}"}
    except Exception as e:
        data = {"error": f"Execution failed: {e}"}
    return {"id": cmd_id, "action": action, "result": data, "timestamp": time.time()}


def main():
    log("Starting LAN Agent v1.0.0")
    log(f"HA URL: {HA_URL}")
    log(f"UniFi URL: {UNIFI_URL}")
    log(f"Poll interval: {POLL_INTERVAL}s")
    log(f"Command topic: {CMD_TOPIC[:12]}...")
    if not HA_TOKEN:
        log("WARNING: No HA token configured — HA API calls will fail")
    if not CMD_TOPIC or not RESULT_TOPIC:
        log("ERROR: command_topic and result_topic must be configured")
        sys.exit(1)

    # Announce we're alive
    ntfy_publish({"id": "startup", "action": "ping",
                   "result": {"status": "agent online", "version": "1.0.0"},
                   "timestamp": time.time()})

    while True:
        try:
            commands = ntfy_poll()
            for cmd in commands:
                result = execute(cmd)
                ntfy_publish(result)
        except Exception as e:
            log(f"Loop error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
