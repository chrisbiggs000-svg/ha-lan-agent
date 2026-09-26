#!/usr/bin/env python3
"""
LAN Agent v2 — hardened Home Assistant add-on.

Command channel: ntfy (poll). Every command is an encrypted envelope
carrying an HMAC-signed payload. Replay protection is persistent
(/data/nonces.json) so restarts don't reopen the window.

There is intentionally NO shell action. The agent only performs the
explicit allowlisted actions in protocol.ACTIONS.

Secrets live in the add-on options (HA stores them); nothing secret
is in this repo.
"""

import json
import os
import socket
import sys
import time
import uuid

import requests

from protocol import (
    ACTIONS,
    CLOCK_SKEW_SECONDS,
    NONCE_TTL_SECONDS,
    NonceStore,
    build_result,
    check_domain,
    check_entity_id,
    check_host,
    check_mac,
    check_port,
    check_service,
    decrypt_command,
    parse_envelope,
    verify_command,
)

CONFIG_PATH = "/data/options.json"
NONCES_PATH = "/data/nonces.json"
STATE_PATH = "/data/state.json"


def log(msg):
    print(f"[lan-agent] {msg}", flush=True)


def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    secret = cfg.get("command_secret", "")
    if len(secret) < 32:
        log("ERROR: command_secret must be set and at least 32 characters")
        sys.exit(1)
    if not cfg.get("command_topic") or not cfg.get("result_topic"):
        log("ERROR: command_topic and result_topic must be configured")
        sys.exit(1)
    cfg.setdefault("ha_url", "http://homeassistant:8123")
    cfg.setdefault("ntfy_server", "https://ntfy.sh")
    cfg.setdefault("poll_interval", 15)
    return cfg


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.secret = cfg["command_secret"]
        self.ntfy_server = cfg["ntfy_server"].rstrip("/")
        self.cmd_topic = cfg["command_topic"]
        self.res_topic = cfg["result_topic"]
        self.ntfy_token = cfg.get("ntfy_token", "")
        # HA access: prefer the Supervisor token (homeassistant_api: true) so no
        # long-lived HA token has to be configured. Falls back to ha_url/ha_token.
        supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
        log(f"DEBUG env names: {sorted(k for k in os.environ if 'TOKEN' in k or 'SUPERVISOR' in k or 'HASSIO' in k)}")
        if supervisor_token:
            self.ha_url = "http://supervisor/core/api"
            self.ha_token = supervisor_token
            self._ha_via_supervisor = True
        else:
            self.ha_url = cfg.get("ha_url", "http://homeassistant:8123").rstrip("/")
            self.ha_token = cfg.get("ha_token", "")
            self._ha_via_supervisor = False
        self.poll_interval = int(cfg.get("poll_interval", 15))
        self._unifi_session = None
        self.nonces = NonceStore()
        self._load_persisted()

    # --- persistence ---------------------------------------------------
    def _load_persisted(self):
        try:
            with open(NONCES_PATH) as f:
                self.nonces.load(json.load(f))
        except (FileNotFoundError, ValueError):
            pass
        self.nonces.prune(int(time.time()))
        try:
            with open(STATE_PATH) as f:
                self.last_ntfy_id = json.load(f).get("last_ntfy_id")
        except (FileNotFoundError, ValueError):
            self.last_ntfy_id = None

    def _save_persisted(self):
        try:
            with open(NONCES_PATH, "w") as f:
                json.dump(self.nonces.dump(), f)
            with open(STATE_PATH, "w") as f:
                json.dump({"last_ntfy_id": self.last_ntfy_id}, f)
        except OSError as e:
            log(f"persist error: {e}")

    # --- ntfy transport -------------------------------------------------
    def _headers(self):
        h = {"Accept": "application/json"}
        if self.ntfy_token:
            h["Authorization"] = f"Bearer {self.ntfy_token}"
        return h

    def poll_commands(self):
        """Return list of raw envelope dicts since last poll."""
        since = self.last_ntfy_id or "all"
        try:
            r = requests.get(
                f"{self.ntfy_server}/{self.cmd_topic}/json?since={since}",
                headers=self._headers(), timeout=30)
            if r.status_code != 200:
                log(f"poll status {r.status_code}")
                return []
            envelopes = []
            for line in r.text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if msg.get("event") != "message":
                    continue
                self.last_ntfy_id = msg.get("id", self.last_ntfy_id)
                try:
                    body = json.loads(msg.get("message", ""))
                    parse_envelope(body)
                    envelopes.append(body)
                except (ValueError, json.JSONDecodeError):
                    continue  # not a v2 envelope; ignore
            return envelopes
        except Exception as e:
            log(f"poll error: {e}")
            return []

    def publish_result(self, envelopes):
        for env in envelopes:
            try:
                requests.post(
                    f"{self.ntfy_server}/{self.res_topic}",
                    data=json.dumps(env),
                    headers={**self._headers(),
                             "Content-Type": "application/json",
                             "Title": "lan-agent"},
                    timeout=15)
            except Exception as e:
                log(f"publish error: {e}")

    def respond(self, cmd_id, action, ok, result):
        self.publish_result(build_result(self.secret, cmd_id, action, ok, result))

    # --- HA helpers ------------------------------------------------------
    def ha_request(self, method, path, body=None):
        headers = {"Content-Type": "application/json"}
        if self.ha_token:
            headers["Authorization"] = f"Bearer {self.ha_token}"
        r = requests.request(method, self.ha_url + path, json=body,
                             headers=headers, timeout=30)
        try:
            data = r.json()
        except ValueError:
            data = r.text[:2000]
        return {"status": r.status_code, "data": data}

    # --- UniFi helpers ----------------------------------------------------
    def unifi_session(self):
        if self._unifi_session:
            return self._unifi_session
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        base = self.cfg.get("unifi_url", "https://192.168.1.1").rstrip("/")
        s = requests.Session()
        s.verify = False
        r = s.post(f"{base}/api/auth/login",
                   json={"username": self.cfg.get("unifi_user", ""),
                         "password": self.cfg.get("unifi_pass", "")},
                   timeout=15)
        if r.status_code not in (200, 204):
            r = s.post(f"{base}/api/login",
                       json={"username": self.cfg.get("unifi_user", ""),
                             "password": self.cfg.get("unifi_pass", "")},
                       timeout=15)
            if r.status_code != 200:
                raise RuntimeError(f"UniFi login failed: {r.status_code}")
        token = r.headers.get("X-CSRF-Token")
        if token:
            s.headers["X-CSRF-Token"] = token
        self._unifi_session = (s, base)
        return self._unifi_session

    def unifi_request(self, method, path, body=None, site="default"):
        s, base = self.unifi_session()
        url = f"{base}/proxy/network/api/s/{site}{path}"
        r = s.request(method, url, json=body, timeout=30)
        if r.status_code == 401:
            self._unifi_session = None
            raise RuntimeError("UniFi session expired, retry")
        try:
            data = r.json()
        except ValueError:
            data = r.text[:2000]
        return {"status": r.status_code, "data": data}

    # --- actions -----------------------------------------------------------
    def do_ping(self, p):
        return {"status": "pong", "agent": "lan-agent", "version": "2.0.0"}

    def do_ha_call_service(self, p):
        domain = check_domain(p["domain"])
        service = check_service(p["service"])
        data = p.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return self.ha_request("POST", f"/api/services/{domain}/{service}", data)

    def do_ha_get_state(self, p):
        entity_id = check_entity_id(p["entity_id"])
        return self.ha_request("GET", f"/api/states/{entity_id}")

    def do_ha_get_states(self, p):
        domain = p.get("domain")
        if domain is not None:
            check_domain(domain)
        resp = self.ha_request("GET", "/api/states")
        if resp["status"] != 200 or not isinstance(resp["data"], list):
            return resp
        out = []
        for s in resp["data"]:
            eid = s.get("entity_id", "")
            if domain and not eid.startswith(domain + "."):
                continue
            attrs = s.get("attributes", {})
            if isinstance(attrs, dict) and len(json.dumps(attrs)) > 2000:
                attrs = {"_truncated": True,
                         "friendly_name": attrs.get("friendly_name")}
            out.append({"entity_id": eid, "state": s.get("state"),
                        "attributes": attrs})
            if len(out) >= 200:
                break
        return {"status": 200, "count": len(out), "data": out}

    def do_ha_get_services(self, p):
        resp = self.ha_request("GET", "/api/services")
        if resp["status"] != 200 or not isinstance(resp["data"], list):
            return resp
        return {"status": 200,
                "data": {d["domain"]: list(d.get("services", {}).keys())
                         for d in resp["data"] if "domain" in d}}

    def do_unifi_get_clients(self, p):
        return self.unifi_request("GET", "/stat/sta", site=p.get("site", "default"))

    def do_unifi_get_devices(self, p):
        return self.unifi_request("GET", "/stat/device", site=p.get("site", "default"))

    def _unifi_sta_cmd(self, p, cmd):
        mac = check_mac(p["mac"])
        return self.unifi_request("POST", "/cmd/stamgr",
                                  {"cmd": cmd, "mac": mac},
                                  site=p.get("site", "default"))

    def do_unifi_reconnect_client(self, p):
        return self._unifi_sta_cmd(p, "kick-sta")

    def do_unifi_block_client(self, p):
        return self._unifi_sta_cmd(p, "block-sta")

    def do_unifi_unblock_client(self, p):
        return self._unifi_sta_cmd(p, "unblock-sta")

    def do_wol(self, p):
        mac = check_mac(p["mac"]).replace(":", "")
        data = b"\xff" * 6 + bytes.fromhex(mac) * 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for bcast in ("255.255.255.255", "192.168.1.255", "192.168.50.255"):
            try:
                sock.sendto(data, (bcast, 9))
            except OSError:
                pass
        return {"status": "WOL packet sent"}

    def do_net_tcp_check(self, p):
        host = check_host(p["host"])
        port = check_port(p.get("port", 80))
        timeout = min(float(p.get("timeout", 3)), 10)
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return {"host": host, "port": port, "open": True}
        except OSError:
            return {"host": host, "port": port, "open": False}

    HANDLERS = {
        "ping": do_ping,
        "ha.call_service": do_ha_call_service,
        "ha.get_state": do_ha_get_state,
        "ha.get_states": do_ha_get_states,
        "ha.get_services": do_ha_get_services,
        "unifi.get_clients": do_unifi_get_clients,
        "unifi.get_devices": do_unifi_get_devices,
        "unifi.reconnect_client": do_unifi_reconnect_client,
        "unifi.block_client": do_unifi_block_client,
        "unifi.unblock_client": do_unifi_unblock_client,
        "wol": do_wol,
        "net.tcp_check": do_net_tcp_check,
    }

    def execute(self, action, params):
        handler = self.HANDLERS.get(action)
        if handler is None:
            return False, {"error": f"unknown action: {action}"}
        try:
            return True, handler(self, params)
        except (ValueError, KeyError) as e:
            return False, {"error": f"bad params: {e}"}
        except Exception as e:
            return False, {"error": f"execution failed: {e}"}

    def handle_envelope(self, env):
        now = int(time.time())
        try:
            cmd = decrypt_command(self.secret, env)
        except Exception:
            return  # not for us / junk; stay silent
        ok, reason = verify_command(self.secret, cmd, self.nonces, now)
        if not ok:
            log(f"rejected command: {reason}")
            return  # stay silent on auth failures — no oracle
        action = cmd["action"]
        cmd_id = cmd["id"]
        log(f"executing {action} (id={cmd_id[:8]})")
        ok, result = self.execute(action, cmd["params"])
        self.respond(cmd_id, action, ok, result)

    def run(self):
        log("Starting LAN Agent v2.0.2")
        via = "supervisor" if self._ha_via_supervisor else "direct"
        log(f"HA URL: {self.ha_url} (via {via}) | poll: {self.poll_interval}s")
        if not self.ha_token:
            log("WARNING: no HA token configured")
        self.respond(f"hello-{uuid.uuid4().hex[:8]}", "hello", True,
                     {"status": "agent online", "version": "2.0.0"})
        while True:
            try:
                envelopes = self.poll_commands()
                for env in envelopes:
                    self.handle_envelope(env)
                if envelopes:
                    self._save_persisted()
            except Exception as e:
                log(f"loop error: {e}")
            self.nonces.prune(int(time.time()))
            time.sleep(self.poll_interval)


def main():
    cfg = load_config()
    Agent(cfg).run()


if __name__ == "__main__":
    main()
