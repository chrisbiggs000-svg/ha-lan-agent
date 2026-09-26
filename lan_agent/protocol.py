#!/usr/bin/env python3
"""
LAN Agent v2 — protocol layer (no I/O, no config).

Wire format (both directions):
    {"v": 2, "enc": "<base64>"}
where the base64 payload is:
    nonce(12) || AES-256-GCM(nonce, plaintext)
Plaintext is canonical JSON.

Commands (Muse -> agent), plaintext schema:
    {"id": str, "ts": int, "nonce": str, "action": str, "params": dict, "sig": str}
sig = HMAC-SHA256(secret, "id\\nts\\nnonce\\naction\\ncanonical(params)").hex()

Results (agent -> Muse), plaintext schema:
    {"id": str, "action": str, "ts": int, "ok": bool, "result": any}
Large results are split into chunks; each chunk is its own envelope:
    {"v": 2, "id": str, "seq": int, "of": int, "enc": "<base64 chunk>"}
"""

import base64
import hashlib
import hmac
import json
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 2
CLOCK_SKEW_SECONDS = 300          # max |now - ts| for a command
NONCE_TTL_SECONDS = 600          # how long a seen nonce is remembered
MAX_PARAMS_BYTES = 8192
CHUNK_CHARS = 3000               # base64 chars per ntfy message (ntfy.sh limit ~4096)

# --- validation patterns -------------------------------------------------
RE_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
RE_DOMAIN = re.compile(r"^[a-z0-9_]+$")
RE_MAC = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
RE_HOST = re.compile(
    r"^(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?|"
    r"\d{1,3}(\.\d{1,3}){3})$"
)

# Explicit allowlist — there is intentionally no shell action.
ACTIONS = {
    "ping",
    "ha.call_service",
    "ha.get_state",
    "ha.get_states",
    "ha.get_services",
    "unifi.get_clients",
    "unifi.get_devices",
    "unifi.reconnect_client",
    "unifi.block_client",
    "unifi.unblock_client",
    "wol",
    "net.tcp_check",
}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _kdf(secret: str, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"lan-agent-v2",
        info=info,
    ).derive(secret.encode("utf-8"))


def cmd_key(secret: str) -> bytes:
    return _kdf(secret, b"commands")


def res_key(secret: str) -> bytes:
    return _kdf(secret, b"results")


def encrypt(key: bytes, plaintext: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(key: bytes, blob: str) -> bytes:
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def sign_command(secret: str, cmd_id: str, ts: int, nonce: str,
                 action: str, params: dict) -> str:
    body = "\n".join([cmd_id, str(ts), nonce, action, canonical(params)])
    return hmac.new(secret.encode("utf-8"), body.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def build_command(secret: str, action: str, params: dict,
                  cmd_id: str, ts: int, nonce: str) -> dict:
    """Build the encrypted wire envelope for a command."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action}")
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    if len(canonical(params).encode()) > MAX_PARAMS_BYTES:
        raise ValueError("params too large")
    sig = sign_command(secret, cmd_id, ts, nonce, action, params)
    inner = {"id": cmd_id, "ts": ts, "nonce": nonce, "action": action,
             "params": params, "sig": sig}
    return {"v": PROTOCOL_VERSION, "enc": encrypt(cmd_key(secret), canonical(inner).encode())}


def parse_envelope(env: dict) -> dict:
    if not isinstance(env, dict) or env.get("v") != PROTOCOL_VERSION or "enc" not in env:
        raise ValueError("not a v2 envelope")
    return env


def decrypt_command(secret: str, env: dict) -> dict:
    inner = json.loads(decrypt(cmd_key(secret), parse_envelope(env)["enc"]).decode("utf-8"))
    for field in ("id", "ts", "nonce", "action", "params", "sig"):
        if field not in inner:
            raise ValueError(f"command missing field: {field}")
    return inner


def verify_signature(secret: str, cmd: dict) -> bool:
    expected = sign_command(secret, cmd["id"], cmd["ts"], cmd["nonce"],
                            cmd["action"], cmd["params"])
    return hmac.compare_digest(expected, cmd["sig"])


def verify_command(secret: str, cmd: dict, nonce_store, now: int):
    """Full auth check. Returns (True, '') or (False, reason)."""
    if cmd.get("action") not in ACTIONS:
        return False, f"unknown action: {cmd.get('action')}"
    if not isinstance(cmd.get("params"), dict):
        return False, "params must be an object"
    if not verify_signature(secret, cmd):
        return False, "bad signature"
    ts = cmd.get("ts")
    if not isinstance(ts, int) or abs(now - ts) > CLOCK_SKEW_SECONDS:
        return False, "stale or skewed timestamp"
    nonce = cmd.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 16:
        return False, "bad nonce"
    if not nonce_store.add(nonce, ts):
        return False, "replayed nonce"
    return True, ""


def build_result(secret: str, cmd_id: str, action: str, ok: bool, result) -> list:
    """Build encrypted result envelope(s), chunked for ntfy limits."""
    inner = {"id": cmd_id, "action": action, "ts": 0, "ok": ok, "result": result}
    import time
    inner["ts"] = int(time.time())
    blob = encrypt(res_key(secret), canonical(inner).encode())
    chunks = [blob[i:i + CHUNK_CHARS] for i in range(0, len(blob), CHUNK_CHARS)] or [""]
    if len(chunks) == 1:
        return [{"v": PROTOCOL_VERSION, "enc": chunks[0]}]
    return [{"v": PROTOCOL_VERSION, "id": cmd_id, "seq": i, "of": len(chunks),
             "enc": c} for i, c in enumerate(chunks)]


def reassemble_result(secret: str, envelopes: list) -> dict:
    """Reassemble chunked (or single) result envelopes and decrypt."""
    if len(envelopes) == 1 and "seq" not in envelopes[0]:
        blob = parse_envelope(envelopes[0])["enc"]
    else:
        parts = sorted(envelopes, key=lambda e: e["seq"])
        if [p["seq"] for p in parts] != list(range(len(parts))):
            raise ValueError("missing result chunks")
        blob = "".join(p["enc"] for p in parts)
    return json.loads(decrypt(res_key(secret), blob).decode("utf-8"))


class NonceStore:
    """Persistent replay protection. Nonces are remembered for NONCE_TTL_SECONDS."""

    def __init__(self):
        self._seen = {}  # nonce -> ts

    def load(self, data: dict):
        if isinstance(data, dict):
            self._seen = {k: int(v) for k, v in data.items()
                          if isinstance(v, int)}

    def dump(self) -> dict:
        return dict(self._seen)

    def prune(self, now: int):
        cutoff = now - NONCE_TTL_SECONDS
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def add(self, nonce: str, ts: int) -> bool:
        """Return False if the nonce was already seen (replay)."""
        if nonce in self._seen:
            return False
        self._seen[nonce] = ts
        return True


def check_entity_id(value: str) -> str:
    if not isinstance(value, str) or not RE_ENTITY_ID.match(value):
        raise ValueError(f"invalid entity_id: {value!r}")
    return value


def check_domain(value: str) -> str:
    if not isinstance(value, str) or not RE_DOMAIN.match(value):
        raise ValueError(f"invalid domain: {value!r}")
    return value


def check_service(value: str) -> str:
    return check_domain(value)


def check_mac(value: str) -> str:
    if not isinstance(value, str) or not RE_MAC.match(value):
        raise ValueError(f"invalid MAC address: {value!r}")
    return value.lower().replace("-", ":")


def check_host(value: str) -> str:
    if not isinstance(value, str) or not RE_HOST.match(value) or len(value) > 253:
        raise ValueError(f"invalid host: {value!r}")
    return value


def check_port(value) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid port: {value!r}")
    return port
