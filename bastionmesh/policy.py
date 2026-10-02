"""Mesh policy: peers, callers, limits and detector actions, from YAML.

Strict on purpose: an unknown key, a bad value or a missing caller key is an
error, never ignored (a typo like `on_injeciton: block` must not silently leave
a detector in warn). Operator-authored rules enforce; heuristic detectors ship
as warn (shadow) until dogfood numbers promote them.

    peers:     name -> url (+ card mode, methods, push webhooks)
    callers:   name -> key (from an env var) + the peers it may call
               none at all = open mode, loopback listen only
"""

from __future__ import annotations

import ipaddress
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .a2a import ALL_OPS, DEFAULT_OPS

WARN, BLOCK, REDACT = "warn", "block", "redact"
CARD_MODES = ("pin", "lock", "off")

_ACTIONS = {
    "on_injection": ((WARN, BLOCK), WARN),
    "on_relay": ((WARN, BLOCK), WARN),
    "on_card_drift": ((WARN, BLOCK), BLOCK),
    "on_card_findings": ((WARN, BLOCK), WARN),
    "on_secret_out": ((REDACT, BLOCK, WARN), REDACT),
    # opt-in: also scan replies' rot13 / leet / reversed / spaced views (replies <= 64 KB)
    "decode_transforms": ((False, True), False),
}
_LIMITS = {"max_depth": 4, "max_inflight_per_caller": 16, "max_requests_per_minute": 120,
           "max_message_chars": 1_000_000}
_TOP = {"policy_version", "listen", "public_url", "peers", "callers", "limits", "actions"}
_PEER_KEYS = {"url", "card_url", "card", "lock", "methods", "push_webhooks"}
_CALLER_KEYS = {"key_env", "peers"}


class PolicyError(ValueError):
    """A policy that must not load."""


@dataclass(frozen=True)
class Peer:
    name: str
    url: str
    card_url: str
    card: str = "pin"
    lock: str | None = None
    methods: frozenset[str] = DEFAULT_OPS
    push_webhooks: tuple[str, ...] = ()


@dataclass(frozen=True)
class Caller:
    name: str
    key: str = field(repr=False)
    peers: frozenset[str] = frozenset()


@dataclass(frozen=True)
class MeshPolicy:
    peers: dict[str, Peer]
    callers: dict[str, Caller] = field(default_factory=dict)  # empty = open mode
    host: str = "127.0.0.1"
    port: int = 9100
    public_url: str = ""
    max_depth: int = 4
    max_inflight_per_caller: int = 16
    max_requests_per_minute: int = 120
    max_message_chars: int = 1_000_000  # text per message; above it: refused, never truncated
    on_injection: str = WARN
    on_relay: str = WARN
    decode_transforms: bool = False
    on_card_drift: str = BLOCK
    on_card_findings: str = WARN
    on_secret_out: str = REDACT

    @property
    def open_mode(self) -> bool:
        return not self.callers

    def caller_for_key(self, key: str) -> Caller | None:
        import hmac

        for c in self.callers.values():
            if hmac.compare_digest(c.key.encode(), key.encode()):
                return c
        return None


def load_policy(path: str | Path, env=None) -> MeshPolicy:
    try:
        obj = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise PolicyError(f"cannot read policy {path}: {e.strerror or e}") from e
    except yaml.YAMLError as e:
        raise PolicyError(f"{path} is not valid YAML: {e}") from e
    return from_dict(obj, env=env, base=Path(path).parent)


def from_dict(obj, env=None, base: Path | None = None) -> MeshPolicy:
    env = os.environ if env is None else env
    if not isinstance(obj, dict):
        raise PolicyError("policy file must be a mapping")
    _no_unknown(obj, _TOP, "top level")
    if obj.get("policy_version", 1) != 1:
        raise PolicyError(f"unsupported policy_version {obj['policy_version']!r}; this bastionmesh reads 1")
    host, port = _listen(obj.get("listen", "127.0.0.1:9100"))
    public_url = obj.get("public_url") or f"http://{_host_for_url(host)}:{port}"
    _http_url(public_url, "public_url")

    peers = _peers(obj.get("peers"), base)
    callers = _callers(obj.get("callers"), env, peers)
    limits = _section(obj.get("limits"), "limits", _LIMITS.keys())
    actions = _section(obj.get("actions"), "actions", _ACTIONS.keys())
    for k, v in limits.items():
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise PolicyError(f"`limits.{k}` must be a positive integer, got {v!r}")
    for k, v in actions.items():
        choices = _ACTIONS[k][0]
        if v not in choices or isinstance(v, bool) != isinstance(choices[0], bool):  # 1 == True
            raise PolicyError(f"`actions.{k}`: {v!r} is not one of {' | '.join(str(c).lower() for c in choices)}")

    policy = MeshPolicy(peers=peers, callers=callers, host=host, port=port,
                        public_url=public_url.rstrip("/"), **limits, **actions)
    check_listen(policy.host, policy.open_mode)
    return policy


def check_listen(host: str, open_mode: bool) -> None:
    """Open mode (no callers) only on a loopback address: anyone who can reach the
    port may call every peer."""
    if open_mode and not _is_loopback(host):
        raise PolicyError(
            f"no `callers:` (open mode) while listening on {host}: anyone who can reach it could "
            "call every peer. Add callers with keys, or listen on 127.0.0.1")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_for_url(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _no_unknown(obj: dict, allowed, where: str) -> None:
    unknown = set(obj) - set(allowed)
    if unknown:
        raise PolicyError(f"unknown key(s) in {where}: {sorted(map(str, unknown))}; allowed: {sorted(allowed)}")


def _section(raw, name: str, allowed) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"`{name}:` must be a mapping")
    _no_unknown(raw, allowed, f"`{name}:`")
    return dict(raw)


def _listen(raw) -> tuple[str, int]:
    text = str(raw)
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise PolicyError(f"`listen:` must be host:port, got {raw!r}")
    return host.strip("[]") or "127.0.0.1", int(port)


def _http_url(url, where: str) -> str:
    if not isinstance(url, str):
        raise PolicyError(f"`{where}` must be a URL string")
    try:
        parsed = urllib.parse.urlparse(url)
        parsed.port  # noqa: B018 - raises on a malformed port
    except ValueError as e:
        raise PolicyError(f"`{where}`: not a valid URL {url!r} ({e})") from e
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise PolicyError(f"`{where}` must be an absolute http(s) URL, got {url!r}")
    return url


def _peers(raw, base: Path | None) -> dict[str, Peer]:
    if not isinstance(raw, dict) or not raw:
        raise PolicyError("`peers:` must map at least one peer name to its settings")
    peers = {}
    for name, cfg in raw.items():
        where = f"peers.{name}"
        if not isinstance(name, str) or not name or "/" in name:
            raise PolicyError(f"peer name {name!r} must be a non-empty string without '/'")
        if not isinstance(cfg, dict):
            raise PolicyError(f"`{where}` must be a mapping with at least `url:`")
        _no_unknown(cfg, _PEER_KEYS, f"`{where}`")
        url = _http_url(cfg.get("url"), f"{where}.url")
        parsed = urllib.parse.urlparse(url)
        card_url = _http_url(cfg.get("card_url") or f"{parsed.scheme}://{parsed.netloc}", f"{where}.card_url")
        card = cfg.get("card", "pin")
        if card not in CARD_MODES:
            raise PolicyError(f"`{where}.card`: {card!r} is not one of {' | '.join(CARD_MODES)}")
        lock = cfg.get("lock")
        if card == "lock":
            if not isinstance(lock, str) or not lock:
                raise PolicyError(f"`{where}.card: lock` needs `lock:` (a file from `bastionmesh check --lock`)")
            lock = str((base or Path(".")) / lock)
        elif lock is not None:
            raise PolicyError(f"`{where}.lock` is only read with `card: lock`")
        methods = cfg.get("methods", sorted(DEFAULT_OPS))
        if not isinstance(methods, list) or not all(m in ALL_OPS for m in methods):
            raise PolicyError(f"`{where}.methods` must be a list drawn from {' | '.join(sorted(ALL_OPS))}")
        hooks = cfg.get("push_webhooks", [])
        if not isinstance(hooks, list):
            raise PolicyError(f"`{where}.push_webhooks` must be a list of URLs")
        for h in hooks:
            _webhook_entry(h, f"{where}.push_webhooks")
        peers[name] = Peer(name=name, url=url, card_url=card_url, card=card, lock=lock,
                           methods=frozenset(methods), push_webhooks=tuple(hooks))
    return peers


def _webhook_entry(url, where: str) -> None:
    _http_url(url, where)
    parsed = urllib.parse.urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PolicyError(f"`{where}`: {url!r} must be scheme://host[:port]/path, no userinfo, query or fragment")


def _callers(raw, env, peers: dict) -> dict[str, Caller]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError("`callers:` must map caller names to {key_env, peers}")
    callers, keys = {}, set()
    for name, cfg in raw.items():
        where = f"callers.{name}"
        if not isinstance(name, str) or not name:
            raise PolicyError(f"caller name {name!r} must be a non-empty string")
        if not isinstance(cfg, dict):
            raise PolicyError(f"`{where}` must be a mapping with `key_env:`")
        _no_unknown(cfg, _CALLER_KEYS, f"`{where}`")
        var = cfg.get("key_env")
        if not isinstance(var, str) or not var:
            raise PolicyError(f"`{where}.key_env` must name an environment variable holding the key")
        key = env.get(var, "")
        if len(key) < 16:
            raise PolicyError(f"`{where}`: environment variable {var} is unset or shorter than 16 characters")
        if key in keys:
            raise PolicyError(f"`{where}`: key in {var} is shared with another caller; each caller needs its own")
        keys.add(key)
        allowed = cfg.get("peers", [])
        if not isinstance(allowed, list) or not all(isinstance(p, str) for p in allowed):
            raise PolicyError(f"`{where}.peers` must be a list of peer names")
        unknown = sorted(set(allowed) - set(peers))
        if unknown:
            raise PolicyError(f"`{where}.peers` names unknown peer(s) {unknown}")
        callers[name] = Caller(name=name, key=key, peers=frozenset(allowed))
    return callers
