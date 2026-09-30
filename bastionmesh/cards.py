"""Peer agent cards: fetch, scan, pin, rewrite.

    fetch (bastionsupply fetch_agent_card: bounded, no redirects)
      -> scan with supply's checks at their REAL severity (supply 0.10 caps
         A2A findings at medium in its own reports; mesh acts in warn by default)
      -> compare with the pin: `lock` = a bastionsupply lock file, `pin` = the
         first card fetched since start (memory), `off` = never compared
      -> rewrite for callers: every JSON-RPC interface points at the mesh, other
         bindings (REST, gRPC) and JWS signatures are dropped, so a caller that
         discovers a peer through the mesh cannot route around it

Refresh is lazy with a TTL. When a fetch fails the last verified state stands
(a flaky card endpoint must not take a working peer offline); only a `lock`
peer never verified since start is refused. Drift is sticky until restart:
re-pinning is regenerating the lock file (`bastionmesh check --lock`).
"""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, field

from bastionsupply import a2a as supply_a2a
from bastionsupply import checks as supply_checks
from bastionsupply import lockfile
from bastionsupply.fetch import fetch_agent_card

from .policy import BLOCK, MeshPolicy, Peer, PolicyError

CARD_TTL = 300.0
FETCH_TIMEOUT = 5.0
_SERIOUS = ("critical", "high")


def serious_findings(server) -> list:
    """Supply's card checks without its A2A severity cap, critical/high only."""
    found = [f for check in supply_checks.ALL_CHECKS for f in check(server)]
    found += supply_a2a.check_card(server)
    return [f for f in found if f.severity in _SERIOUS]


def rewrite(card: dict, mesh_url: str) -> tuple[dict, int]:
    """(card callers should see, number of interfaces dropped)."""
    out = copy.deepcopy(card)
    out.pop("signatures", None)  # a rewritten card no longer verifies; the mesh is the anchor now
    dropped = 0

    def jsonrpc_only(ifaces, key: str) -> list:
        nonlocal dropped
        kept = [dict(i, url=mesh_url) for i in ifaces
                if isinstance(i, dict) and str(i.get(key, "")).upper() == "JSONRPC"]
        dropped += len(ifaces) - len(kept)
        return kept

    if isinstance(out.get("supportedInterfaces"), list):  # v1.0
        out["supportedInterfaces"] = jsonrpc_only(out["supportedInterfaces"], "protocolBinding")
    if "url" in out or "additionalInterfaces" in out:  # v0.3
        out["url"] = mesh_url
        out["preferredTransport"] = "JSONRPC"
        if isinstance(out.get("additionalInterfaces"), list):
            out["additionalInterfaces"] = jsonrpc_only(out["additionalInterfaces"], "transport")
    return out, dropped


@dataclass
class CardState:
    pin: dict | None = None  # lockfile-shaped: {"card": {"sha256": ...}}
    verified: bool = False  # a fetched card was compared at least once since start
    drift: bool = False  # sticky
    findings: tuple = ()
    card: dict | None = None  # rewritten card from the last good fetch
    error: str | None = None
    fetched_at: float = float("-inf")
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class Cards:
    def __init__(self, policy: MeshPolicy, *, fetch=fetch_agent_card, clock=time.monotonic,
                 emit=lambda *a, **k: None, warn=lambda line: None) -> None:
        self.policy = policy
        self._fetch = fetch
        self._clock = clock
        self._emit = emit
        self._warn = warn
        self._states: dict[str, CardState] = {}
        for name, peer in policy.peers.items():
            state = CardState()
            if peer.card == "lock":
                try:
                    state.pin = lockfile.load_lock(peer.lock)
                except (OSError, ValueError) as e:
                    raise PolicyError(f"peer {name}: cannot read lock file {peer.lock} ({e}); "
                                      "create it with `bastionmesh check --lock`") from e
                if not isinstance(state.pin.get("card"), (dict, str)):
                    raise PolicyError(f"peer {name}: {peer.lock} has no agent-card pin")
            self._states[name] = state

    def mesh_url(self, name: str) -> str:
        return f"{self.policy.public_url}/peers/{name}/"

    def refresh(self, name: str, force: bool = False) -> CardState:
        """Re-fetch when the TTL passed (or `force`). Never raises."""
        state = self._states[name]
        if not force and self._clock() - state.fetched_at < CARD_TTL:
            return state
        # one fetch at a time per peer; others use the current state unless there is none yet
        if not state.lock.acquire(blocking=state.fetched_at == float("-inf")):
            return state
        try:
            if force or self._clock() - state.fetched_at >= CARD_TTL:
                self._update(self.policy.peers[name], state)
        finally:
            state.lock.release()
        return state

    def _update(self, peer: Peer, state: CardState) -> None:
        state.fetched_at = self._clock()
        try:
            server = self._fetch(peer.card_url, timeout=FETCH_TIMEOUT)
        except Exception as e:  # noqa: BLE001 - any fetch/parse failure keeps the last verified state
            reason = f"{type(e).__name__}: {e}"
            if state.error != reason:
                self._emit("card_unavailable", peer=peer.name, error=reason)
                self._warn(f"bastionmesh: WARN peer {peer.name}: agent card unavailable ({reason}); "
                           + ("using the last verified card" if state.verified else "not verified yet"))
            state.error = reason
            return
        state.error = None
        findings = tuple(serious_findings(server))
        if findings and findings != state.findings:
            self._emit("card_findings", peer=peer.name, checks=sorted({f.check for f in findings}),
                       action=self.policy.on_card_findings)
            self._warn(f"bastionmesh: WARN peer {peer.name}: agent card has {len(findings)} high/critical "
                       f"finding(s): {', '.join(sorted({f.check for f in findings}))}")
        state.findings = findings
        if peer.card != "off":
            if state.pin is None:
                state.pin = lockfile.make_lock(server)
                self._emit("card_pinned", peer=peer.name)
            elif lockfile.verify(server, state.pin).card_changed and not state.drift:
                state.drift = True
                self._emit("card_drift", peer=peer.name, action=self.policy.on_card_drift)
                self._warn(f"bastionmesh: WARN peer {peer.name}: agent card changed since it was pinned "
                           f"({'traffic blocked' if self.policy.on_card_drift == BLOCK else 'warn only'}); "
                           "re-pin with `bastionmesh check --lock` and restart")
            state.verified = True
        card, dropped = rewrite(server.card, self.mesh_url(peer.name))
        if dropped:
            self._emit("card_interfaces_dropped", peer=peer.name, count=dropped)
        state.card = card

    def gate(self, name: str) -> tuple[str, str] | None:
        """(reason, detail) when JSON-RPC traffic to the peer must be refused."""
        peer = self.policy.peers[name]
        if peer.card == "off" and self.policy.on_card_findings != BLOCK:
            return None
        state = self.refresh(name)
        if state.drift and self.policy.on_card_drift == BLOCK:
            return "card-drift", f"peer {name}'s agent card changed since it was pinned"
        if peer.card == "lock" and not state.verified:
            return "card-unverified", f"peer {name}'s agent card could not be verified against its lock file"
        if state.findings and self.policy.on_card_findings == BLOCK:
            return "card-findings", f"peer {name}'s agent card has high/critical findings"
        return None

    def card_for(self, name: str) -> tuple[int, dict | str]:
        """(HTTP status, rewritten card | error text) for the card route."""
        refused = self.gate(name)
        if refused:
            return 502, f"bastionmesh: {refused[1]}"
        state = self.refresh(name)
        if state.card is None:
            return 502, f"bastionmesh: agent card for peer {name} is unavailable ({state.error})"
        return 200, state.card
