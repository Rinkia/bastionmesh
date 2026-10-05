"""The mesh core: pure message logic, no sockets.

`open_call` decides whether a caller's JSON-RPC request may go to a peer and
what exactly is forwarded; `inspect_response` checks what the peer sends back;
`close_call` must run in a `finally`. The HTTP layer (http.py) is thin glue.

    request:  caller -> peer allowed -> method allowed -> card ok -> rate/in-flight
              -> depth + cycle -> push webhooks -> request scan -> relay -> secrets
    response: every text part (task, status, artifacts, history, stream events)
              -> full injection scan; flagged text is fingerprinted for relay

Scanning is split by direction. A delegation IS an instruction ("always include
sources"), so requests only get hidden-unicode and known-payload (bastioncorpus)
checks plus the relay check. A reply should be data, so replies get the full
set (the same scanner bastiongate runs on MCP tool results).

Delegation depth needs no cooperation from agents: while a request INTO peer P
is in flight, P's own outbound requests continue that chain. Attribution is
exact while an agent serves one request at a time; with several concurrent
inbound requests the shortest chain counts and a cycle needs the target in all
of them (never a false block). Ceiling: async send-then-poll chains end the
inbound request, so they are not depth-capped (TODOS.md).
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import unicodedata
import urllib.parse
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field

from bastiongate import pii
from bastiongate.flows import SECRET_KINDS
from bastiongate.guards import TRANSFORM_MAX_CHARS, scan_encoded_text, scan_result_text
from bastionsupply.checks import decoded_views
from bastionsupply.checks import check_hidden_unicode
from bastionsupply.corpus import poison_signatures
from bastionsupply.models import Server, Tool

from . import a2a
from .policy import BLOCK, REDACT, WARN, MeshPolicy

try:  # the matched span of a poisoning regex is the relay fingerprint for short payloads
    from bastionsupply.checks import _POISON as _POISON_RX
except ImportError:  # pragma: no cover - supply renamed it; shingles still work
    _POISON_RX = ()

SHINGLE = 32
RELAY_WINDOW = 256_000  # relay shingles cover each part's head and tail; see README limits
RELAY_TTL = 1800.0
MAX_RELAY_HASHES = 200_000
MAX_SNIPPETS = 512  # each is a substring search over the outbound text
MAX_SHINGLES_PER_TEXT = 4096
CARRY = 256  # chars of each streamed artifact kept to scan with the next chunk
MAX_CARRY_KEYS = 4096  # per stream: at most ~1 MB of carried text
MAX_TRACKED_CALLERS = 10_000
RATE_WINDOW = 60.0


_ASCII_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# every credential kind in bastiongate.flows.SECRET_KINDS starts with one of these;
# text without any cannot hold one, so the (slower) full PII scrub is skipped
_SECRET_HINT = re.compile(r"-----BEGIN|AKIA|ASIA|sk-|AIza|gh[pousr]_|xox[baprs]-|eyJ")


def fold(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).lower().strip()


def _stderr_warn(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _hash(s: str) -> int:
    return hash(s)  # in-memory only, so the per-process salt is fine (and fast)


def request_scan(text: str, views=None) -> str | None:
    """Delegation-safe checks: hidden unicode, known payloads. Returns a reason or None."""
    # ASCII without control characters cannot hide anything: skip the per-char walk
    suspicious = not text.isascii() or _ASCII_CONTROL.search(text)
    if suspicious and check_hidden_unicode(Server("request", (Tool(name="_", description=text),))):
        return "hidden/control unicode"
    low = fold(text)
    if any(phrase in low for _cat, phrase in poison_signatures()):
        return "a known prompt-injection payload (bastioncorpus)"
    for d in (decoded_views(text) if views is None else views):  # known payloads, hidden in base64/hex/...
        low = fold(d.text)
        if any(phrase in low for _cat, phrase in poison_signatures()):
            return f"a known prompt-injection payload hidden in {d.encoding} encoding"
    return None


_TRANSFORMS = frozenset({"rot13", "reversed", "leet", "spaced"})


def reply_views(text: str, transforms: bool) -> tuple[list, list]:
    """(run-based views, all views to scan). One decode; with `transforms` (replies up to
    TRANSFORM_MAX_CHARS) the scan also sees the whole-text rewrites, while the relay
    store keeps run-based views only (its hash budget is split across views)."""
    views = decoded_views(text, transforms=transforms and len(text) <= TRANSFORM_MAX_CHARS)
    return [d for d in views if d.encoding not in _TRANSFORMS], views


def response_scan(text: str, views=None) -> tuple[str | None, list[str]]:
    """(reason or None, matched poisoning spans) with the full signature set."""
    decision = scan_result_text(text)
    if decision.allowed:
        views = decoded_views(text) if views is None else views  # decoded once, reused
        decision = scan_encoded_text(text, views)  # base64/hex/binary/... decoded, same signatures
        if decision.allowed:
            return None, []
        spans = [m.group(0) for d in views for rx in _POISON_RX if (m := rx.search(d.text))]
        return decision.reason.removeprefix("tool result "), spans
    spans = [m.group(0) for rx in _POISON_RX if (m := rx.search(text))]
    return decision.reason.removeprefix("tool result "), spans  # gate words it for MCP


class RelayStore:
    """Fingerprints of flagged text: 32-char shingles plus matched poisoning spans,
    bounded (LRU) with a TTL. A later outbound part that contains one is a relay."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._hashes: OrderedDict[int, tuple[str, int | None, float]] = OrderedDict()
        self._snippets: OrderedDict[str, tuple[str, int | None, float]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _shingles(folded: str, limit: int | None) -> list[int]:
        if len(folded) < SHINGLE:
            return [_hash(folded)] if folded else []
        n = len(folded) - SHINGLE + 1
        step = max(1, n // limit) if limit else 1
        return [_hash(folded[i:i + SHINGLE]) for i in range(0, n, step)]

    @staticmethod
    def _window(text: str) -> str:
        if len(text) <= 2 * RELAY_WINDOW:
            return text
        return text[:RELAY_WINDOW] + " " + text[-RELAY_WINDOW:]

    def add(self, text: str, origin: str, seq: int | None, spans=(), views=None) -> None:
        now = self._clock()
        entry = (origin, seq, now)
        texts = [text] + [d.text for d in (decoded_views(text) if views is None else views)]
        # one add() never inserts more than ~MAX_SHINGLES_PER_TEXT hashes in total (the
        # decoded views share the budget), so a single big reply cannot flush the store
        each = max(1, MAX_SHINGLES_PER_TEXT // len(texts))
        hashes = [h for t in texts for h in self._shingles(fold(self._window(t)), each)]
        with self._lock:
            for h in hashes:
                self._hashes[h] = entry
                self._hashes.move_to_end(h)
            for span in spans:
                s = fold(span)
                if s:
                    self._snippets[s] = entry
                    self._snippets.move_to_end(s)
            while len(self._hashes) > MAX_RELAY_HASHES:
                self._hashes.popitem(last=False)
            while len(self._snippets) > MAX_SNIPPETS:
                self._snippets.popitem(last=False)

    def match(self, text: str, views=None) -> tuple[str, int | None] | None:
        """(origin, origin seq) of the flagged text this one copies, else None."""
        if not self._hashes and not self._snippets:
            return None
        cutoff = self._clock() - RELAY_TTL
        with self._lock:
            snippets = [(s, e) for s, e in self._snippets.items() if e[2] >= cutoff]
        folded = fold(text)  # hashing and substring search run outside the lock
        for s, (origin, seq, _ts) in snippets:
            if s in folded:
                return origin, seq
        decoded = decoded_views(text) if views is None else views
        windows = [fold(self._window(t)) for t in [text] + [d.text for d in decoded]]
        hashes = [h for w in windows if len(w) >= SHINGLE for h in self._shingles(w, None)]
        if not hashes:
            return None
        with self._lock:
            for h in hashes:
                hit = self._hashes.get(h)
                if hit and hit[2] >= cutoff:
                    return hit[0], hit[1]
        return None


def webhook_allowed(url: str, allowed: tuple[str, ...]) -> bool:
    """Exact scheme + host + port, path prefix on a segment boundary, no userinfo."""
    try:
        u = urllib.parse.urlparse(url)
        port = u.port
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        return False
    path = urllib.parse.unquote(u.path)
    if "/../" in f"{path}/" or "/./" in f"{path}/":
        return False
    default = {"http": 80, "https": 443}[u.scheme]
    for entry in allowed:
        a = urllib.parse.urlparse(entry)
        if (a.scheme, (a.hostname or "").lower(), a.port or {"http": 80, "https": 443}[a.scheme]) != (
                u.scheme, u.hostname.lower(), port or default):
            continue
        prefix = a.path.rstrip("/")
        if not prefix or path == prefix or path.startswith(prefix + "/"):
            return True
    return False


class ContentTrace:
    """Opt-in bastiontrace v3 trace: every forwarded message as an `agent_message`
    (the caller's delegation, the peer's reply), with provenance edges."""

    def __init__(self, path) -> None:
        self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 - closed by close()
        self._seq = 0
        self._lock = threading.Lock()
        self._write({"type": "trace", "v": 3, "trace_id": f"bastionmesh-{int(time.time())}",
                     "source": "bastionmesh"})

    def _write(self, row: dict) -> None:
        self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._fh.flush()

    def message(self, from_agent: str, to_agent: str, kind: str, content: str, derived_from=()) -> int:
        with self._lock:
            seq = self._seq
            self._seq += 1
            row = {"type": "agent_message", "seq": seq, "from_agent": from_agent, "to_agent": to_agent,
                   "kind": kind, "content": content}
            edges = sorted({d for d in derived_from if d is not None and d < seq})
            if edges:
                row["derived_from"] = edges
            self._write(row)
            return seq

    def close(self) -> None:
        with self._lock:
            self._fh.close()


@dataclass(eq=False)
class Call:
    """One forwarded request, open until close_call."""

    mid: object
    caller: str
    peer: str
    op: str
    chain: tuple[str, ...]
    forward: dict
    seq: int | None = None
    carry: dict = field(default_factory=dict)
    flagged: bool = False
    released: bool = False
    sent: frozenset = frozenset()  # the caller's own part texts; a task's history echoes them


class Mesh:
    def __init__(self, policy: MeshPolicy, cards=None, *, emit=None, warn=_stderr_warn,
                 clock=time.monotonic, content: ContentTrace | None = None) -> None:
        self.policy = policy
        self.cards = cards
        self._emit_fn = emit or (lambda event, **fields: None)
        self._warn = warn
        self._clock = clock
        self.content = content
        self.relays = RelayStore(clock)
        self._lock = threading.RLock()  # refusals bump metrics while holding it
        self._rate: OrderedDict[str, deque] = OrderedDict()
        self._inflight: Counter = Counter()
        self._into: dict[str, list[Call]] = {}
        self._metrics: Counter = Counter()

    # --- bookkeeping ----------------------------------------------------------
    def _emit(self, event: str, **fields) -> None:
        self._emit_fn(event, **fields)

    def _bump(self, name: str) -> None:
        with self._lock:
            self._metrics[name] += 1

    def metrics(self) -> dict:
        with self._lock:
            m = dict(self._metrics)
            m["inflight"] = sum(self._inflight.values())
        return m

    def _refuse(self, mid, reason: str, detail: str, **fields) -> tuple[None, dict]:
        self._emit("blocked", reason=reason, detail=detail, **fields)
        self._bump(f"blocked_{reason}")
        return None, a2a.block_error(mid, reason, detail)

    def _flag(self, action: str, reason: str, detail: str, mid, **fields) -> dict | None:
        """Warn (and continue) or block, per a detector's action."""
        if action == BLOCK:
            return self._refuse(mid, reason, detail, **fields)[1]
        self._emit("warned", reason=reason, detail=detail, **fields)
        self._bump(f"warned_{reason}")
        self._warn(f"bastionmesh: WARN {reason}: {detail}")
        return None

    # --- caller -> peer -------------------------------------------------------
    def open_call(self, caller: str, peer: str, msg: dict) -> tuple[Call | None, dict | None]:
        """(call to forward, None) or (None, JSON-RPC error reply). `caller` is the
        caller's policy name, or `ip:<addr>` in open mode."""
        mid = msg.get("id")
        where = {"caller": caller, "peer": peer, "id": mid}
        named = self.policy.callers.get(caller)
        if named is not None and peer not in named.peers:
            return self._refuse(mid, "caller-denied", f"caller {caller} may not call peer {peer}", **where)
        op = a2a.op_of(msg.get("method"))
        if op is None or op not in self.policy.peers[peer].methods:
            return self._refuse(mid, "method-denied",
                                f"method {msg.get('method')!r} is not allowed for peer {peer}", **where)
        malformed = a2a.bad_shape(msg)
        if malformed:
            return self._refuse(mid, "malformed", f"request refused: {malformed}", **where)
        if self.cards is not None:
            refused = self.cards.gate(peer)
            if refused:
                return self._refuse(mid, *refused, **where)
        params = msg.get("params")
        with self._lock:
            limited = self._rate_limited(caller)
            if limited:
                return self._refuse(mid, "rate-limited", limited, **where)
            chain, why = self._chain(caller, peer)
            if why:
                return self._refuse(mid, "depth-exceeded", why, chain=list(chain), **where)
            # reserve the slot and register the chain in the same lock hold, so neither
            # concurrent requests (cap) nor concurrent A->B / B->A (cycle) can slip past
            call = Call(mid=mid, caller=caller, peer=peer, op=op, chain=chain, forward=msg)
            self._inflight[caller] += 1
            self._into.setdefault(peer, []).append(call)
        try:
            reply = self._check_request(call, op, params)
            if reply is None:
                self._emit("forward", op=op, depth=len(chain) - 1, **where)
                self._bump("forwarded")
        except BaseException:
            self._release(call)
            raise
        if reply is not None:
            self._release(call)
            return None, reply
        return call, None

    def _rate_limited(self, caller: str) -> str | None:
        now = self._clock()
        window = self._rate.get(caller)
        if window is None:
            window = self._rate[caller] = deque()
            while len(self._rate) > MAX_TRACKED_CALLERS:
                self._rate.popitem(last=False)
        self._rate.move_to_end(caller)
        while window and window[0] <= now - RATE_WINDOW:
            window.popleft()
        if len(window) >= self.policy.max_requests_per_minute:
            return f"caller {caller} exceeded {self.policy.max_requests_per_minute} requests per minute"
        if self._inflight[caller] >= self.policy.max_inflight_per_caller:
            return f"caller {caller} has {self.policy.max_inflight_per_caller} requests in flight"
        window.append(now)
        return None

    def _chain(self, caller: str, peer: str) -> tuple[tuple[str, ...], str | None]:
        if peer == caller:
            return (caller, peer), f"delegation cycle: {caller} -> {peer} (an agent calling itself)"
        parents = [c.chain for c in self._into.get(caller, ())]
        if not parents:
            parent = (caller,)
        else:
            if all(peer in p for p in parents):
                p = min(parents, key=len)
                return p + (peer,), f"delegation cycle: {' -> '.join(p + (peer,))}"
            parent = min(parents, key=len)
        chain = parent + (peer,)
        if len(chain) - 1 > self.policy.max_depth:
            return chain, f"delegation depth {len(chain) - 1} exceeds max_depth {self.policy.max_depth}"
        return chain, None

    def _parent_seqs(self, caller: str) -> list[int]:
        with self._lock:
            return [c.seq for c in self._into.get(caller, ()) if c.seq is not None]

    def _check_request(self, call: Call, op: str, params) -> dict | None:
        mid, where = call.mid, {"caller": call.caller, "peer": call.peer, "id": call.mid}
        peer = self.policy.peers[call.peer]
        for url in a2a.push_urls(op, params):
            if not webhook_allowed(url, peer.push_webhooks):
                host = urllib.parse.urlparse(url).hostname if isinstance(url, str) else None
                return self._refuse(mid, "push-webhook-denied",
                                    f"push-notification webhook host {host!r} is not in "
                                    f"peers.{call.peer}.push_webhooks", **where)[1]
        pieces = a2a.request_pieces(params)
        size = sum(len(p.text) for p in pieces)
        if size > self.policy.max_message_chars:
            return self._refuse(mid, "oversize", f"message text is {size} characters; the mesh scans at most "
                                f"{self.policy.max_message_chars} (limits.max_message_chars)", **where)[1]
        call.sent = frozenset(p.text for p in pieces)
        joined = len(pieces) > 1
        if joined:  # a payload split across parts is whole again once joined
            pieces = pieces + [a2a.Piece("\n".join(p.text for p in pieces))]
        relay_origin = None
        for i, piece in enumerate(pieces):
            last_joined = joined and i == len(pieces) - 1
            views = decoded_views(piece.text)  # decoded once per piece: scan, add and match share it
            why = request_scan(piece.text, views)
            if why and not (last_joined and call.flagged):
                call.flagged = True
                self.relays.add(piece.text, origin=call.caller, seq=None, views=views)
                reply = self._flag(self.policy.on_injection, "injection",
                                   f"message to peer {call.peer} carries {why}", mid, direction="request", **where)
                if reply:
                    return reply
            hit = None if (last_joined and relay_origin) else self.relays.match(piece.text, views)
            if hit and hit[0] != call.caller:  # passing on someone else's flagged text
                relay_origin = hit
                reply = self._flag(self.policy.on_relay, "relay",
                                   f"{call.caller} is forwarding content flagged in a reply from {hit[0]} "
                                   f"to peer {call.peer}", mid, origin=hit[0], **where)
                if reply:
                    return reply
        call.forward = self._secrets(call, params, op)
        if call.forward is None:
            return self._refuse(mid, "secret", f"message to peer {call.peer} carries a credential", **where)[1]
        if self.content is not None and op in ("send", "stream"):
            text = "\n".join(p.text for p in a2a.request_pieces((call.forward.get("params"))))
            derived = self._parent_seqs(call.caller) + ([relay_origin[1]] if relay_origin else [])
            call.seq = self.content.message(call.caller, call.peer, "delegate", text, derived)
        return None

    def _secrets(self, call: Call, params, op: str) -> dict | None:
        """Forwarded message with credentials handled per on_secret_out; None = block.
        Every string in the params is checked (parts, data, metadata); only strings
        that hold a credential are rewritten."""
        msg = call.forward
        if not isinstance(params, dict):
            return msg
        kinds: set[str] = set()
        new_params = _scrub_secrets(params, kinds, in_push=op == "push-set")
        if not kinds:
            return msg
        action = self.policy.on_secret_out
        where = {"caller": call.caller, "peer": call.peer, "id": call.mid, "kinds": sorted(kinds)}
        if action == BLOCK:
            return None
        if action == WARN:
            self._flag(WARN, "secret", f"message to peer {call.peer} carries a credential", call.mid, **where)
            return msg
        assert action == REDACT
        self._emit("secret_redacted", **where)
        self._bump("secret_redacted")
        return {**msg, "params": new_params}

    # --- peer -> caller -------------------------------------------------------
    def inspect_response(self, call: Call, msg) -> dict:
        """The message to send the caller: `msg`, or a block error in its place."""
        if not isinstance(msg, dict):
            return msg
        where = {"caller": call.caller, "peer": call.peer, "id": call.mid}
        malformed = a2a.bad_shape(msg)
        if malformed:  # a lenient client would read what the mesh cannot scan: always refused
            return self._refuse(msg.get("id"), "malformed", f"reply from peer {call.peer} refused: "
                                f"{malformed}", **where)[1]
        streaming = a2a.is_streaming(call.op)
        # the caller's own words echoed back (task history) were scanned on the way out
        # with the delegation-safe checks; the full reply set would flag every delegation
        pieces = [p for p in a2a.response_pieces(msg) if p.text not in call.sent]
        size = sum(len(p.text) for p in pieces)
        if size > self.policy.max_message_chars:  # fail closed: never forward what was not scanned
            return self._refuse(msg.get("id"), "oversize", f"reply from peer {call.peer} has {size} characters "
                                f"of text; the mesh scans at most {self.policy.max_message_chars}", **where)[1]
        joined = len(pieces) > 1
        if joined:  # a payload split across parts is whole again once joined
            pieces = pieces + [a2a.Piece("\n".join(p.text for p in pieces))]
        texts, flagged_here = [], False
        for i, piece in enumerate(pieces):
            last_joined = joined and i == len(pieces) - 1
            text = piece.text
            if streaming and not last_joined:
                key = piece.key or ""  # "" = status/message text of the stream
                text = call.carry.pop(key, "") + text
                call.carry[key] = text[-CARRY:]  # newest last; the oldest is evicted
                while len(call.carry) > MAX_CARRY_KEYS:
                    call.carry.pop(next(iter(call.carry)))
            if not last_joined:
                texts.append(piece.text)
            views, scan_views = reply_views(text, self.policy.decode_transforms)
            why, spans = response_scan(text, scan_views)
            if why and not (last_joined and flagged_here):
                flagged_here = True
                call.flagged = True
                seq = self._record_reply(call, texts)
                texts = []
                self.relays.add(text, origin=call.peer, seq=seq, spans=spans, views=views)
                reply = self._flag(self.policy.on_injection, "injection",
                                   f"reply from peer {call.peer} {why}", msg.get("id"), direction="response",
                                   **where)
                if reply:
                    return reply
        self._record_reply(call, texts)
        if a2a.binary_parts(msg):
            self._emit("binary_parts_unscanned", count=a2a.binary_parts(msg), **where)
        return msg

    def _record_reply(self, call: Call, texts: list[str]) -> int | None:
        if self.content is None or not texts:
            return None
        return self.content.message(call.peer, call.caller, "reply", "\n".join(texts), [call.seq])

    def close_call(self, call: Call) -> None:
        self._release(call)

    def _release(self, call: Call) -> None:
        with self._lock:
            if call.released:
                return
            call.released = True
            self._inflight[call.caller] -= 1
            if self._inflight[call.caller] <= 0:
                del self._inflight[call.caller]
            active = self._into.get(call.peer, [])
            if call in active:
                active.remove(call)
            if not active:
                self._into.pop(call.peer, None)


_PUSH_AUTH_KEYS = frozenset({"token", "authentication", "credentials"})


def _scrub_secrets(obj, kinds: set, depth: int = 0, in_push: bool = False):
    """Copy of `obj` with every string that holds a credential redacted (all PII in
    that string, per bastiongate.pii); `kinds` collects the credential kinds.
    A push-notification config's own `token` / `authentication` are the webhook's
    credentials, meant for that (allow-listed) webhook: they pass untouched."""
    if depth > 64:
        return obj
    if isinstance(obj, str):
        if not _SECRET_HINT.search(obj):
            return obj
        red, found = pii.scrub_text(obj)
        secret = set(found) & SECRET_KINDS
        if not secret:
            return obj
        kinds |= secret
        return red
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            push = in_push or (isinstance(k, str) and "push" in k.lower())
            out[k] = v if push and k in _PUSH_AUTH_KEYS else _scrub_secrets(v, kinds, depth + 1, push)
        return out
    if isinstance(obj, list):
        return [_scrub_secrets(v, kinds, depth + 1, in_push) for v in obj]
    return obj
