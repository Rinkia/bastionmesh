"""HTTP front of the mesh: routes, auth, JSON and SSE relay.

    GET  /peers/<p>/.well-known/agent-card.json   scanned, pinned, rewritten card
    GET  /peers/<p>/.well-known/agent.json        (legacy path, same card)
    POST /peers/<p>/                              A2A JSON-RPC to peer p
    GET  /__bastionmesh/metrics                   counters (auth'd like everything else)

Posture (same as bastiongate's HTTP proxy): binds 127.0.0.1 unless told
otherwise; the upstream URL comes from the policy, never from the client (no
SSRF); redirects are never followed; bodies are capped; only a safelist of
headers is forwarded, and the mesh's own key header never is.

Streams are relayed event by event. Each event's JSON-RPC payload goes through
`Mesh.inspect_response`; a blocked event is replaced by the block error and the
stream is closed (the peer's remaining output never reaches the caller).
"""

from __future__ import annotations

import hmac
import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .mesh import Mesh

MAX_BODY = 10 * 1024 * 1024  # request bodies, JSON responses, and each stream in total
MAX_LINE = 1024 * 1024
MAX_EVENT_LINES = 10_000
MAX_TRACKED_IPS = 10_000
DRAIN_ON_REFUSAL = 64 * 1024
HANDLER_TIMEOUT = 60.0  # socket timeout: an idle client cannot hold a thread forever
UPSTREAM_TIMEOUT = 120.0
AUTH_HEADER = "X-Bastionmesh-Key"
AUTH_MAX_FAILS = 10
AUTH_WINDOW = 60.0
METRICS_PATH = "/__bastionmesh/metrics"
_CARD_PATHS = ("/.well-known/agent-card.json", "/.well-known/agent.json")
_FWD_REQ_HEADERS = {"content-type", "accept", "authorization", "a2a-version", "a2a-extensions", "last-event-id"}
_FWD_RESP_HEADERS = {"a2a-version", "a2a-extensions"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPHandler, urllib.request.HTTPSHandler)


class StreamLimit(Exception):
    """An upstream stream broke a size bound; the mesh closes it."""


_SSE_EOL = re.compile(r"\r\n|\r|\n")


def iter_sse(resp):
    """Yield (other_lines, data) per SSE event; data is the joined `data:` lines or None.

    Line ends are CRLF, LF or a lone CR (all three per the SSE spec: a client that
    honours a lone CR must not see a `data:` line the mesh never parsed). Every
    byte counts toward MAX_BODY; a line longer than MAX_LINE or an event with more
    than MAX_EVENT_LINES lines raises StreamLimit."""
    lines: list[str] = []
    total, pending = 0, ""
    raws = iter(lambda: resp.readline(MAX_LINE + 1), b"") if hasattr(resp, "readline") else iter(resp)
    for raw in raws:
        total += len(raw)
        if total > MAX_BODY or len(raw) > MAX_LINE:
            raise StreamLimit("upstream stream exceeds the mesh's size bounds")
        pieces = _SSE_EOL.split(pending + raw.decode("utf-8", errors="replace"))
        pending = pieces.pop()  # text after the last line end, carried into the next read
        for line in pieces:
            if line:
                lines.append(line)
                if len(lines) > MAX_EVENT_LINES:
                    raise StreamLimit("upstream event has too many lines")
                continue
            if lines:
                yield _split(lines)
                lines = []
        if len(pending) > MAX_LINE:
            raise StreamLimit("upstream stream exceeds the mesh's size bounds")
    if pending:
        lines.append(pending)
    if lines:
        yield _split(lines)


def _split(lines: list[str]) -> tuple[list[str], str | None]:
    other, data = [], []
    for line in lines:
        if line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        else:
            other.append(line)  # event:, id:, retry:, comments
    return other, ("\n".join(data) if data else None)


def sse_event(other: list[str], data: str | None) -> bytes:
    out = list(other)
    if data is not None:
        out += [f"data: {chunk}" for chunk in data.split("\n")]
    return ("\n".join(out) + "\n\n").encode("utf-8")


def _route(path: str) -> tuple[str | None, str]:
    """(peer name, rest) for /peers/<p>/<rest>; (None, path) otherwise."""
    path = path.split("?", 1)[0]
    if not path.startswith("/peers/"):
        return None, path
    name, _, rest = path[len("/peers/"):].partition("/")
    return name or None, "/" + rest


def make_handler(mesh: Mesh, emit=lambda *a, **k: None):
    policy = mesh.policy
    fails: dict[str, deque] = {}
    fails_lock = threading.Lock()

    def throttled(ip: str) -> bool:
        now = time.monotonic()
        with fails_lock:
            dq = fails.setdefault(ip, deque())
            while dq and dq[0] < now - AUTH_WINDOW:
                dq.popleft()
            if not dq:
                fails.pop(ip, None)
            return len(dq) >= AUTH_MAX_FAILS

    def record_fail(ip: str) -> None:
        with fails_lock:
            if ip not in fails and len(fails) >= MAX_TRACKED_IPS:
                fails.pop(next(iter(fails)))  # oldest-inserted first: bounded memory
            fails.setdefault(ip, deque()).append(time.monotonic())

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bastionmesh"
        timeout = HANDLER_TIMEOUT

        def log_message(self, *a):
            pass

        # --- auth -------------------------------------------------------------
        def _caller(self, pending: int = 0) -> str | None:
            """Caller identity, or None after sending 401/429. On refusal at most
            DRAIN_ON_REFUSAL pending body bytes are drained (a small client then sees
            the status, not a reset); a big unauthenticated body is never read."""
            ip = self.client_address[0]
            if policy.open_mode:
                return f"ip:{ip}"
            if 0 < pending <= DRAIN_ON_REFUSAL and (
                    throttled(ip) or policy.caller_for_key(self.headers.get(AUTH_HEADER, "")) is None):
                try:
                    self.rfile.read(pending)
                except OSError:
                    pass
            if throttled(ip):
                emit("auth_throttled", ip=ip)
                self._simple(429, "too many failed auth attempts")
                return None
            caller = policy.caller_for_key(self.headers.get(AUTH_HEADER, ""))
            if caller is None:
                record_fail(ip)
                emit("auth_rejected", ip=ip, path=self.path)
                self._simple(401, f"missing or invalid {AUTH_HEADER}")
                return None
            return caller.name

        # --- routes -----------------------------------------------------------
        def do_GET(self):
            caller = self._caller()
            if caller is None:
                return
            if self.path.split("?", 1)[0].rstrip("/") == METRICS_PATH:
                return self._json(200, mesh.metrics())
            peer, rest = _route(self.path)
            if peer not in policy.peers or rest not in _CARD_PATHS:
                return self._simple(404, "not found")
            named = policy.callers.get(caller)
            if named is not None and peer not in named.peers:
                emit("card_denied", caller=caller, peer=peer)
                return self._simple(403, f"caller {caller} may not call peer {peer}")
            if mesh.cards is None:
                return self._simple(404, "card routes are disabled")
            status, body = mesh.cards.card_for(peer)
            if status != 200:
                return self._simple(status, body)
            self._json(200, body)

        def do_POST(self):
            length = self._length()
            if length is None:
                return
            caller = self._caller(length)
            if caller is None:
                return
            raw = self.rfile.read(length) if length else b""
            peer, rest = _route(self.path)
            if peer not in policy.peers or rest != "/":
                return self._simple(404, "not found")
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._simple(400, "invalid JSON body")
            if isinstance(msg, list):
                emit("batch_rejected", n=len(msg))
                return self._simple(400, "bastionmesh: JSON-RPC batches are not supported (they would "
                                         "bypass per-message policy); send one message per request")
            if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
                return self._simple(400, "not a JSON-RPC request")
            call, reply = mesh.open_call(caller, peer, msg)
            if reply is not None:
                return self._json(200, reply)
            try:
                self._forward(call)
            finally:
                mesh.close_call(call)

        def do_PUT(self):
            self._simple(405, "method not allowed")

        do_DELETE = do_PATCH = do_PUT

        # --- upstream ---------------------------------------------------------
        def _forward(self, call):
            upstream = policy.peers[call.peer].url
            req = urllib.request.Request(upstream, data=json.dumps(call.forward).encode("utf-8"), method="POST")
            for h, v in self.headers.items():
                if h.lower() in _FWD_REQ_HEADERS:
                    req.add_header(h, v)
            req.add_header("Content-Type", "application/json")
            try:
                resp = _OPENER.open(req, timeout=UPSTREAM_TIMEOUT)
            except urllib.error.HTTPError as e:
                if 300 <= e.code < 400:
                    emit("upstream_redirect_refused", peer=call.peer, status=e.code)
                    return self._simple(502, "bastionmesh: upstream redirected; redirects are not followed")
                return self._relay_json(call, e.code, e.headers, e.read(MAX_BODY + 1))
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                emit("upstream_error", peer=call.peer, error=type(e).__name__)
                return self._simple(502, "bastionmesh: upstream unreachable")
            with resp:
                if resp.headers.get("Content-Type", "").lower().startswith("text/event-stream"):
                    return self._relay_sse(call, resp)
                return self._relay_json(call, resp.status, resp.headers, resp.read(MAX_BODY + 1))

        def _relay_json(self, call, status, headers, data: bytes):
            if len(data) > MAX_BODY:
                emit("upstream_too_large", peer=call.peer)
                return self._simple(502, "bastionmesh: upstream response too large")
            try:
                parsed = json.loads(data) if data else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                out = mesh.inspect_response(call, parsed)
                data = json.dumps(out).encode("utf-8")
            elif isinstance(parsed, list):
                return self._simple(502, "bastionmesh: upstream returned a JSON-RPC batch to a single request")
            elif data:
                return self._simple(502, "bastionmesh: upstream returned a non-JSON body")
            self.send_response(status)
            self._copy_headers(headers)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _relay_sse(self, call, resp):
            self.send_response(resp.status)
            self._copy_headers(resp.headers)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.close_connection = True  # no Content-Length: the stream ends with the connection
            self.end_headers()
            events = iter_sse(resp)
            while True:
                try:
                    other, data = next(events)
                except StopIteration:
                    return
                except StreamLimit:
                    emit("upstream_too_large", peer=call.peer)
                    return
                except (OSError, TimeoutError, http.client.HTTPException):
                    emit("upstream_error", peer=call.peer, error="stream interrupted")
                    return
                blocked = False
                if data is not None:
                    try:
                        parsed = json.loads(data)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, dict):
                        out = mesh.inspect_response(call, parsed)
                        blocked = out is not parsed  # inspect_response only replaces a message to block it
                        data = json.dumps(out)
                    else:
                        emit("sse_non_json_dropped", peer=call.peer)
                        continue  # never pass unscanned payloads through
                try:
                    self.wfile.write(sse_event(other, data))
                    self.wfile.flush()
                except OSError:
                    return  # caller went away
                if blocked:
                    emit("stream_closed_on_block", peer=call.peer, id=call.mid)
                    return

        # --- helpers ----------------------------------------------------------
        def _length(self) -> int | None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._simple(400, "bad Content-Length")
                return None
            if length < 0 or length > MAX_BODY:
                self._simple(413, "request too large")
                return None
            return length

        def _copy_headers(self, headers):
            for h in _FWD_RESP_HEADERS:
                v = headers.get(h) if headers else None
                if v:
                    self.send_header(h, v)

        def _json(self, status, obj):
            out = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def _simple(self, status, text):
            self.close_connection = True  # an unread request body may remain
            out = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    return Handler


def serve(mesh: Mesh, host: str, port: int, emit=lambda *a, **k: None) -> ThreadingHTTPServer:
    """A started-but-not-serving server (call serve_forever)."""
    httpd = ThreadingHTTPServer((host, port), make_handler(mesh, emit))
    httpd.daemon_threads = True
    return httpd
