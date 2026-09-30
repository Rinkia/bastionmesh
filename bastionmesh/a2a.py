"""A2A JSON-RPC wire shapes, v1.0 and v0.3.

v1.0 renamed every method (`SendMessage`, `GetTask`, ...) and dropped the Part
`kind` discriminator (`{"text": ...}` instead of `{"kind": "text", "text": ...}`);
v0.3 servers are still common. The two method sets are disjoint, so the method
name alone says which version a request speaks. Everything here reads both.

    method name --op_of--> canonical op (send, stream, get, ...)
    params      --request_pieces--> text the caller hands the peer
    response    --response_pieces--> text the peer hands back (task, message,
                                     status, artifacts, history, stream events)

Readers never raise on hostile shapes: non-dicts are skipped, depth and piece
counts are bounded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

_OPS = {
    # v1.0
    "SendMessage": "send",
    "SendStreamingMessage": "stream",
    "GetTask": "get",
    "ListTasks": "list",
    "CancelTask": "cancel",
    "SubscribeToTask": "subscribe",
    "CreateTaskPushNotificationConfig": "push-set",
    "GetTaskPushNotificationConfig": "push-get",
    "ListTaskPushNotificationConfigs": "push-list",
    "DeleteTaskPushNotificationConfig": "push-delete",
    "GetExtendedAgentCard": "card",
    # v0.3
    "message/send": "send",
    "message/stream": "stream",
    "tasks/get": "get",
    "tasks/cancel": "cancel",
    "tasks/resubscribe": "subscribe",
    "tasks/pushNotificationConfig/set": "push-set",
    "tasks/pushNotificationConfig/get": "push-get",
    "tasks/pushNotificationConfig/list": "push-list",
    "tasks/pushNotificationConfig/delete": "push-delete",
    "agent/getAuthenticatedExtendedCard": "card",
}
ALL_OPS = frozenset(_OPS.values())
DEFAULT_OPS = frozenset({"send", "stream", "get", "cancel", "subscribe"})
_STREAMING = frozenset({"stream", "subscribe"})

# A2A owns JSON-RPC codes -32001..-32099; mesh blocks use the generic server error
# and say why in `error.data`.
BLOCK_CODE = -32000

_MAX_DEPTH = 64
_MAX_PIECES = 10_000


@dataclass(frozen=True)
class Piece:
    text: str
    key: str | None = None  # artifactId for artifact parts (stream chunk carry)


def op_of(method) -> str | None:
    return _OPS.get(method) if isinstance(method, str) else None


def is_streaming(op: str) -> bool:
    return op in _STREAMING


def block_error(mid, reason: str, detail: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {
        "code": BLOCK_CODE, "message": f"bastionmesh blocked: {detail}",
        "data": {"bastionmesh": reason, "detail": detail}}}


def _part_text(part) -> str | None:
    """Scannable text of one Part: `text`, or `data` as JSON. Files/raw bytes: None."""
    if not isinstance(part, dict):
        return None
    if isinstance(part.get("text"), str):
        return part["text"]
    if "data" in part and part["data"] is not None:
        try:
            return json.dumps(part["data"], ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError, RecursionError):
            return None
    return None


def _is_binary(part) -> bool:
    if not isinstance(part, dict):
        return False
    if "raw" in part:  # v1.0
        return True
    f = part.get("file")  # v0.3
    return isinstance(f, dict) and "bytes" in f


def _walk(obj, visit, depth: int = 0, key: str | None = None) -> None:
    """Depth-first over dicts/lists; `visit(dict, artifact_key)` on every dict."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(obj, dict):
        aid = obj.get("artifactId")
        if isinstance(aid, str) and isinstance(obj.get("parts"), list):
            key = aid
        visit(obj, key)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _walk(v, visit, depth + 1, key)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                _walk(v, visit, depth + 1, key)


def _pieces(root, *, artifact_names: bool) -> list[Piece]:
    """Every part text under `root`. Past _MAX_PIECES the rest is merged into one
    last piece: nothing goes unscanned, and a flood of tiny parts stays cheap."""
    out: list[Piece] = []

    def visit(d: dict, key):
        parts = d.get("parts")
        if isinstance(parts, list):
            art = key if d.get("artifactId") == key else None
            if artifact_names and art is not None:
                out.extend(Piece(d[f]) for f in ("name", "description") if isinstance(d.get(f), str))
            for p in parts:
                text = _part_text(p)
                if text:
                    out.append(Piece(text, art))

    _walk(root, visit)
    if len(out) > _MAX_PIECES:
        rest = "\n".join(p.text for p in out[_MAX_PIECES - 1:])
        out = out[:_MAX_PIECES - 1] + [Piece(rest)]
    return out


def request_pieces(params) -> list[Piece]:
    """Text a caller sends: every part list in the params (the message's parts are
    the normal case; nothing else in params is read by the peer as content)."""
    return _pieces(params, artifact_names=False) if isinstance(params, dict) else []


def response_pieces(msg) -> list[Piece]:
    """Text a peer returns: every part list anywhere in the message (task status,
    artifacts, history, messages, stream events of both versions, with or without
    a `result` wrapper) plus `error.message` and `error.data`."""
    if not isinstance(msg, dict):
        return []
    out = _pieces({k: v for k, v in msg.items() if k != "error"}, artifact_names=True)
    err = msg.get("error")
    if isinstance(err, dict):
        if isinstance(err.get("message"), str):
            out.append(Piece(err["message"]))
        if err.get("data") is not None:
            text = err["data"] if isinstance(err["data"], str) else _part_text({"data": err["data"]})
            if text:
                out.append(Piece(text))
    return out


# Keys a lenient decoder (Go's encoding/json matches field names case-insensitively)
# would read as these. A key that folds to one of them but is spelled differently
# is refused: the mesh would not scan it, the peer or client would still read it.
_CANONICAL = {k.casefold(): k for k in (
    "jsonrpc", "id", "method", "params", "result", "error", "message", "parts", "text", "data",
    "raw", "url", "file", "bytes", "uri", "configuration", "pushNotificationConfig",
    "taskPushNotificationConfig", "task", "status", "artifacts", "artifact", "history",
    "artifactId", "artifactUpdate", "statusUpdate", "metadata", "name", "description", "kind")}
_SNAKE_OK = {"push_notification_config", "task_push_notification_config", "artifact_id",
             "artifact_update", "status_update"}  # protobuf JSON parsers accept original names
# free-form maps (decoded as maps, never case-folded into fields); their content is
# still scanned as text: `data` as JSON, `metadata` is never read as content
_FREE_FORM = frozenset({"data", "metadata"})


def bad_shape(obj) -> str | None:
    """A reason when `obj` must not pass: a non-canonical spelling of a known key,
    or nesting deeper than the readers walk. None when fine."""
    stack = [(obj, 0, True)]
    while stack:
        node, depth, check_keys = stack.pop()
        if depth > _MAX_DEPTH:  # deeper than the readers walk: content there is never scanned
            return f"nesting deeper than {_MAX_DEPTH} levels"
        if isinstance(node, dict):
            for k, v in node.items():
                if check_keys and isinstance(k, str) and k not in _SNAKE_OK:
                    canon = _CANONICAL.get(k.casefold())  # casefold: Go also folds e.g. U+017F to s
                    if canon is not None and k != canon:
                        return f"key {k!r} is a non-canonical spelling of {canon!r}"
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1, check_keys and k not in _FREE_FORM))
        elif isinstance(node, list):
            stack.extend((v, depth + 1, check_keys) for v in node if isinstance(v, (dict, list)))
    return None


def binary_parts(msg) -> int:
    count = 0

    def visit(d: dict, _key):
        nonlocal count
        parts = d.get("parts")
        if isinstance(parts, list):
            count += sum(1 for p in parts if _is_binary(p))

    _walk(msg, visit)
    return count


def push_urls(op: str, params) -> list[str]:
    """Webhook URLs a request asks the peer to POST task data to.

    push-set: every `url` in the params (v1.0 puts it at the top, v0.3 under
    `pushNotificationConfig`). send/stream: `url`s under a key naming push
    notifications (`configuration.taskPushNotificationConfig` / `pushNotificationConfig`)."""
    if not isinstance(params, dict):
        return []
    urls: list[str] = []

    def collect(obj, depth: int, inside: bool):
        if depth > _MAX_DEPTH:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                under = inside or (isinstance(k, str) and "push" in k.lower())
                if k == "url" and under and isinstance(v, str):
                    urls.append(v)
                elif isinstance(v, (dict, list)):
                    collect(v, depth + 1, under)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, depth + 1, inside)

    if op == "push-set":
        collect(params, 0, True)
    elif op in ("send", "stream"):
        collect(params.get("configuration"), 0, False)
    return urls
