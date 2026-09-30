"""A2A wire shapes, v1.0 and v0.3: method table, text extraction, push URLs."""

from __future__ import annotations

import json

import pytest

from bastionmesh import a2a


@pytest.mark.parametrize("method, op", [
    ("SendMessage", "send"), ("message/send", "send"),
    ("SendStreamingMessage", "stream"), ("message/stream", "stream"),
    ("GetTask", "get"), ("tasks/get", "get"),
    ("CancelTask", "cancel"), ("tasks/cancel", "cancel"),
    ("SubscribeToTask", "subscribe"), ("tasks/resubscribe", "subscribe"),
    ("ListTasks", "list"),
    ("CreateTaskPushNotificationConfig", "push-set"), ("tasks/pushNotificationConfig/set", "push-set"),
    ("GetExtendedAgentCard", "card"), ("agent/getAuthenticatedExtendedCard", "card"),
])
def test_method_table_maps_both_versions(method, op):
    assert a2a.op_of(method) == op


@pytest.mark.parametrize("method", ["tools/call", "sendmessage", "", None, 7])
def test_unknown_methods_have_no_op(method):
    assert a2a.op_of(method) is None


def test_streaming_ops():
    assert a2a.is_streaming("stream") and a2a.is_streaming("subscribe")
    assert not a2a.is_streaming("send")


V1_TASK = {"jsonrpc": "2.0", "id": 1, "result": {"task": {
    "id": "t1", "contextId": "c1",
    "status": {"state": "TASK_STATE_COMPLETED", "message": {
        "messageId": "m2", "role": "ROLE_AGENT", "parts": [{"text": "status text"}]}},
    "artifacts": [{"artifactId": "a1", "name": "report", "description": "the report",
                   "parts": [{"text": "artifact text"}, {"data": {"k": "data value"}},
                             {"raw": "aGVsbG8=", "mediaType": "text/plain"}]}],
    "history": [{"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "history text"}]}],
}}}

V03_TASK = {"jsonrpc": "2.0", "id": 1, "result": {
    "kind": "task", "id": "t1", "contextId": "c1",
    "status": {"state": "completed", "message": {
        "kind": "message", "messageId": "m2", "role": "agent",
        "parts": [{"kind": "text", "text": "status text"}]}},
    "artifacts": [{"artifactId": "a1", "parts": [
        {"kind": "text", "text": "artifact text"},
        {"kind": "file", "file": {"name": "x.txt", "bytes": "aGVsbG8="}}]}],
}}


def _texts(msg):
    return [p.text for p in a2a.response_pieces(msg)]


def test_v1_task_pieces():
    texts = _texts(V1_TASK)
    assert "status text" in texts and "artifact text" in texts and "history text" in texts
    assert "report" in texts and "the report" in texts
    assert json.dumps({"k": "data value"}) in texts
    assert not any("aGVsbG8" in t for t in texts)  # raw bytes are not text


def test_v1_artifact_pieces_carry_artifact_id():
    keyed = {p.text: p.key for p in a2a.response_pieces(V1_TASK)}
    assert keyed["artifact text"] == "a1" and keyed["status text"] is None


def test_v03_task_pieces():
    texts = _texts(V03_TASK)
    assert "status text" in texts and "artifact text" in texts
    assert not any("aGVsbG8" in t for t in texts)


def test_binary_parts_are_counted():
    assert a2a.binary_parts(V1_TASK) == 1 and a2a.binary_parts(V03_TASK) == 1


@pytest.mark.parametrize("event", [
    {"jsonrpc": "2.0", "id": 1, "result": {"artifactUpdate": {
        "taskId": "t", "contextId": "c", "append": True,
        "artifact": {"artifactId": "a9", "parts": [{"text": "chunk"}]}}}},
    {"jsonrpc": "2.0", "id": 1, "result": {"kind": "artifact-update", "taskId": "t", "append": True,
                                           "artifact": {"artifactId": "a9", "parts": [{"kind": "text", "text": "chunk"}]}}},
])
def test_stream_artifact_events_both_shapes(event):
    [piece] = a2a.response_pieces(event)
    assert piece.text == "chunk" and piece.key == "a9"


@pytest.mark.parametrize("event", [
    {"jsonrpc": "2.0", "id": 1, "result": {"statusUpdate": {"taskId": "t", "status": {
        "state": "TASK_STATE_WORKING", "message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "working"}]}}}}},
    {"jsonrpc": "2.0", "id": 1, "result": {"kind": "status-update", "taskId": "t", "status": {
        "state": "working", "message": {"kind": "message", "parts": [{"kind": "text", "text": "working"}]}}}},
    {"jsonrpc": "2.0", "id": 1, "result": {"message": {"messageId": "m", "role": "ROLE_AGENT",
                                                       "parts": [{"text": "working"}]}}},
])
def test_status_and_message_events(event):
    assert _texts(event) == ["working"]


def test_error_message_is_scanned_too():
    msg = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "task not found", "data": {"x": "y"}}}
    assert "task not found" in _texts(msg)


def test_request_pieces_read_the_message_parts_only():
    params = {"message": {"messageId": "m", "role": "ROLE_USER", "metadata": {"note": "meta"},
                          "parts": [{"text": "do this"}, {"data": {"a": 1}}]}}
    texts = [p.text for p in a2a.request_pieces(params)]
    assert texts == ["do this", json.dumps({"a": 1})]


@pytest.mark.parametrize("hostile", [
    None, 3, "x", [], {"result": None}, {"result": {"artifacts": "no"}},
    {"result": {"artifacts": [None, 3, {"parts": "x"}, {"parts": [None, {"text": 5}]}]}},
])
def test_hostile_shapes_never_raise(hostile):
    a2a.response_pieces(hostile)
    a2a.request_pieces(hostile)
    a2a.binary_parts(hostile)
    a2a.push_urls("push-set", hostile)


def test_deep_nesting_is_bounded():
    deep: dict = {"parts": [{"text": "bottom"}]}
    for _ in range(5000):
        deep = {"history": [deep]}
    a2a.response_pieces({"result": deep})  # must not RecursionError


@pytest.mark.parametrize("op, params, urls", [
    ("push-set", {"taskId": "t", "url": "https://hooks.example/a", "token": "x"}, ["https://hooks.example/a"]),
    ("push-set", {"taskId": "t", "pushNotificationConfig": {"url": "https://h.example/b"}}, ["https://h.example/b"]),
    ("send", {"message": {"parts": []}, "configuration": {"taskPushNotificationConfig": {"url": "https://h/c"}}},
     ["https://h/c"]),
    ("send", {"message": {"parts": []}, "configuration": {"pushNotificationConfig": {"url": "https://h/d"}}},
     ["https://h/d"]),
    ("send", {"message": {"parts": [{"url": "https://file.example/x.pdf"}]}}, []),
])
def test_push_urls(op, params, urls):
    assert a2a.push_urls(op, params) == urls


def test_error_response_shape():
    err = a2a.block_error(7, "injection", "peer reply carries injection")
    assert err == {"jsonrpc": "2.0", "id": 7, "error": {
        "code": -32000, "message": "bastionmesh blocked: peer reply carries injection",
        "data": {"bastionmesh": "injection", "detail": "peer reply carries injection"}}}
