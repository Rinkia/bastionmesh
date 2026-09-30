"""Strict mesh policy loading: every mistake is an error, never ignored."""

from __future__ import annotations

import pytest

from bastionmesh.policy import PolicyError, from_dict, load_policy

KEY_A = "a" * 24
KEY_B = "b" * 24
ENV = {"KEY_A": KEY_A, "KEY_B": KEY_B}


def base(**over):
    obj = {
        "peers": {"researcher": {"url": "https://researcher.example/a2a"},
                  "mailer": {"url": "http://mailer.internal:8000"}},
        "callers": {"orchestrator": {"key_env": "KEY_A", "peers": ["researcher", "mailer"]},
                    "researcher": {"key_env": "KEY_B", "peers": []}},
    }
    obj.update(over)
    return obj


def test_valid_policy_and_defaults():
    p = from_dict(base(), env=ENV)
    assert set(p.peers) == {"researcher", "mailer"}
    r = p.peers["researcher"]
    assert r.card == "pin" and r.card_url == "https://researcher.example"
    assert r.methods == {"send", "stream", "get", "cancel", "subscribe"}
    assert p.host == "127.0.0.1" and p.port == 9100 and p.public_url == "http://127.0.0.1:9100"
    assert (p.on_injection, p.on_relay, p.on_card_drift, p.on_card_findings, p.on_secret_out) == (
        "warn", "warn", "block", "warn", "redact")
    assert p.max_depth == 4 and not p.open_mode
    assert p.caller_for_key(KEY_A).name == "orchestrator" and p.caller_for_key("x" * 24) is None


def test_caller_key_is_not_in_repr():
    p = from_dict(base(), env=ENV)
    assert KEY_A not in repr(p)


def test_load_from_file_resolves_lock_relative(tmp_path):
    f = tmp_path / "mesh.yaml"
    f.write_text("peers:\n  r:\n    url: https://r.example\n    card: lock\n    lock: r.lock.json\n", encoding="utf-8")
    p = load_policy(f, env={})
    assert p.open_mode and p.peers["r"].lock == str(tmp_path / "r.lock.json")


@pytest.mark.parametrize("over, needle", [
    ({"on_injection": "block"}, "unknown key(s) in top level"),
    ({"peers": {}}, "at least one peer"),
    ({"peers": {"r": {"url": "ftp://r"}}}, "absolute http(s) URL"),
    ({"peers": {"r": {"url": "https://r", "urll": "x"}}}, "unknown key(s) in `peers.r`"),
    ({"peers": {"r": {"url": "https://r", "card": "yes"}}}, "`peers.r.card`"),
    ({"peers": {"r": {"url": "https://r", "card": "lock"}}}, "needs `lock:`"),
    ({"peers": {"r": {"url": "https://r", "lock": "x.json"}}}, "only read with `card: lock`"),
    ({"peers": {"r": {"url": "https://r", "methods": ["send", "tools/call"]}}}, "`peers.r.methods`"),
    ({"peers": {"a/b": {"url": "https://r"}}}, "without '/'"),
    ({"peers": {"r": {"url": "https://r", "push_webhooks": ["https://u:p@h/x"]}}}, "no userinfo"),
    ({"limits": {"max_depth": 0}}, "positive integer"),
    ({"limits": {"max_dept": 3}}, "unknown key(s) in `limits:`"),
    ({"actions": {"on_injeciton": "block"}}, "unknown key(s) in `actions:`"),
    ({"actions": {"on_injection": "redact"}}, "not one of warn | block"),
    ({"listen": "nope"}, "host:port"),
    ({"policy_version": 2}, "policy_version"),
    ({"callers": {"x": {"key_env": "MISSING", "peers": []}}}, "unset or shorter"),
    ({"callers": {"x": {"key_env": "KEY_A", "peers": ["ghost"]}}}, "unknown peer"),
    ({"callers": {"x": {"key_env": "KEY_A"}, "y": {"key_env": "KEY_A"}}}, "shared with another caller"),
    ({"callers": {"x": {"key_env": "KEY_A", "role": "admin"}}}, "unknown key(s) in `callers.x`"),
])
def test_bad_policies_fail_loudly(over, needle):
    with pytest.raises(PolicyError) as e:
        from_dict(base(**over), env=ENV)
    assert needle in str(e.value)


def test_short_key_rejected():
    with pytest.raises(PolicyError, match="shorter than 16"):
        from_dict(base(), env={"KEY_A": "short", "KEY_B": KEY_B})


@pytest.mark.parametrize("listen, ok", [
    ("127.0.0.1:9100", True), ("localhost:9100", True), ("[::1]:9100", True),
    ("0.0.0.0:9100", False), ("10.0.0.5:9100", False),
])
def test_open_mode_only_on_loopback(listen, ok):
    obj = base(listen=listen)
    del obj["callers"]
    if ok:
        assert from_dict(obj, env={}).open_mode
    else:
        with pytest.raises(PolicyError, match="open mode"):
            from_dict(obj, env={})


def test_callers_allow_non_loopback():
    assert from_dict(base(listen="0.0.0.0:9100"), env=ENV).host == "0.0.0.0"


def test_bad_yaml_is_a_policy_error(tmp_path):
    f = tmp_path / "m.yaml"
    f.write_text("peers: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(f)
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.yaml")
