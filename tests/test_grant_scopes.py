"""A grant only ever turns an ask into an allow, and only for exactly what
the operator was shown."""

from agentguard.policy import ASK, DENY, PolicyEngine, grant_scopes
from agentguard.session import Session

ASK_ON_MISS = {"network": {"allow_patterns": ["*.github.com"], "default_action": "ask"}}


def test_allowlist_miss_scope_names_the_host_that_missed_not_the_first_url():
    engine = PolicyEngine(ASK_ON_MISS)
    decision = engine.evaluate("fetch", {"urls": ["https://api.github.com/x", "https://evil.test/y"]})
    assert decision.action == ASK
    assert grant_scopes("fetch", decision) == ["fetch:network:evil.test"]


def test_a_session_grant_for_one_host_does_not_cover_another():
    engine = PolicyEngine(ASK_ON_MISS)
    session = Session.new(["server"])
    first = engine.evaluate("fetch", {"urls": ["https://api.github.com/x", "https://evil.test/y"]}, session)
    session.grants.update(grant_scopes("fetch", first))
    # The approved host is now covered...
    assert engine.evaluate("fetch", {"url": "https://evil.test/z"}, session).allowed
    # ...but a different one, even next to an allowlisted URL, is asked again.
    other = engine.evaluate("fetch", {"urls": ["https://api.github.com/x", "https://other.test/"]}, session)
    assert other.action == ASK
    assert grant_scopes("fetch", other) == ["fetch:network:other.test"]


def test_file_allowlist_miss_scope_is_the_canonical_path(tmp_path):
    engine = PolicyEngine({"file_access": {"allow_patterns": [f"{tmp_path}/pub/**"], "default_action": "ask"}},
                          base_dir=str(tmp_path))
    decision = engine.evaluate("read", {"paths": ["pub/a", "priv/b"]})
    assert grant_scopes("read", decision) == [f"read:file_access:{tmp_path}/priv/b"]


ASK_AND_DENY = {"file_access": {"deny_patterns": [
    {"pattern": "**/*.log", "action": "ask"},
    "~/.ssh/**",
]}}


def test_a_hard_deny_on_one_argument_wins_over_an_ask_on_another():
    engine = PolicyEngine(ASK_AND_DENY)
    decision = engine.evaluate("copy", {"source": "/var/app.log", "destination": "~/.ssh/authorized_keys"})
    assert decision.action == DENY
    assert decision.matched_rule == "~/.ssh/**"


def test_a_grant_for_the_ask_part_never_lets_the_deny_through():
    engine = PolicyEngine(ASK_AND_DENY)
    session = Session.new(["server"])
    session.grants.add("copy:file_access:**/*.log")
    # The ask alone is granted...
    assert engine.evaluate("copy", {"source": "/var/app.log"}, session).allowed
    # ...but not when the same call also carries a denied value, in either order.
    for arguments in (
        {"source": "/var/app.log", "destination": "~/.ssh/authorized_keys"},
        {"destination": "~/.ssh/authorized_keys", "source": "/var/app.log"},
    ):
        decision = engine.evaluate("copy", arguments, session)
        assert not decision.allowed
        assert decision.action == DENY


def test_several_asks_in_one_call_need_every_scope_granted():
    engine = PolicyEngine({
        "file_access": {"deny_patterns": [{"pattern": "**/*.log", "action": "ask"}]},
        "network": {"allow_patterns": ["*.github.com"], "default_action": "ask"},
    })
    session = Session.new(["server"])
    arguments = {"path": "/var/app.log", "url": "https://evil.test/"}
    decision = engine.evaluate("upload", arguments, session)
    assert decision.action == ASK
    scopes = grant_scopes("upload", decision)
    assert scopes == ["upload:file_access:**/*.log", "upload:network:evil.test"]
    session.grants.add(scopes[0])
    assert engine.evaluate("upload", arguments, session).action == ASK
    session.grants.add(scopes[1])
    assert engine.evaluate("upload", arguments, session).allowed


def test_unclassified_ask_scope_is_keyed_on_the_argument_names():
    engine = PolicyEngine({"unclassified_arguments": "ask"})
    decision = engine.evaluate("tool", {"b": "x", "a": "y"})
    assert grant_scopes("tool", decision) == ["tool:unclassified:a,b"]
