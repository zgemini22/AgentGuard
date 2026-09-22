"""The network allowlist judges the host the server's HTTP client will
connect to. Values whose host parsers disagree on, or that can't be
parsed at all, are refused rather than guessed at (policy.url_host)."""

import pytest

from agentguard.policy import PolicyEngine, url_host
from tests.test_default_policy import load_default_config


@pytest.fixture
def engine():
    return PolicyEngine(load_default_config())


def verdict(engine, url):
    return engine.evaluate("fetch_url", {"url": url})


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos",
    "https://API.GitHub.com/repos",
    "https://api.github.com./repos",
    "https://user@api.github.com/",
    "https://api.github.com:443/x",
    "api.github.com",
    "api.github.com/repos",
    "//api.github.com/repos",
    "https://docs.example.com/readme",
])
def test_allowlisted_hosts_are_allowed(engine, url):
    assert verdict(engine, url).allowed, url


@pytest.mark.parametrize("url", [
    # A backslash ends the authority for browsers, urllib3 and requests,
    # but not for urllib.parse: those clients connect to the first host.
    "http://127.0.0.1:9\\@api.github.com/",
    "https://evil.test\\@api.github.com/",
    "https://evil.test\.api.github.com/",
    # Userinfo is fine; the host after it is what's judged.
    "https://api.github.com@evil.test/",
    # No scheme: the host is the part before the first '/', not the string.
    "evil.test/a.github.com",
    "evil.test/.example.com",
    "evil.test#.github.com",
    # Whitespace / control characters / percent-encoding in the authority.
    "https://evil.test /api.github.com",
    "https://evil.test\t.github.com/",
    "https://evil.test\n.github.com/",
    "https://%65vil.test/",
    "https://api.github.com%2f@evil.test/",
    # No authority at all, or a malformed port.
    "http:evil.test",
    "https://api.github.com:99999/",
    "",
])
def test_ambiguous_or_foreign_hosts_are_denied(engine, url):
    decision = verdict(engine, url)
    assert not decision.allowed, url
    assert decision.category == "network"


@pytest.mark.parametrize("value, host", [
    ("https://API.github.com./x", "api.github.com"),
    # "host:port" with no scheme reads as scheme "host" to urlparse and to
    # WHATWG alike, so it is refused rather than guessed at.
    ("api.github.com:8080/path", None),
    ("//api.github.com:8080/path", "api.github.com"),
    ("http://[::1]:80/", "::1"),
    ("https://bücher.example/", "xn--bcher-kva.example"),
    ("http://a\\@b/", None),
    ("http:b", None),
    ("https://%61.test/", None),
    ("not a url", None),
])
def test_url_host(value, host):
    assert url_host(value) == host


def test_unparseable_value_is_left_alone_when_the_policy_judges_no_hosts():
    engine = PolicyEngine({"network": {"enabled": True}})
    assert engine.evaluate("fetch_url", {"url": "http://a\\@b/"}).allowed


def test_unparseable_value_is_denied_under_a_deny_only_network_policy():
    engine = PolicyEngine({"network": {"deny_patterns": ["*.evil.test"]}})
    decision = engine.evaluate("fetch_url", {"url": "http://good.test\\@x.evil.test/"})
    assert not decision.allowed
    assert "can be determined unambiguously" in decision.reason
