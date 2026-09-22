from agentguard.classify import (
    ArgumentClassifier,
    Classification,
    classify_by_key_name,
    classify_property,
)
from agentguard.policy import PolicyEngine, iter_string_arguments

FILE_TOOLS = [
    {
        "name": "read_document",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_location": {"type": "string"},
                "encoding": {"type": "string", "description": "Text encoding, e.g. utf-8"},
            },
        },
    },
    {
        "name": "http_get",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "timeout": {"type": "number"},
            },
        },
    },
    {
        "name": "open_thing",
        "inputSchema": {
            "type": "object",
            "properties": {
                "where": {"type": "string", "description": "Absolute path to the file to read."},
                "what": {"type": "string", "description": "The URL to fetch content from."},
                "how": {"type": "string", "description": "Shell command to run in the sandbox."},
                "content": {"type": "string", "description": "The content to write to the file."},
            },
        },
    },
    {"name": "no_schema_tool"},
    {"name": "", "inputSchema": {}},
    "not-a-dict",
]


def make_classifier() -> ArgumentClassifier:
    c = ArgumentClassifier()
    c.register_tools(FILE_TOOLS)
    return c


def test_key_name_fallback_is_v1_behavior():
    assert classify_by_key_name("path") == Classification("file_access", "key_name")
    assert classify_by_key_name("URL") == Classification("network", "key_name")
    assert classify_by_key_name("command") == Classification("command_exec", "key_name")
    assert classify_by_key_name("count") is None


def test_register_tools_skips_malformed_entries():
    c = make_classifier()
    assert c.known_tools == ["http_get", "no_schema_tool", "open_thing", "read_document"]
    assert c.register_tools(None) == 0
    assert c.register_tools("nope") == 0


def test_property_name_token_classifies_without_schema():
    c = ArgumentClassifier()
    assert c.classify("anything", "file_location").category == "file_access"
    assert c.classify("anything", "targetHost").category == "network"
    assert c.classify("anything", "shell-script").category == "command_exec"
    assert c.classify("anything", "file_location").source == "key_token"


def test_property_name_token_does_not_match_inside_words():
    c = ArgumentClassifier()
    assert c.classify("anything", "profile") is None
    assert c.classify("anything", "curly") is None


def test_schema_format_uri_beats_path_like_key_name():
    c = make_classifier()
    # `target` is in PATH_ARG_KEYS, but the schema says it's a URI.
    result = c.classify("http_get", "target")
    assert result == Classification("network", "schema:format")
    # Same key on a tool with no schema falls back to the v1 guess.
    assert c.classify("no_schema_tool", "target") == Classification("file_access", "key_name")


def test_schema_description_keywords_classify():
    c = make_classifier()
    assert c.classify("open_thing", "where") == Classification("file_access", "schema:description")
    assert c.classify("open_thing", "what") == Classification("network", "schema:description")
    assert c.classify("open_thing", "how") == Classification("command_exec", "schema:description")


def test_content_argument_is_not_mistaken_for_a_path():
    c = make_classifier()
    assert c.classify("open_thing", "content") is None
    assert c.classify("read_document", "encoding") is None


def test_unknown_property_and_unknown_tool_are_unclassified():
    c = make_classifier()
    assert c.classify("read_document", "mystery") is None
    assert c.classify("never_listed", "mystery") is None
    assert classify_property("mystery", None) is None
    assert classify_property("mystery", {"type": "string", "format": "not-a-real-format"}) is None


def test_engine_uses_schema_to_deny_renamed_path_argument():
    engine = PolicyEngine({"file_access": {"deny_patterns": ["**/.ssh/**"]}})
    engine.classifier.register_tools(FILE_TOOLS)
    decision = engine.evaluate("read_document", {"file_location": "/home/u/.ssh/id_rsa"})
    assert decision.allowed is False
    assert decision.category == "file_access"
    assert decision.argument_categories == {"file_location": "file_access"}


def test_engine_denies_uri_format_argument_via_network_rule():
    engine = PolicyEngine({"network": {"allow_patterns": ["api.github.com"], "default_action": "deny"}})
    engine.classifier.register_tools(FILE_TOOLS)
    decision = engine.evaluate("http_get", {"target": "https://evil.example.net/x", "timeout": 5})
    assert decision.allowed is False
    assert decision.category == "network"
    # `target` is also a path-like key name, so the value is judged under
    # both categories; the network allowlist is what denies it.
    assert decision.argument_categories == {"target": "network+file_access"}


def test_engine_reports_unclassified_arguments_in_decision():
    engine = PolicyEngine({"file_access": {"deny_patterns": ["**/.ssh/**"]}})
    decision = engine.evaluate("list_things", {"count": "10", "path": "/tmp/x"})
    assert decision.allowed is True
    assert decision.argument_categories == {"count": "unclassified", "path": "file_access"}


def test_iter_string_arguments_flattens_lists_and_nested_objects():
    args = {
        "paths": ["/a", "/b"],
        "options": {"path": "/c", "depth": 2},
        "items": [{"file": "/d"}],
        "n": 3,
        "flag": True,
    }
    assert list(iter_string_arguments(args)) == [
        ("paths", "/a"), ("paths", "/b"), ("options.path", "/c"), ("items.file", "/d"),
    ]


def test_engine_checks_path_lists_and_nested_paths():
    engine = PolicyEngine({"file_access": {"deny_patterns": ["**/.env"]}})
    assert engine.evaluate("read_many", {"paths": ["/app/README", "/app/.env"]}).allowed is False
    assert engine.evaluate("read_opts", {"options": {"path": "/app/.env"}}).allowed is False
    assert engine.evaluate("read_many", {"paths": ["/app/README"]}).allowed is True
