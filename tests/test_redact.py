from agentguard.redact import SecretRedactor

CONFIG = {
    "redaction": {
        "enabled": True,
        "rules": [
            {"name": "aws_access_key_id", "pattern": r"AKIA[0-9A-Z]{16}"},
            {"name": "github_token", "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}"},
            {
                "name": "private_key_block",
                "pattern": r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----",
            },
        ],
    }
}


def make_redactor() -> SecretRedactor:
    return SecretRedactor.from_config(CONFIG)


def test_redacts_aws_access_key():
    redactor = make_redactor()
    text, rules = redactor.redact("my key is AKIAABCDEFGHIJKLMNOP ok")
    assert "AKIAABCDEFGHIJKLMNOP" not in text
    assert "[REDACTED:aws_access_key_id]" in text
    assert rules == ["aws_access_key_id"]


def test_redacts_github_token():
    redactor = make_redactor()
    token = "ghp_" + "a" * 36
    text, rules = redactor.redact(f"token={token}")
    assert token not in text
    assert rules == ["github_token"]


def test_redacts_private_key_block():
    redactor = make_redactor()
    block = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETDATA\n-----END OPENSSH PRIVATE KEY-----"
    text, rules = redactor.redact(f"here it is: {block}")
    assert "SECRETDATA" not in text
    assert rules == ["private_key_block"]


def test_redacts_multiple_secrets_in_one_string():
    redactor = make_redactor()
    text, rules = redactor.redact("keys: AKIAABCDEFGHIJKLMNOP and AKIAZZZZZZZZZZZZZZZZ")
    assert "AKIA" not in text
    assert rules == ["aws_access_key_id", "aws_access_key_id"]


def test_leaves_clean_text_untouched():
    redactor = make_redactor()
    text, rules = redactor.redact("just some normal tool output, nothing to see here")
    assert text == "just some normal tool output, nothing to see here"
    assert rules == []


def test_disabled_redactor_is_a_noop():
    config = {"redaction": {"enabled": False, "rules": [{"name": "aws_access_key_id", "pattern": r"AKIA[0-9A-Z]{16}"}]}}
    redactor = SecretRedactor.from_config(config)
    text, rules = redactor.redact("AKIAABCDEFGHIJKLMNOP")
    assert text == "AKIAABCDEFGHIJKLMNOP"
    assert rules == []


def test_no_config_uses_default_rules():
    redactor = SecretRedactor.from_config({})
    text, rules = redactor.redact("AKIAABCDEFGHIJKLMNOP")
    assert "AKIAABCDEFGHIJKLMNOP" not in text
    assert rules == ["aws_access_key_id"]
