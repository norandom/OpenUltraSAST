"""Secret redaction for traces and reports (Phase 15).

Example secrets are assembled at runtime (string concatenation) so no scannable token
literal lives in the repository, while still exercising the redaction patterns.
"""

from openultrasast.redaction import REDACTED, redact_secrets


def test_redacts_provider_api_keys() -> None:
    secret = "sk-" + "abcdEFGH1234567890zzzz"
    out = redact_secrets(f"key {secret} used")
    assert secret not in out and REDACTED in out


def test_redacts_aws_github_slack_google_keys() -> None:
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    github = "ghp_" + "0123456789abcdefghij" + "ABCDEFGHIJ012345"
    slack = "xoxb-" + "123456789012" + "-abcdefghijklmno"
    google = "AIza" + "SyA1234567890_abcdefghijklmnopqrst"
    assert aws not in redact_secrets(aws)
    assert github not in redact_secrets(github)
    assert slack not in redact_secrets(slack)
    assert google not in redact_secrets(google)


def test_redacts_bearer_token_but_keeps_scheme() -> None:
    out = redact_secrets("Authorization: Bearer " + "abcDEF123456ghiJKL")
    assert out == f"Authorization: Bearer {REDACTED}"


def test_redacts_url_embedded_credentials() -> None:
    password = "s3cret" + "Pass"
    out = redact_secrets("postgres://admin:" + password + "@db.internal:5432/app")
    assert password not in out and "admin" in out  # user kept, password masked


def test_redacts_key_value_assignments() -> None:
    pw = "hunter2" + "value"
    tok = "tok_" + "abcdefgh"
    assert pw not in redact_secrets('password = "' + pw + '"')
    assert tok not in redact_secrets("api_key: " + tok)


def test_redacts_private_key_block() -> None:
    body = "MIIE" + "abc"
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"
    assert body not in redact_secrets(pem)


def test_leaves_benign_text_untouched_and_is_idempotent() -> None:
    benign = "return eval(request.data)  # CWE-95 code injection"
    assert redact_secrets(benign) == benign
    once = redact_secrets("sk-" + "abcdEFGH1234567890zzzz")
    assert redact_secrets(once) == once  # idempotent
