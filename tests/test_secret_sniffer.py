import json
import subprocess

import pytest

from secret_sniffer.cli import main
from secret_sniffer.core import entropy, redact, scan_staged, scan_text, scan_path

# Secret-shaped values are assembled at runtime so this repository contains no credential-like literals.
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GH = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1fG3hI5"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
STRIPE = "sk" + "_live_" + "AbCdEfGhIjKlMnOp1234"
GOOGLE = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
HIGH_ENT = "q8Zk3Lm9Xv2Bn7Rt4Yc6Wp1Hd5Fs0Ja"


@pytest.mark.parametrize("secret,rule", [
    (AWS, "aws-access-key"), (GH, "github-token"), (SLACK, "slack-token"), (STRIPE, "stripe-live-key"),
    (GOOGLE, "google-api-key"), (PEM, "private-key"),
])
def test_provider_patterns(secret, rule):
    f = scan_text("a.txt", f"value = {secret}\n")
    assert rule in {x.rule for x in f}
    assert all(secret not in x.preview for x in f)  # redacted


def test_jwt_and_url_credentials():
    jwt = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcDEF123456_-xyz"
    assert "jwt" in {x.rule for x in scan_text("a", f"t={jwt}")}
    f = scan_text("a", "db = postgres://admin:Sup3rS3cret@db.internal:5432/app")
    assert f and f[0].rule == "url-credentials" and "Sup3rS3cret" not in f[0].preview


def test_generic_high_entropy_assignment():
    f = scan_text("c.py", f'API_TOKEN = "{HIGH_ENT}"\n')
    assert f and f[0].rule == "high-entropy-secret"


@pytest.mark.parametrize("line", [
    'API_TOKEN = "your_token_goes_here_please_replace"',
    'password = "aaaaaaaaaaaaaaaaaaaaaaaa"',
    'secret = "${SECRET_FROM_ENV_VARIABLE_NAME}"',
    "key = AKIAEXAMPLEEXAMPLE12",
    'API_KEY = "changemechangemechangeme12"',
])
def test_placeholders_and_low_entropy_are_ignored(line):
    assert scan_text("a", line + "\n") == []


def test_inline_ignore_marker():
    assert scan_text("a", f"x = {AWS}  # secret-sniffer:ignore\n") == []


def test_entropy_and_redact_helpers():
    assert entropy("aaaa") == 0 and entropy("abcd") == 2.0
    assert redact("abcdefghijkl") == "abcd…[redacted]" and redact("ab") == "[redacted]"


def test_path_scan_skips_binary_and_vendor_dirs(tmp_path):
    (tmp_path / "ok.txt").write_text(f"k={AWS}\n")
    (tmp_path / "bin.dat").write_bytes(b"\0\0" + AWS.encode())
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(f"k={AWS}\n")
    found = scan_path(tmp_path)
    assert len(found) == 1 and found[0].file.endswith("ok.txt")


def test_baseline_roundtrip(tmp_path, capsys):
    (tmp_path / "a.env").write_text(f"AWS={AWS}\n")
    base = tmp_path / "base.json"
    assert main([str(tmp_path), "--write-baseline", str(base)]) == 0
    assert main([str(tmp_path), "--baseline", str(base)]) == 0
    (tmp_path / "b.env").write_text(f"GH={GH}\n")   # a NEW secret still fails
    assert main([str(tmp_path), "--baseline", str(base)]) == 2


def test_cli_json_output_never_contains_the_secret(tmp_path, capsys):
    (tmp_path / "a.env").write_text(f"AWS={AWS}\n")
    main([str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert AWS not in out and json.loads(out)[0]["rule"] == "aws-access-key"


def test_staged_scan_uses_index_not_working_tree(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@t"); git("config", "user.name", "t")
    f = tmp_path / "leak.txt"
    f.write_text(f"k={AWS}\n")
    git("add", "leak.txt")
    f.write_text("clean now\n")      # working tree is clean, the index still holds the secret
    assert [x.rule for x in scan_staged(tmp_path)] == ["aws-access-key"]


def test_install_hook(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    assert main(["--install-hook"]) == 0
    hook = tmp_path / ".git/hooks/pre-commit"
    assert hook.exists() and "secret-sniffer --staged" in hook.read_text()
