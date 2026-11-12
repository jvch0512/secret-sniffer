# secret-sniffer

Find secrets before they reach your repository. Provider-specific patterns (AWS, GitHub, Slack, Stripe, Google, LLM API keys, private keys, JWTs, credentials in URLs) plus **entropy-based detection** for generic `token = "..."` assignments.

Designed around one rule: **the tool must never leak what it finds.** Every preview is redacted, and a test asserts it for both text and JSON output.

## Features

* Staged-changes mode scans the **git index**, so a secret you "removed" from the working tree but still staged is caught (tested)
* Pre-commit hook installer: `secret-sniffer --install-hook`
* **Baselines**: accept existing findings with `--write-baseline`, fail only on new ones (fingerprints are salted hashes, no secrets stored)
* Placeholder and low-entropy filtering to keep false positives down (`your_token_here`, `${VAR}`, repeated characters)
* Inline allow marker: `# secret-sniffer:ignore`
* Skips binary files, files over 1 MB and vendor directories
* Exit code 2 on findings, with `--fail-on` severity threshold

## Usage

```bash
pip install -e .
secret-sniffer .                         # scan a directory
secret-sniffer --staged                  # scan what you are about to commit
secret-sniffer --install-hook            # block commits that contain secrets
secret-sniffer . --write-baseline .secrets-baseline.json
secret-sniffer . --baseline .secrets-baseline.json --fail-on medium
```

## How detection works

1. Provider regexes for well-known token shapes
2. A generic assignment regex (`secret|token|password|api_key = "..."`) whose value must reach **3.5 bits/char of Shannon entropy**
3. Placeholder filter, then redaction of the matched value in the output

## Limitations

Regex and entropy heuristics will miss obfuscated secrets and will flag some random-looking identifiers. A found secret must be **rotated**, not just removed: it stays in git history. Test fixtures in this repo assemble secret-shaped strings at runtime so the repository itself contains none.

## Development

```bash
pip install -e .[dev] && pytest -q
```

MIT licensed.
