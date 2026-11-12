"""Secret detection: provider patterns plus entropy-based generic detection, redacted output, baselines."""
from __future__ import annotations

import hashlib
import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws-access-key", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", "critical", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", "critical", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("llm-api-key", "high", re.compile(r"\bsk-[A-Za-z0-9_\-]{32,}\b")),
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("url-credentials", "high", re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@\"']{1,64}:([^/\s:@\"']{6,})@")),
]
GENERIC = re.compile(r"""(?i)(?:secret|token|passw(?:or)?d|api[_-]?key|auth[_-]?key|private[_-]?key)\w*["']?\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']""")
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|xxxx|dummy|sample|test[_-]?key|\*{4,}|<[^>]+>|\$\{)")
IGNORE_MARK = "secret-sniffer:ignore"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
MAX_BYTES = 1_000_000
SEV = ["low", "medium", "high", "critical"]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    preview: str
    fingerprint: str

    def as_dict(self):
        return self.__dict__.copy()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def redact(secret: str, keep: int = 4) -> str:
    return secret[:keep] + "…[redacted]" if len(secret) > keep else "[redacted]"


def _fp(rule: str, file: str, secret: str) -> str:
    return hashlib.sha256(f"{rule}|{file}|{secret}".encode()).hexdigest()[:16]


def scan_text(file: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        hit_spans: list[tuple[int, int]] = []
        for rule, sev, rx in PATTERNS:
            for m in rx.finditer(line):
                secret = m.group(1) if rule == "url-credentials" else m.group(0)
                if PLACEHOLDER.search(secret):
                    continue
                hit_spans.append(m.span())
                out.append(Finding(rule, sev, file, n, line.replace(secret, redact(secret)).strip()[:160], _fp(rule, file, secret)))
        for m in GENERIC.finditer(line):
            secret = m.group(1)
            if any(a <= m.start(1) < b for a, b in hit_spans) or PLACEHOLDER.search(secret):
                continue
            if entropy(secret) >= 3.5:
                out.append(Finding("high-entropy-secret", "medium", file, n, line.replace(secret, redact(secret)).strip()[:160], _fp("generic", file, secret)))
    return out


def _is_text(data: bytes) -> bool:
    return b"\0" not in data[:2048]


def scan_path(root: str | Path) -> list[Finding]:
    p = Path(root)
    files = [p] if p.is_file() else [f for f in sorted(p.rglob("*")) if f.is_file() and not (set(f.relative_to(p).parts) & SKIP_DIRS)]
    out: list[Finding] = []
    for f in files:
        try:
            if f.stat().st_size > MAX_BYTES:
                continue
            data = f.read_bytes()
        except OSError:
            continue
        if _is_text(data):
            out += scan_text(f.as_posix(), data.decode("utf-8", "replace"))
    return out


def scan_staged(repo: str | Path = ".") -> list[Finding]:
    """Scan the content that is about to be committed (index), not the working tree."""
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], cwd=repo, capture_output=True, check=True).stdout.split(b"\0")
    out: list[Finding] = []
    for raw in filter(None, names):
        name = raw.decode()
        blob = subprocess.run(["git", "show", f":{name}"], cwd=repo, capture_output=True)
        if blob.returncode == 0 and len(blob.stdout) <= MAX_BYTES and _is_text(blob.stdout):
            out += scan_text(name, blob.stdout.decode("utf-8", "replace"))
    return out


def apply_baseline(findings: list[Finding], known: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in known]
