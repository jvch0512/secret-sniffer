from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

from .core import SEV, apply_baseline, scan_path, scan_staged

HOOK = "#!/bin/sh\n# installed by secret-sniffer\nsecret-sniffer --staged --fail-on medium || {\n  echo 'secret-sniffer: possible secret in staged changes, commit blocked.'; exit 1; }\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secret-sniffer", description="Find secrets in files or staged git changes. Output is always redacted.")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--staged", action="store_true", help="scan staged changes (use as a pre-commit hook)")
    p.add_argument("--baseline", help="JSON file of accepted fingerprints to ignore")
    p.add_argument("--write-baseline", help="write current findings as a baseline file and exit 0")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=SEV, default="low")
    p.add_argument("--install-hook", action="store_true", help="install a git pre-commit hook in the current repo")
    a = p.parse_args(argv)

    if a.install_hook:
        hook = Path(".git/hooks/pre-commit")
        if not hook.parent.is_dir():
            print("not a git repository", file=sys.stderr)
            return 1
        hook.write_text(HOOK)
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"hook installed at {hook}")
        return 0

    findings = scan_staged(a.path) if a.staged else scan_path(a.path)
    if a.write_baseline:
        Path(a.write_baseline).write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2))
        print(f"baseline with {len(findings)} finding(s) written to {a.write_baseline}")
        return 0
    if a.baseline and Path(a.baseline).exists():
        findings = apply_baseline(findings, set(json.loads(Path(a.baseline).read_text())))

    if a.format == "json":
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(f"[{f.severity.upper():8}] {f.rule:24} {f.file}:{f.line}\n    {f.preview}")
        print(f"\n{len(findings)} potential secret(s)")
    return 2 if any(SEV.index(f.severity) >= SEV.index(a.fail_on) for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
