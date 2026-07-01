"""File walker + rule engine."""

import os
from pathlib import Path

from .rules import COMPILED_RULES, EXT_LANG

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist",
    "build", ".mypy_cache", ".pytest_cache", "site-packages", ".tox",
    "target", ".next", ".nuxt", "vendor", "coverage",
}
MAX_BYTES = 1_000_000  # skip files larger than 1 MB


def language_for(path):
    return EXT_LANG.get(path.suffix.lower())


def _iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        # prune noisy/vendor directories in place
        dirnames[:] = [
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for name in filenames:
            yield Path(dirpath) / name


def scan_path(root):
    """Scan a file or directory; return a list of finding dicts.

    Each finding: {rule, file, line, code}.
    """
    root = Path(root)
    findings = []

    if root.is_file():
        files = [root]
    else:
        files = _iter_files(root)

    for path in files:
        lang = language_for(path)
        if not lang:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in COMPILED_RULES:
                if rule["langs"] != "*" and lang not in rule["langs"]:
                    continue
                if rule["regex"].search(line):
                    findings.append(
                        {
                            "rule": rule,
                            "file": str(path),
                            "line": lineno,
                            "code": line.strip()[:200],
                        }
                    )
    return findings
