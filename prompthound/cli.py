"""Command-line interface for prompthound."""

import argparse
import json
import sys

from . import __version__
from .scanner import scan_path

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_COLOR = {
    "CRITICAL": "\033[95m",  # magenta
    "HIGH": "\033[91m",      # red
    "MEDIUM": "\033[93m",    # yellow
    "LOW": "\033[96m",       # cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
BLUE = "\033[94m"


def _paint(text, code, color):
    return f"{code}{text}{RESET}" if color else text


def build_parser():
    parser = argparse.ArgumentParser(
        prog="prompthound",
        description="Static analyzer that hunts insecure AI/LLM integration patterns.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Only report findings at or above this severity (default: LOW)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"prompthound {__version__}")
    return parser


def _to_dict(f):
    r = f["rule"]
    return {
        "id": r["id"],
        "severity": r["severity"],
        "title": r["title"],
        "file": f["file"],
        "line": f["line"],
        "code": f["code"],
        "why": r["why"],
        "fix": r["fix"],
    }


def main(argv=None):
    args = build_parser().parse_args(argv)

    findings = scan_path(args.path)
    threshold = SEV_ORDER[args.min_severity]
    findings = [f for f in findings if SEV_ORDER[f["rule"]["severity"]] >= threshold]
    findings.sort(key=lambda f: (-SEV_ORDER[f["rule"]["severity"]], f["file"], f["line"]))

    if args.json:
        print(json.dumps([_to_dict(f) for f in findings], indent=2))
        return 1 if findings else 0

    color = sys.stdout.isatty() and not args.no_color

    print()
    print(_paint(f"🐶 prompthound", BOLD, color) + _paint(f"  v{__version__}", DIM, color))
    print(_paint(f"   scanning {args.path}", DIM, color))
    print()

    for f in findings:
        r = f["rule"]
        sev = r["severity"]
        tag = _paint(f" {sev} ", SEV_COLOR[sev] + BOLD, color)
        print(f"{tag} {_paint(r['id'], BOLD, color)}  {r['title']}")
        location = f["file"] + ":" + str(f["line"])
        print(f"   {_paint(location, BLUE, color)}")
        print(f"     {_paint(f['code'], DIM, color)}")
        print(f"   {_paint('why:', BOLD, color)} {r['why']}")
        print(f"   {_paint('fix:', BOLD, color)} {r['fix']}")
        print()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["rule"]["severity"]] += 1

    if findings:
        summary = (
            f"{len(findings)} findings  "
            f"({counts['CRITICAL']} critical, {counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium, {counts['LOW']} low)"
        )
        print(_paint("✗ " + summary, SEV_COLOR["HIGH"] + BOLD, color))
    else:
        print(_paint("✓ No insecure AI/LLM patterns found.", GREEN + BOLD, color))
    print()

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
