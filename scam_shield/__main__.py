import argparse
import csv
import os
import pathlib
import sys

from .core import analyze, hash_safeword, verify_safeword

STORE = pathlib.Path(os.environ.get("SCAM_SHIELD_HOME", pathlib.Path.home() / ".scam-shield")) / "safeword"


def build_parser():
    ap = argparse.ArgumentParser(prog="scam-shield")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("text", nargs="?")
    c.add_argument("--file")
    c.add_argument("--sender")
    sw = sub.add_parser("safeword").add_subparsers(dest="sub", required=True)
    sw.add_parser("set").add_argument("word")
    sw.add_parser("verify").add_argument("word")
    return ap


def _run(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)

    if a.cmd == "safeword":
        if a.sub == "set":
            STORE.parent.mkdir(parents=True, exist_ok=True)
            STORE.write_text(hash_safeword(a.word))
            print("Safe word saved (only a salted hash is stored).")
            return 0
        if not STORE.exists():
            print("No safe word set.", file=sys.stderr)
            return 1
        ok = verify_safeword(a.word, STORE.read_text())
        print(
            "MATCH - this is likely really your family member."
            if ok
            else "NO MATCH - treat this caller as a possible scam."
        )
        return 0 if ok else 2

    text = pathlib.Path(a.file).read_text(encoding="utf-8-sig") if a.file else (a.text or sys.stdin.read())
    v = analyze(text, a.sender)
    print(f"Verdict: {v.label.upper()} (risk {v.score}/100)")
    for s in v.signals:
        print(f"  - {s.name} (+{s.weight}): {s.evidence}")
    for tip in v.advice:
        print(f"  > {tip}")
    return 0


def main(argv=None):
    """Run the CLI; a bad input file or argument exits 2 with a one-line error instead of a traceback.

    Set AGENT_ECONOMY_DEBUG=1 to see the full traceback.
    """
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        return _run(argv)
    except (OSError, ValueError, KeyError, csv.Error) as e:
        if os.environ.get("AGENT_ECONOMY_DEBUG"):
            raise
        msg = e.args[0] if isinstance(e, KeyError) and e.args else e
        print(f"error: {msg}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
