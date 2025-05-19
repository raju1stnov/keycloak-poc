#!/usr/bin/env python
"""
Quick sanity test: can we read the Casbin files as UTF-8?
Usage:  python test_casbin_encoding.py
"""
import sys
from pathlib import Path

FILES = ["app1/casbin_policy.csv", "app1/casbin_model.conf"]

for relpath in FILES:
    fp = Path(relpath)
    try:
        with fp.open(encoding="utf-8") as f:
            first_line = f.readline().rstrip()
        print(f"OK  {relpath}: {first_line[:60]}{'...' if len(first_line) > 60 else ''}")
    except Exception as e:
        print(f"FAIL {relpath}: {e}", file=sys.stderr)
        sys.exit(1)

print("✓ All files readable with utf-8")
