#!/usr/bin/env python3
"""Require a bin2c array to have at least 64-byte alignment."""

import re
import sys
from pathlib import Path


if len(sys.argv) != 3:
    raise SystemExit(f"usage: {sys.argv[0]} HEADER SYMBOL")

header = Path(sys.argv[1])
symbol = re.escape(sys.argv[2])
source = header.read_text()
pattern = re.compile(
    rf"(\b{symbol}\s*\[\]\s*__attribute__\s*\(\(\s*aligned\s*\(\s*)"
    r"(\d+)(\s*\)\s*\)\))"
)
matches = list(pattern.finditer(source))
if len(matches) != 1:
    raise SystemExit(
        f"error: expected one aligned declaration for {sys.argv[2]}, "
        f"found {len(matches)}"
    )

alignment = int(matches[0].group(2))
if alignment < 64:
    source = pattern.sub(r"\g<1>64\g<3>", source, count=1)
    header.write_text(source)

verified = list(pattern.finditer(header.read_text()))
if len(verified) != 1 or int(verified[0].group(2)) < 64:
    raise SystemExit(f"error: failed to enforce 64-byte alignment for {sys.argv[2]}")

print(f"verified {sys.argv[2]} generated alignment: {verified[0].group(2)} bytes")
