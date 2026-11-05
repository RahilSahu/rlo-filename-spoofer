#!/usr/bin/env python3
"""RLO filename spoof generator and detector.

The Right-to-Left Override character (U+202E) is a Unicode bidirectional
control character. When it appears in a filename, file managers and
browsers render the text after it right-to-left, which can make a file
named "invoice<RLO>fdp.exe" display as "invoiceexe.pdf": an executable
that looks like a PDF.

This is a well-known social engineering and upload-filter bypass
technique (MITRE ATT&CK T1036.002, Right-to-Left Override). Penetration
testers use it to check whether users, mail gateways, and upload
handlers can be fooled, and defenders use it to spot hostile filenames.

This tool has two modes:
- make: build a spoofed filename (optionally copy a harmless test file
  to that name) for an authorised test
- check: inspect a filename, reveal any bidirectional control
  characters, and show the true name versus the displayed name

Zero dependencies: Python 3.9+ standard library only.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

RLO = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
LRM = "\u200e"
RLM = "\u200f"
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING (U+202A)",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING (U+202B)",
    "\u202c": "POP DIRECTIONAL FORMATTING (U+202C)",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE (U+202D)",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE (U+202E)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (U+2066)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (U+2067)",
    "\u2068": "FIRST STRONG ISOLATE (U+2068)",
    "\u2069": "POP DIRECTIONAL ISOLATE (U+2069)",
    "\u200e": "LEFT-TO-RIGHT MARK (U+200E)",
    "\u200f": "RIGHT-TO-LEFT MARK (U+200F)",
}

EXECUTABLE_EXTENSIONS = ["exe", "scr", "bat", "cmd", "com", "pif", "msi", "jar", "ps1", "vbs", "js"]
DISPLAY_EXTENSIONS = ["pdf", "jpg", "png", "docx", "xlsx", "txt", "mp4", "zip"]


def spoof_name(base: str, real_ext: str, fake_ext: str) -> str:
    """Build the spoofed filename.

    Layout: base + RLO + reversed(fake_ext) + "." + real_ext
    The part after RLO is rendered reversed, so the viewer sees
    base + real_ext + "." + fake_ext while the true name ends in
    "." + real_ext.
    """
    real_ext = real_ext.lower().lstrip(".")
    fake_ext = fake_ext.lower().lstrip(".")
    return f"{base}{RLO}{fake_ext[::-1]}.{real_ext}"


def displayed_name(filename: str) -> str:
    """Simulate how a filename containing RLO is displayed.

    Simplified bidi simulation: text after a RIGHT-TO-LEFT OVERRIDE is
    shown reversed until a POP or the end of the string. Good enough to
    demonstrate the deception and to power the check mode.
    """
    out: list[str] = []
    i = 0
    while i < len(filename):
        char = filename[i]
        if char == RLO:
            j = i + 1
            segment: list[str] = []
            while j < len(filename) and filename[j] not in ("\u202c", "\u2069"):
                if filename[j] in BIDI_CONTROLS:
                    j += 1
                    continue
                segment.append(filename[j])
                j += 1
            out.append("".join(reversed(segment)))
            i = j
        elif char in BIDI_CONTROLS:
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def visible_name(filename: str) -> str:
    """Show the raw name with bidi controls made visible, for reports."""
    shown = filename
    for char, label in BIDI_CONTROLS.items():
        shown = shown.replace(char, f"<{label}>")
    return shown


def find_bidi_controls(filename: str) -> list[str]:
    return [label for char, label in BIDI_CONTROLS.items() if char in filename]


def true_extension(filename: str) -> str:
    clean = "".join(c for c in filename if c not in BIDI_CONTROLS)
    return clean.rsplit(".", 1)[-1].lower() if "." in clean else ""


def displayed_extension(filename: str) -> str:
    shown = displayed_name(filename)
    return shown.rsplit(".", 1)[-1].lower() if "." in shown else ""


def make_command(args) -> int:
    name = spoof_name(args.base, args.real_ext, args.fake_ext)
    print(f"True filename:      {visible_name(name)}")
    print(f"Displayed filename: {displayed_name(name)}")
    print(f"True extension:     .{args.real_ext.lower().lstrip('.')}")
    print(f"Looks like:         .{args.fake_ext.lower().lstrip('.')}")
    if args.source:
        source = Path(args.source)
        if not source.is_file():
            print(f"Error: source file not found: {source}", file=sys.stderr)
            return 2
        target = Path(args.output_dir) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        print(f"Created test file:  {target}")
    return 0


def check_command(args) -> int:
    name = args.filename
    controls = find_bidi_controls(name)
    print(f"Raw filename:       {visible_name(name)}")
    print(f"Displayed filename: {displayed_name(name)}")
    print(f"True extension:     .{true_extension(name)}")
    print(f"Displayed extension: .{displayed_extension(name)}")
    if controls:
        print("\nFINDING: bidirectional control characters present:")
        for label in controls:
            print(f"  - {label}")
        if true_extension(name) in EXECUTABLE_EXTENSIONS and displayed_extension(name) in DISPLAY_EXTENSIONS:
            print("RISK: executable file disguised as a document or image. Treat as hostile unless it came from an authorised test.")
        else:
            print("RISK: filename rendering does not match the real filename. Investigate the source.")
        return 1
    print("\nNo bidirectional control characters found.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate and detect Right-to-Left Override (RLO) filename spoofs.")
    sub = parser.add_subparsers(dest="command", required=True)

    make = sub.add_parser("make", help="Build a spoofed filename")
    make.add_argument("base", help="Base name shown first, e.g. invoice")
    make.add_argument("--real-ext", required=True, help="True extension, e.g. exe")
    make.add_argument("--fake-ext", required=True, help="Extension it should look like, e.g. pdf")
    make.add_argument("--source", help="Optional harmless test file to copy to the spoofed name")
    make.add_argument("--output-dir", default=".", help="Where to create the test file")
    make.set_defaults(func=make_command)

    check = sub.add_parser("check", help="Inspect a filename for bidi spoofing")
    check.add_argument("filename")
    check.set_defaults(func=check_command)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
