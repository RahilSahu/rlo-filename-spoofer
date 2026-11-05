# RLO Filename Spoofer and Detector

A small tool for generating and detecting Right-to-Left Override
(U+202E) filename spoofs, the trick that makes a file called
`invoice.exe` display on screen as `invoiceexe.pdf`.

This technique is tracked as MITRE ATT&CK T1036.002 (Masquerading:
Right-to-Left Override). It turns up in phishing lures, in mail gateway
and upload filter bypass attempts, and in security awareness tests.

## Why this exists

- Testers: check whether a mail gateway, DLP, upload handler, or a
  user's eye can be fooled by a spoofed filename, in an authorised test
- Defenders: the `check` mode inspects any suspicious filename, reveals
  the hidden control characters, and shows the true extension versus
  the displayed one

## Usage

Generate a spoofed name:

```bash
python3 rlo_spoof.py make invoice --real-ext exe --fake-ext pdf
```

```text
True filename:      invoice<RIGHT-TO-LEFT OVERRIDE (U+202E)>fdp.exe
Displayed filename: invoiceexe.pdf
True extension:     .exe
Looks like:         .pdf
```

Optionally copy a harmless test file to the spoofed name:

```bash
python3 rlo_spoof.py make invoice --real-ext exe --fake-ext pdf --source ./harmless-test.txt
```

Inspect a suspicious filename:

```bash
python3 rlo_spoof.py check "invoice<U+202E>fdp.exe"

Raw filename:       invoice<RIGHT-TO-LEFT OVERRIDE (U+202E)>fdp.exe
Displayed filename: invoiceexe.pdf
True extension:     .exe
Displayed extension: .pdf

FINDING: bidirectional control characters present
RISK: executable file disguised as a document or image
```

The check mode exits with code 1 when control characters are found, so
it can be dropped into scripts that scan upload directories or mail
quarantine folders.

## How it works

The spoofed name is built as:

```text
base + U+202E + reversed(fake extension) + "." + real extension
```

Everything after U+202E is rendered right-to-left by file managers and
browsers, so the viewer sees the extensions swapped. The detector
simulates that rendering and compares true versus displayed extensions.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only use the generator in authorised security tests and awareness
exercises, with harmless test files. Disguising real malware with this
technique is an attack, not a test.

## License

MIT, see LICENSE.
