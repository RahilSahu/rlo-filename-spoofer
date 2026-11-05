import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rlo_spoof import (
    RLO,
    displayed_extension,
    displayed_name,
    find_bidi_controls,
    spoof_name,
    true_extension,
)


class SpoofTests(unittest.TestCase):
    def test_classic_invoice_case(self):
        name = spoof_name("invoice", "exe", "pdf")
        self.assertIn(RLO, name)
        self.assertTrue(name.replace(RLO, "").endswith(".exe"))
        self.assertEqual(displayed_name(name), "invoiceexe.pdf")

    def test_extensions_detected_correctly(self):
        name = spoof_name("photo", "scr", "jpg")
        self.assertEqual(true_extension(name), "scr")
        self.assertEqual(displayed_extension(name), "jpg")

    def test_photo_display(self):
        name = spoof_name("photo", "exe", "jpg")
        self.assertEqual(displayed_name(name), "photoexe.jpg")


class DetectorTests(unittest.TestCase):
    def test_normal_name_is_clean(self):
        self.assertEqual(find_bidi_controls("quarterly-report.pdf"), [])
        self.assertEqual(displayed_name("quarterly-report.pdf"), "quarterly-report.pdf")

    def test_spoofed_name_is_flagged(self):
        name = spoof_name("invoice", "exe", "pdf")
        findings = find_bidi_controls(name)
        self.assertTrue(any("U+202E" in f for f in findings))

    def test_other_bidi_controls_flagged(self):
        name = "report\u202d-test.docx"
        self.assertTrue(find_bidi_controls(name))


if __name__ == "__main__":
    unittest.main()
