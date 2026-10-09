import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime

source_path = Path(__file__).resolve().parents[1] / "network-change-and-check-fix" / "ad_export.py"
spec = importlib.util.spec_from_file_location("ad_export_under_test", source_path)
ad_export = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ad_export
spec.loader.exec_module(ad_export)


class ExportConfigurationTests(unittest.TestCase):
    def test_default_pattern_lists_are_independent(self):
        first = ad_export.ExportConfig()
        second = ad_export.ExportConfig()
        first.name_patterns.append("SRV*")
        self.assertEqual(second.name_patterns, [])
        self.assertEqual(first.csv_output_path, "ad_computers.csv")

    def test_missing_and_corrupt_state_have_no_last_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            self.assertEqual(ad_export.load_state(str(path)), {"last_run": None})
            path.write_text("not-json", encoding="utf-8")
            self.assertEqual(ad_export.load_state(str(path)), {"last_run": None})

    def test_state_round_trip_retains_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            timestamp = datetime(2026, 10, 9, 12, 30, 0)
            ad_export.save_state(str(path), timestamp)
            self.assertEqual(ad_export.load_state(str(path))["last_run"], timestamp.isoformat())


if __name__ == "__main__":
    unittest.main()
