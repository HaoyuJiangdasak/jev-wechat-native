"""Offline tray metadata/error tests: no Qt, host, API or process attachment."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_tray


class TrayMetadataTests(unittest.TestCase):
    def test_startup_phase_exists_before_host(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "state.json"
            native_tray.write_tray_metadata(path, "tray_initializing")
            self.assertEqual(json.loads(path.read_text()), {
                "phase": "tray_initializing", "counts": {}, "error_types": []})
            self.assertEqual(native_tray.read_metadata(path)["phase"], "tray_initializing")

    def test_failed_launch_is_fixed_metadata_without_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            error = OSError(2, "SYNTHETIC_SECRET_DO_NOT_LOG")
            native_tray.write_tray_metadata(path, "startup_failed", "TrayHostLaunchError",
                                           os_error=native_tray.launch_failure_code(error))
            data = json.loads(path.read_text())
            self.assertEqual(data["counts"], {"trayOsError": 2})
            self.assertEqual(data["error_types"], ["TrayHostLaunchError"])
            self.assertNotIn("SYNTHETIC_SECRET", path.read_text())
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_exit_without_host_state_records_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            native_tray.write_tray_metadata(path, "startup_failed", "HostExitedBeforeState", 1)
            data = json.loads(path.read_text())
            self.assertEqual(data["counts"]["hostExitCode"], 1)
            self.assertFalse(native_tray.exit_policy(1, data)[0])

    def test_untrusted_error_string_and_phase_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            for phase, error in (("running", "PRIVATE_ERROR"), ("PRIVATE_PHASE", None)):
                with self.assertRaises(ValueError):
                    native_tray.write_tray_metadata(path, phase, error)
            self.assertFalse(path.exists())

    def test_only_missing_window_and_detachment_retry(self):
        self.assertTrue(native_tray.exit_policy(1, {"error_types": ["TargetSelectionError"]})[0])
        self.assertTrue(native_tray.exit_policy(1, {"error_types": ["NativeSessionDetached"]})[0])
        for error in ("CompatibilityError", "MissingKeyError", "HostExitedBeforeState"):
            self.assertFalse(native_tray.exit_policy(1, {"error_types": [error]})[0])

    def test_smoke_exception_never_writes_production_state(self):
        with patch.object(native_tray, "TraySingleton") as singleton, \
             patch.object(native_tray, "run_tray", side_effect=RuntimeError("PRIVATE_ERROR")), \
             patch.object(native_tray, "write_tray_metadata") as writer:
            singleton.return_value.acquire.return_value = True
            self.assertEqual(native_tray.main(["--smoke-test", "2"]), 4)
            writer.assert_not_called()
            singleton.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
