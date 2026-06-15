"""Smoke tests for RATECHECK. Standard library only, no network."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ratecheck import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Spec,
    analyze_spec,
)
from ratecheck.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "login_burst.json",
)


def _spec(**overrides):
    base = {
        "target": "https://api.example.com/v1/x",
        "method": "GET",
        "window_seconds": 1.0,
        "probes": [],
    }
    base.update(overrides)
    return Spec.from_dict(base)


class TestMetadata(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(TOOL_NAME, "ratecheck")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestNoThrottle(unittest.TestCase):
    def test_unthrottled_auth_endpoint_is_high(self):
        probes = [{"t": i * 0.05, "status": 401, "headers": {}} for i in range(12)]
        spec = _spec(auth_required=True, probes=probes)
        report = analyze_spec(spec)
        codes = {f.code: f.severity for f in report.findings}
        self.assertIn("RC001", codes)
        self.assertEqual(codes["RC001"], "high")
        self.assertIn("RC003", codes)  # no headers
        self.assertTrue(report.actionable)

    def test_unthrottled_nonauth_is_medium(self):
        probes = [{"t": i * 0.05, "status": 200, "headers": {}} for i in range(8)]
        spec = _spec(auth_required=False, probes=probes)
        report = analyze_spec(spec)
        codes = {f.code: f.severity for f in report.findings}
        self.assertEqual(codes["RC001"], "medium")


class TestHealthy(unittest.TestCase):
    def test_throttled_with_headers_is_clean(self):
        probes = [
            {"t": 0.0, "status": 200, "headers": {"X-RateLimit-Remaining": "1"}},
            {"t": 0.1, "status": 200, "headers": {"X-RateLimit-Remaining": "0"}},
            {"t": 0.2, "status": 429, "headers": {"Retry-After": "2"}},
            {"t": 0.3, "status": 429, "headers": {"Retry-After": "2"}},
        ]
        spec = _spec(probes=probes)
        report = analyze_spec(spec)
        codes = {f.code for f in report.findings}
        self.assertIn("RC100", codes)
        self.assertNotIn("RC001", codes)
        self.assertEqual(report.max_severity, "info")
        self.assertFalse(report.actionable)


class TestLooseLimit(unittest.TestCase):
    def test_throttle_above_documented_limit(self):
        probes = [{"t": i * 0.02, "status": 200, "headers": {"X-RateLimit-Limit": "3"}} for i in range(10)]
        probes.append({"t": 0.25, "status": 429, "headers": {"Retry-After": "1"}})
        spec = _spec(expected_limit=3, probes=probes)
        report = analyze_spec(spec)
        codes = {f.code for f in report.findings}
        self.assertIn("RC002", codes)


class TestThrottleNoRetryAfter(unittest.TestCase):
    def test_missing_retry_after_flagged(self):
        probes = [
            {"t": 0.0, "status": 200, "headers": {"X-RateLimit-Limit": "1"}},
            {"t": 0.1, "status": 429, "headers": {}},
        ]
        spec = _spec(probes=probes)
        report = analyze_spec(spec)
        codes = {f.code for f in report.findings}
        self.assertIn("RC004", codes)


class TestServerErrors(unittest.TestCase):
    def test_5xx_under_load(self):
        probes = [
            {"t": 0.0, "status": 200, "headers": {}},
            {"t": 0.1, "status": 500, "headers": {}},
        ]
        spec = _spec(probes=probes)
        report = analyze_spec(spec)
        codes = {f.code: f.severity for f in report.findings}
        self.assertIn("RC005", codes)
        self.assertEqual(codes["RC005"], "high")


class TestSpecParsing(unittest.TestCase):
    def test_missing_target_raises(self):
        with self.assertRaises(ValueError):
            Spec.from_dict({"probes": []})

    def test_window_derived_from_probes(self):
        spec = Spec.from_dict({
            "target": "x",
            "probes": [{"t": 0.0, "status": 200}, {"t": 2.0, "status": 200}],
        })
        self.assertEqual(spec.window_seconds, 2.0)

    def test_header_keys_lowercased(self):
        spec = Spec.from_dict({
            "target": "x",
            "probes": [{"t": 0, "status": 429, "headers": {"Retry-After": "5"}}],
        })
        self.assertIn("retry-after", spec.probes[0].headers)


class TestCLI(unittest.TestCase):
    def test_demo_table_exit_1(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["check", DEMO])
        self.assertEqual(rc, 1)
        self.assertIn("RC001", buf.getvalue())

    def test_demo_json_parses(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["check", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "ratecheck")
        self.assertTrue(data["actionable"])
        self.assertEqual(data["target"], "https://api.example.com/v1/login")

    def test_missing_file_exit_2(self):
        rc = main(["check", "does_not_exist_12345.json"])
        self.assertEqual(rc, 2)

    def test_no_command_prints_help(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_malformed_json_file_exit_2(self):
        """A file with invalid JSON should exit 2 with a message to stderr."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{not valid json}")
            tmp = f.name
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["check", tmp])
            self.assertEqual(rc, 2)
            self.assertIn("invalid spec", err.getvalue())
        finally:
            os.unlink(tmp)

    def test_json_array_root_exit_2(self):
        """A spec file that is a JSON array (not object) should exit 2."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write('[{"target":"x"}]')
            tmp = f.name
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["check", tmp])
            self.assertEqual(rc, 2)
            self.assertIn("invalid spec", err.getvalue())
        finally:
            os.unlink(tmp)

    def test_empty_probes_no_crash(self):
        """An empty probes list must not raise — just zero findings."""
        spec = _spec(probes=[])
        report = analyze_spec(spec)
        self.assertEqual(report.summary["total_probes"], 0)
        self.assertFalse(report.actionable)

    def test_probe_bad_status_raises_valueerror(self):
        """A probe with a non-numeric status must raise ValueError cleanly."""
        from ratecheck.core import Probe
        with self.assertRaises(ValueError) as ctx:
            Probe.from_dict({"t": 0.0, "status": "OK"})
        self.assertIn("status", str(ctx.exception))

    def test_probe_invalid_status_range_raises(self):
        """A probe status outside 100-599 must raise ValueError."""
        from ratecheck.core import Probe
        with self.assertRaises(ValueError):
            Probe.from_dict({"t": 0.0, "status": 99})
        with self.assertRaises(ValueError):
            Probe.from_dict({"t": 0.0, "status": 600})

    def test_spec_negative_window_raises(self):
        """window_seconds < 0 must raise ValueError."""
        with self.assertRaises(ValueError):
            _spec(window_seconds=-1.0)

    def test_spec_empty_target_raises(self):
        """An empty target string must raise ValueError."""
        from ratecheck.core import Spec
        with self.assertRaises(ValueError):
            Spec.from_dict({"target": "   ", "probes": []})

    def test_spec_non_list_probes_raises(self):
        """probes that is not a list must raise ValueError."""
        from ratecheck.core import Spec
        with self.assertRaises(ValueError):
            Spec.from_dict({"target": "https://x.example.com", "probes": "bad"})

    def test_zero_window_derived_single_probe(self):
        """A single probe with only one timestamp: window derives to 0, no crash."""
        from ratecheck.core import Spec
        spec = Spec.from_dict({
            "target": "https://x.example.com",
            "probes": [{"t": 5.0, "status": 200}],
        })
        self.assertEqual(spec.window_seconds, 0.0)
        report = analyze_spec(spec)
        # Should not crash; effective_rps is None when window is 0
        self.assertIsNone(report.summary["effective_rps"])


if __name__ == "__main__":
    unittest.main()
