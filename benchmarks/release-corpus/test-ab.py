#!/usr/bin/env python3
# Unit tests for the A/B gate's verdict computation (ab.py).
#
# Run: python3 test-ab.py
#
# The verdict cases feed synthetic per-package median seconds into
# compute_verdict and pin the verdict: the pass case, each gate rule
# tripping on its own, the noise band absorbing a geomean move, the
# no-baseline verdict, and the fail-closed edges (unpaired packages,
# missing calibration, zero-length timings). The timing cases run fake
# binaries through main and time_binary and pin the run-validity and
# usage-error paths: a run counts only when it completes a lint, which
# rpmcrab reports with exit status 0 or 64.

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ab", HERE / "ab.py")
ab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ab)


def scaled(medians, factor):
    return {name: seconds * factor for name, seconds in medians.items()}


BASE = {
    "aaa_base": 0.4,
    "bash": 0.6,
    "chromium": 8.0,
    "curl": 0.3,
    "git": 0.2,
    "glibc": 1.2,
    "kernel-default": 6.0,
    "perl": 1.5,
    "systemd": 2.0,
    "vim": 0.9,
}


class VerdictTests(unittest.TestCase):
    def test_pass_with_ratios_near_one(self):
        verdict = ab.compute_verdict(BASE, scaled(BASE, 1.02), (BASE, scaled(BASE, 1.01)))
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["reasons"], [])

    def test_pass_when_candidate_is_faster(self):
        verdict = ab.compute_verdict(BASE, scaled(BASE, 0.8), (BASE, BASE))
        self.assertEqual(verdict["verdict"], "pass")

    def test_geomean_trip(self):
        # Everything 20% slower with a silent calibration pair: both the
        # 1.10 bar and the 3x-spread bar are cleared.
        verdict = ab.compute_verdict(BASE, scaled(BASE, 1.2), (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("geomean" in r for r in verdict["reasons"]))
        self.assertAlmostEqual(verdict["geomean_ratio"], 1.2, places=3)
        self.assertEqual(verdict["aa_spread"], 0.0)

    def test_geomean_move_within_noise_band_passes(self):
        # Geomean 1.13 clears the 1.10 bar, but the A/A pair spread 0.05
        # puts 3x spread at 0.15, above the 0.13 slowdown: the run is too
        # noisy to call this a regression.
        aa = (BASE, scaled(BASE, 1.05))
        verdict = ab.compute_verdict(BASE, scaled(BASE, 1.13), aa)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertAlmostEqual(verdict["aa_spread"], 0.05, places=3)

    def test_geomean_move_beyond_noise_band_fails(self):
        # Same 1.13 geomean, tighter calibration (spread 0.02, 3x = 0.06
        # < 0.13): the gate trips.
        aa = (BASE, scaled(BASE, 1.02))
        verdict = ab.compute_verdict(BASE, scaled(BASE, 1.13), aa)
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("geomean" in r for r in verdict["reasons"]))

    def test_per_package_trip(self):
        # One package at 2.5x with a 9s delta; the geomean over ten
        # packages stays under 1.10, so only the per-package rule trips.
        candidate = dict(BASE)
        candidate["kernel-default"] = BASE["kernel-default"] * 2.5
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("kernel-default" in r for r in verdict["reasons"]))
        self.assertFalse(any("geomean" in r for r in verdict["reasons"]))
        self.assertLess(verdict["geomean_ratio"], ab.GEOMEAN_MAX)

    def test_per_package_ratio_without_delta_passes(self):
        # A 2.1x ratio on a 0.1s package is an 0.11s delta: under the
        # absolute floor, so the per-package rule stays silent.
        base = dict(BASE)
        base["git"] = 0.1
        candidate = dict(base)
        candidate["git"] = 0.21
        verdict = ab.compute_verdict(base, candidate, (base, base))
        self.assertEqual(verdict["verdict"], "pass")

    def test_per_package_trip_with_delta_above_floor(self):
        candidate = dict(BASE)
        candidate["bash"] = BASE["bash"] + 0.25  # 0.85 vs 0.6: ratio 1.42
        candidate["curl"] = BASE["curl"] * 3.0  # ratio 3.0, delta 0.6
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("curl" in r for r in verdict["reasons"]))
        # bash moved by exactly the floor but its ratio is under 2.0:
        # the rule needs both conditions, so bash stays unreported.
        self.assertFalse(any("bash" in r for r in verdict["reasons"]))

    def test_dead_candidate_fails_closed(self):
        # A candidate that crashes instantly on every package records
        # near-zero medians against a baseline that did real work:
        # the gate fails closed instead of passing it as faster.
        candidate = {name: 0.0 for name in BASE}
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(
            any("plausibility floor" in r for r in verdict["reasons"]),
            verdict["reasons"],
        )

    def test_dead_candidate_on_one_package_fails_closed(self):
        candidate = dict(BASE)
        candidate["chromium"] = 0.0
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(
            any(
                "chromium" in r and "plausibility floor" in r
                for r in verdict["reasons"]
            ),
            verdict["reasons"],
        )

    def test_unmeasurable_on_both_sides_passes(self):
        # A package both binaries dispatch unmeasurably fast measured
        # nothing on either side: the clamped ratio is 1.0 and the
        # plausibility rule stays silent (its baseline is equally
        # unmeasurable).
        base = {"tiny": 0.0, "bash": 1.0}
        candidate = {"tiny": 0.0, "bash": 1.0}
        verdict = ab.compute_verdict(base, candidate, (base, base))
        self.assertEqual(verdict["verdict"], "pass")

    def test_candidate_median_below_plausibility_floor_fails(self):
        candidate = dict(BASE)
        candidate["bash"] = 0.0005
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(
            any(
                "bash" in r and "plausibility floor" in r
                for r in verdict["reasons"]
            )
        )

    def test_candidate_median_above_plausibility_floor_can_pass(self):
        candidate = dict(BASE)
        candidate["git"] = 0.02
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "pass")

    def test_no_baseline(self):
        verdict = ab.compute_verdict(None, None)
        self.assertEqual(verdict["verdict"], "no-baseline")

    def test_unpaired_package_fails(self):
        candidate = dict(BASE)
        del candidate["vim"]
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("vim" in r for r in verdict["reasons"]))

    def test_missing_calibration_fails(self):
        verdict = ab.compute_verdict(BASE, scaled(BASE, 1.01), None)
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any("calibration" in r for r in verdict["reasons"]))

    def test_zero_baseline_median_is_finite(self):
        base = {"tiny": 0.0, "bash": 1.0}
        verdict = ab.compute_verdict(base, dict(base), (base, base))
        self.assertEqual(verdict["verdict"], "pass")
        # Both sides unmeasurably fast: the clamped ratio is exactly 1.
        self.assertEqual(verdict["package_ratios"]["tiny"], 1.0)

    def test_synthetic_timing_json(self):
        # The verdict computed from a timings document, as parsed from
        # the JSON shape a timing harness would record.
        timings = json.loads(
            """
            {
              "baseline": {"a": 1.0, "b": 2.0, "c": 4.0},
              "candidate": {"a": 1.0, "b": 2.0, "c": 4.0},
              "aa": [{"a": 1.0, "b": 2.0, "c": 4.0},
                     {"a": 1.01, "b": 1.98, "c": 4.02}]
            }
            """
        )
        verdict = ab.compute_verdict(
            timings["baseline"],
            timings["candidate"],
            (timings["aa"][0], timings["aa"][1]),
        )
        self.assertEqual(verdict["verdict"], "pass")
        self.assertAlmostEqual(verdict["geomean_ratio"], 1.0, places=3)


class TimingTests(unittest.TestCase):
    def write_binary(self, directory, name, package_action):
        path = pathlib.Path(directory) / name
        path.write_text(
            chr(10).join(
                [
                    "#!/bin/sh",
                    'if [ "$1" = "--version" ]; then',
                    "    echo 'fake 1.0'",
                    "    exit 0",
                    "fi",
                    package_action,
                    "",
                ]
            )
        )
        path.chmod(
            path.stat().st_mode
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
        return path

    def run_gate(self, directory, baseline, candidate, extra=()):
        rpm = pathlib.Path(directory) / "pkg.rpm"
        rpm.write_bytes(b"fake rpm")
        stdout = io.StringIO()
        args = [
            "--rpms-dir",
            str(directory),
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--rounds",
            "1",
            "--aa-rounds",
            "1",
            *extra,
        ]
        with contextlib.redirect_stdout(stdout):
            rc = ab.main(args)
        return rc, json.loads(stdout.getvalue())

    def fake_gate(self, directory, candidate_action, extra=()):
        baseline = self.write_binary(directory, "baseline", "exit 64")
        candidate = self.write_binary(
            directory, "candidate", candidate_action
        )
        return self.run_gate(directory, baseline, candidate, extra)

    def test_crashing_candidate_fails_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, out = self.fake_gate(directory, "exit 1")
        self.assertEqual(rc, 1)
        self.assertEqual(out["verdict"], "fail")
        self.assertTrue(
            any(
                "candidate" in r and "exited with status 1" in r
                for r in out["reasons"]
            )
        )

    def test_candidate_killed_by_signal_fails_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, out = self.fake_gate(directory, "kill -11 $$")
        self.assertEqual(rc, 1)
        self.assertEqual(out["verdict"], "fail")
        self.assertTrue(
            any("died from signal 11" in r for r in out["reasons"])
        )

    def test_candidate_timeout_fails_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, out = self.fake_gate(
                directory, "sleep 2", ("--run-timeout", "0.05")
            )
        self.assertEqual(rc, 1)
        self.assertEqual(out["verdict"], "fail")
        self.assertTrue(
            any("timed out after 0.05s" in r for r in out["reasons"])
        )

    def test_time_binary_accepts_completed_lint_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            rpm = pathlib.Path(directory) / "pkg.rpm"
            rpm.write_bytes(b"fake rpm")
            for code in (0, 64):
                binary = self.write_binary(
                    directory, f"binary-{code}", f"exit {code}"
                )
                self.assertGreaterEqual(
                    ab.time_binary(str(binary), str(rpm)), 0.0
                )

    def test_baseline_without_rpms_dir_is_a_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                ab.main(
                    ["--candidate", "unused", "--baseline", "also-unused"]
                )
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "--rpms-dir is required when --baseline is supplied",
            stderr.getvalue(),
        )
        self.assertNotIn("Traceback", stderr.getvalue())


class TimingRunTests(unittest.TestCase):
    def _script(self, body):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as f:
            f.write(f"#!{sys.executable}\n{body}")
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.addCleanup(os.unlink, path)
        return path

    @unittest.skipUnless(os.name == "posix", "signal death is POSIX")
    def test_signal_death_fails_closed(self):
        script = self._script(
            "import os, signal\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n"
        )
        with self.assertRaises(ab.TimingRunError) as ctx:
            ab.time_binary(script, "ignored.rpm")
        self.assertIn("died from signal 9", str(ctx.exception))

    def test_timeout_fails_closed(self):
        script = self._script("import time\ntime.sleep(30)\n")
        with self.assertRaises(ab.TimingRunError) as ctx:
            ab.time_binary(script, "ignored.rpm", timeout_s=0.2)
        self.assertIn("timed out after 0.2s", str(ctx.exception))

    def test_disallowed_exit_status_fails_closed(self):
        script = self._script("import sys\nsys.exit(3)\n")
        with self.assertRaises(ab.TimingRunError) as ctx:
            ab.time_binary(script, "ignored.rpm")
        self.assertIn("exited with status 3", str(ctx.exception))


class MedianTests(unittest.TestCase):
    def test_median_odd_and_even(self):
        self.assertEqual(ab.median([3.0, 1.0, 2.0]), 2.0)
        self.assertEqual(ab.median([1.0, 2.0]), 1.5)


if __name__ == "__main__":
    unittest.main()
