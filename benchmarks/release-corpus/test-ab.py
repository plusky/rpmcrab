#!/usr/bin/env python3
# Unit tests for the A/B gate's verdict computation (ab.py).
#
# Run: python3 test-ab.py
#
# Every case feeds synthetic per-package median seconds into
# compute_verdict and pins the verdict: the pass case, each gate rule
# tripping on its own, the noise band absorbing a geomean move, the
# no-baseline verdict, and the fail-closed edges (unpaired packages,
# missing calibration, zero-length timings).

import importlib.util
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
        # unmeasurable medians against a baseline that did real work:
        # the gate fails closed instead of passing it as faster.
        candidate = {name: 0.0 for name in BASE}
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(
            any("did no work" in r for r in verdict["reasons"]),
            verdict["reasons"],
        )

    def test_dead_candidate_on_one_package_fails_closed(self):
        candidate = dict(BASE)
        candidate["chromium"] = 0.0
        verdict = ab.compute_verdict(BASE, candidate, (BASE, BASE))
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(
            any(
                "chromium" in r and "did no work" in r
                for r in verdict["reasons"]
            ),
            verdict["reasons"],
        )

    def test_unmeasurable_on_both_sides_passes(self):
        # A package both binaries dispatch unmeasurably fast measured
        # nothing on either side: the clamped ratio is 1.0 and the
        # dead-candidate rule stays silent (its baseline is equally
        # unmeasurable).
        base = {"tiny": 0.0, "bash": 1.0}
        candidate = {"tiny": 0.0, "bash": 1.0}
        verdict = ab.compute_verdict(base, candidate, (base, base))
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
        with self.assertRaises(ab.TimingError):
            ab.time_binary(script, "ignored.rpm")

    def test_timeout_fails_closed(self):
        script = self._script("import time\ntime.sleep(30)\n")
        saved = ab.RUN_TIMEOUT_S
        ab.RUN_TIMEOUT_S = 0.2
        try:
            with self.assertRaises(ab.TimingError):
                ab.time_binary(script, "ignored.rpm")
        finally:
            ab.RUN_TIMEOUT_S = saved

    def test_missing_rpms_dir_with_baseline_exits_cleanly(self):
        # --rpms-dir is optional in argparse but the baseline path
        # dereferences it: direct CLI use without it exits with a
        # clear error instead of crashing.
        with self.assertRaises(SystemExit) as ctx:
            ab.main(
                [
                    "--candidate",
                    sys.executable,
                    "--baseline",
                    sys.executable,
                ]
            )
        self.assertIn("--rpms-dir", str(ctx.exception))


class MedianTests(unittest.TestCase):
    def test_median_odd_and_even(self):
        self.assertEqual(ab.median([3.0, 1.0, 2.0]), 2.0)
        self.assertEqual(ab.median([1.0, 2.0]), 1.5)


if __name__ == "__main__":
    unittest.main()
