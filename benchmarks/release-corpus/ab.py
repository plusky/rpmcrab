#!/usr/bin/env python3
# A/B regression gate for the release corpus benchmark.
#
# Times two rpmcrab binaries (baseline, candidate) over the pinned release
# corpus, interleaved per package, and renders a pass/fail verdict:
#
#   * the geomean of the per-package median ratios (candidate / baseline)
#     is compared against the noise the same computation measures on an
#     A/A calibration pair (the baseline timed against itself);
#   * a single package that more than doubles while also costing at least
#     PACKAGE_MIN_DELTA_S extra seconds fails on its own.
#
# bench.sh drives this script. test-ab.py exercises compute_verdict with
# synthetic timing data.

import argparse
import datetime
import glob
import json
import math
import os
import platform
import subprocess
import sys
import time

GEOMEAN_MAX = 1.10
AA_SPREAD_MULTIPLIER = 3.0
PACKAGE_RATIO_MAX = 2.0
PACKAGE_MIN_DELTA_S = 0.25
# Ratio inputs clamp to the timer's useful resolution on both sides, so a
# package whose medians round to zero gets a finite ratio (1.0 when both
# sides are unmeasurably fast); the per-package rule judges such packages
# by their absolute delta.
TIME_FLOOR_S = 0.001


def median(values):
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def geomean(values):
    return math.exp(sum(math.log(v) for v in values) / len(values))


def package_ratios(baseline, candidate):
    """Per-package candidate/baseline ratios over the shared package set."""
    return {
        name: max(candidate[name], TIME_FLOOR_S)
        / max(baseline[name], TIME_FLOOR_S)
        for name in baseline
        if name in candidate
    }


def compute_verdict(baseline, candidate, aa_pair=None):
    """Render the gate verdict from per-package median seconds.

    baseline/candidate map package name -> median seconds. aa_pair is a
    (first, second) pair of median maps for the baseline binary timed
    against itself. With baseline None the verdict is "no-baseline".
    Every reason collected fails the gate: the verdict is "pass" only
    when the reasons list is empty.
    """
    result = {
        "verdict": "pass",
        "reasons": [],
        "geomean_ratio": None,
        "aa_geomean_ratio": None,
        "aa_spread": None,
        "package_ratios": {},
    }
    if baseline is None:
        result["verdict"] = "no-baseline"
        result["reasons"].append(
            "no baseline binary supplied; the gate has nothing to compare against"
        )
        return result

    unpaired = sorted(set(baseline) ^ set(candidate))
    if unpaired:
        result["reasons"].append(
            "packages timed on one side only: " + ", ".join(unpaired)
        )
    shared = sorted(set(baseline) & set(candidate))
    if not shared:
        result["reasons"].append("no package was timed on both sides")

    if shared:
        ratios = package_ratios(baseline, candidate)
        result["package_ratios"] = {n: round(ratios[n], 4) for n in shared}
        geo = geomean([ratios[n] for n in shared])
        result["geomean_ratio"] = round(geo, 4)

        aa_spread = None
        if aa_pair is None:
            result["reasons"].append("A/A calibration pair missing")
        else:
            aa_first, aa_second = aa_pair
            aa_shared = sorted(set(aa_first) & set(aa_second))
            if not aa_shared:
                result["reasons"].append("A/A calibration timed no packages")
            else:
                aa_geo = geomean(
                    [
                        max(aa_second[n], TIME_FLOOR_S)
                        / max(aa_first[n], TIME_FLOOR_S)
                        for n in aa_shared
                    ]
                )
                result["aa_geomean_ratio"] = round(aa_geo, 4)
                aa_spread = abs(aa_geo - 1.0)
                result["aa_spread"] = round(aa_spread, 4)

        if aa_spread is not None:
            excess = geo - 1.0
            if (
                excess > GEOMEAN_MAX - 1.0
                and excess > AA_SPREAD_MULTIPLIER * aa_spread
            ):
                result["reasons"].append(
                    f"geomean ratio {geo:.3f}: slowdown {excess:.3f} exceeds "
                    f"{GEOMEAN_MAX - 1.0:.2f} and {AA_SPREAD_MULTIPLIER:g}x "
                    f"the A/A spread {aa_spread:.4f}"
                )
        for name in shared:
            delta = candidate[name] - baseline[name]
            if ratios[name] > PACKAGE_RATIO_MAX and delta >= PACKAGE_MIN_DELTA_S:
                result["reasons"].append(
                    f"{name}: ratio {ratios[name]:.2f} with median delta "
                    f"{delta:.3f}s (>= {PACKAGE_MIN_DELTA_S:g}s floor)"
                )
    if result["reasons"]:
        result["verdict"] = "fail"
    return result


def binary_version(binary):
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=60
        )
    except OSError as e:
        raise SystemExit(f"ab.py: cannot execute {binary}: {e}")
    if out.returncode != 0:
        raise SystemExit(
            f"ab.py: {binary} --version failed: {out.stderr.strip()}"
        )
    return out.stdout.strip()


def time_binary(binary, rpm_path):
    # rpmcrab exits nonzero when findings exist; that is not a timing
    # failure, so the exit code is ignored exactly as in bench.sh's
    # single-binary mode.
    start = time.perf_counter()
    subprocess.run(
        [binary, rpm_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return time.perf_counter() - start


def time_pair(rpms, first, second, rounds, label):
    """Interleave two binaries over every RPM for `rounds` paired rounds.

    rpms is a list of (name, path). Even rounds run first-then-second and
    odd rounds swap, so steady drift during a pass lands on both sides.
    Returns (first_samples, second_samples): package name -> [seconds].
    """
    first_samples = {name: [] for name, _ in rpms}
    second_samples = {name: [] for name, _ in rpms}
    for rnd in range(rounds):
        t0 = time.perf_counter()
        for name, path in rpms:
            order = ((first, first_samples), (second, second_samples))
            if rnd % 2:
                order = (order[1], order[0])
            for binary, samples in order:
                samples[name].append(time_binary(binary, path))
        print(
            f"{label} round {rnd + 1}/{rounds}: "
            f"{time.perf_counter() - t0:.1f}s",
            file=sys.stderr,
        )
    return first_samples, second_samples


def medians(samples):
    return {name: median(vals) for name, vals in samples.items()}


def cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="A/B regression gate over the release corpus."
    )
    ap.add_argument("--rpms-dir", help="verified corpus directory")
    ap.add_argument("--candidate", required=True, help="candidate binary")
    ap.add_argument("--baseline", help="baseline binary")
    ap.add_argument("--baseline-tag", default="", help="baseline release tag")
    ap.add_argument("--rounds", type=int, default=5, help="A/B paired rounds")
    ap.add_argument(
        "--aa-rounds", type=int, default=3, help="A/A calibration paired rounds"
    )
    ap.add_argument(
        "--no-baseline",
        action="store_true",
        help="emit a no-baseline verdict without timing anything",
    )
    args = ap.parse_args(argv)
    if args.rounds < 1 or args.aa_rounds < 1:
        raise SystemExit("ab.py: --rounds and --aa-rounds must be >= 1")

    candidate_version = binary_version(args.candidate)
    out = {
        "benchmark": "release-corpus-ab",
        "date": datetime.date.today().isoformat(),
        "candidate": {"bin": args.candidate, "version": candidate_version},
        "baseline": None,
        "rounds": args.rounds,
        "aa_rounds": args.aa_rounds,
        "thresholds": {
            "geomean_max": GEOMEAN_MAX,
            "aa_spread_multiplier": AA_SPREAD_MULTIPLIER,
            "package_ratio_max": PACKAGE_RATIO_MAX,
            "package_min_delta_s": PACKAGE_MIN_DELTA_S,
        },
        "runner": {
            "os": f"{platform.system()} {platform.release()}",
            "cpu": cpu_model(),
            "ncpus": os.cpu_count(),
        },
    }

    if args.no_baseline or not args.baseline:
        verdict = compute_verdict(None, None)
        out.update(verdict)
        print(json.dumps(out, indent=2))
        return 0

    baseline_version = binary_version(args.baseline)
    out["baseline"] = {
        "bin": args.baseline,
        "version": baseline_version,
        "tag": args.baseline_tag,
    }

    rpm_files = sorted(glob.glob(os.path.join(args.rpms_dir, "*.rpm")))
    if not rpm_files:
        raise SystemExit(f"ab.py: no RPMs in {args.rpms_dir}")
    rpms = [(os.path.basename(p)[: -len(".rpm")], p) for p in rpm_files]
    total_mb = sum(os.path.getsize(p) for _, p in rpms) / 1024 / 1024
    out["corpus"] = {
        "manifest": "benchmarks/release-corpus/manifest.toml",
        "rpms": len(rpms),
        "total_mb": round(total_mb, 1),
    }

    try:
        # One untimed run per binary on the first package, so one-time
        # costs (binary page-in, shared-library warm-up) land outside the
        # samples.
        for binary in (args.baseline, args.candidate):
            time_binary(binary, rpms[0][1])
        base_s, cand_s = time_pair(
            rpms, args.baseline, args.candidate, args.rounds, "A/B"
        )
        aa1_s, aa2_s = time_pair(
            rpms, args.baseline, args.baseline, args.aa_rounds, "A/A"
        )
    except OSError as e:
        raise SystemExit(f"ab.py: timing run failed: {e}")

    base_med = medians(base_s)
    cand_med = medians(cand_s)
    aa_med = (medians(aa1_s), medians(aa2_s))
    verdict = compute_verdict(base_med, cand_med, aa_med)
    out.update(verdict)
    out["packages"] = [
        {
            "package": name,
            "baseline_median_s": round(base_med[name], 3),
            "candidate_median_s": round(cand_med[name], 3),
            "ratio": verdict["package_ratios"][name],
        }
        for name in sorted(base_med)
    ]
    print(json.dumps(out, indent=2))
    return 0 if verdict["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
