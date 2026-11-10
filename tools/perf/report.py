"""Receiver averages and full one-second windows; retain raw iperf JSON."""
import json
import argparse
import math
import os
from pathlib import Path


def receiver_windows(report):
    """Ignore warmup, partial tails and iperf 3.12's malformed -O transition."""
    windows = {}
    for interval in report.get("intervals", []):
        for name, summary in interval.items():
            if not name.startswith("sum") or summary.get("sender", True):
                continue
            duration = summary["seconds"]
            span = summary["end"] - summary["start"]
            if summary.get("omitted") or not 0.9 <= duration <= 1.1:
                continue
            if abs(span - duration) > 0.01:
                continue
            windows.setdefault(name, []).append(summary["bits_per_second"] / 1e6)
    return windows


def main(directory, tcp_only=False):
    minimum = float(os.environ.get("PAYPHONE_PERF_MIN_MBPS", "200"))
    max_loss = float(os.environ.get("PAYPHONE_PERF_MAX_LOSS_PCT", "0.1"))
    if not all(math.isfinite(value) and value >= 0 for value in (minimum, max_loss)):
        raise SystemExit("acceptance thresholds must be finite and nonnegative")
    failed = []
    paths = sorted(directory.glob("*.json"))
    expected_files = {"tcp-bidir.json"}
    if not tcp_only:
        expected_files.update(("udp-upload.json", "udp-download.json"))
    if {path.name for path in paths} != expected_files:
        raise SystemExit("expected reports: " + ", ".join(sorted(expected_files)))
    for path in paths:
        report = json.loads(path.read_text())
        if report.get("error"):
            raise SystemExit(f"{path.name}: {report['error']}")
        print(path.name)
        averages = 0
        for name, summary in report.get("end", {}).items():
            if not name.startswith("sum_received"):
                continue
            averages += 1
            rate = summary["bits_per_second"] / 1e6
            loss = summary.get("lost_percent")
            print(f"  {name}: {rate:.2f} Mbps"
                  + (f", lost {loss:.4f}%" if loss is not None else ""))
            if (not math.isfinite(rate) or rate < minimum
                    or (loss is not None and (not math.isfinite(loss) or loss > max_loss))):
                failed.append(f"{path.name}: {name}")
        expected = 2 if "bidir" in path.name else 1
        if averages != expected:
            failed.append(f"{path.name}: missing receiver average")
        window_sets = 0
        duration = report.get("start", {}).get("test_start", {}).get("duration", 1)
        # One interval can be lost at iperf 3.12's -O transition. Missing
        # further windows means the report cannot substantiate 1s stability.
        required_windows = max(1, round(duration) - 1)
        for side, data in (("client", report),
                           ("server", report.get("server_output_json", {}))):
            for name, rates in receiver_windows(data).items():
                window_sets += 1
                print(f"  {side}/{name}: minimum {min(rates):.2f} Mbps"
                      f" over {len(rates)} full 1s receiver windows")
                if min(rates) < minimum or not all(math.isfinite(rate) for rate in rates):
                    failed.append(f"{path.name}: {side}/{name} 1s minimum")
                if len(rates) < required_windows:
                    failed.append(f"{path.name}: {side}/{name} insufficient 1s coverage")
        if window_sets != expected:
            failed.append(f"{path.name}: missing receiver intervals (use --get-server-output)")
    if failed:
        raise SystemExit("FAIL: " + "; ".join(failed))
    print(f"PASS: receiver averages and full 1s windows >= {minimum:g} Mbps"
          + (" (TCP only)" if tcp_only else f"; UDP loss <= {max_loss:g}%"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tcp-only", action="store_true")
    args = parser.parse_args()
    main(args.directory, args.tcp_only)
