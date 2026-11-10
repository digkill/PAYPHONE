"""Regression checks for throughput acceptance, with no network dependencies."""
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from report import main, receiver_windows


def interval(start, end, duration, rate, **extra):
    return {"sum": {"start": start, "end": end, "seconds": duration,
                    "bits_per_second": rate * 1e6, "sender": False, **extra}}


class ReceiverReportTests(unittest.TestCase):
    def test_keeps_real_zero_and_rejects_warmup_and_malformed_transition(self):
        report = {"intervals": [
            interval(0, 1, 1, 300, omitted=True),
            interval(1.000484, 1.000085, 2.000569, 150),
            interval(1, 2, 1, 0),
            interval(2, 3, 1, 300),
            interval(3, 3.2, 0.2, 300),
        ]}
        self.assertEqual(receiver_windows(report), {"sum": [0, 300]})

    def test_checks_upload_receiver_on_server_and_loss(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tcp = {"end": {"sum_received": {"bits_per_second": 300e6},
                           "sum_received_bidir_reverse": {"bits_per_second": 300e6}},
                   "intervals": [interval(0, 1, 1, 300)],
                   "server_output_json": {"intervals": [interval(0, 1, 1, 300)]}}
            udp = {"end": {"sum_received": {"bits_per_second": 300e6, "lost_percent": 0}},
                   "intervals": [interval(0, 1, 1, 300)]}
            reports = {"tcp-bidir.json": tcp, "udp-upload.json": udp,
                       "udp-download.json": copy.deepcopy(udp)}
            def write():
                for name, data in reports.items():
                    (root / name).write_text(json.dumps(data))
            with patch.dict(os.environ, {"PAYPHONE_PERF_MIN_MBPS": "200",
                                         "PAYPHONE_PERF_MAX_LOSS_PCT": "0.1"}), \
                    contextlib.redirect_stdout(io.StringIO()):
                write()
                main(root)
                tcp["server_output_json"]["intervals"] = [interval(0, 1, 1, 0)]
                write()
                with self.assertRaisesRegex(SystemExit, "server/sum 1s minimum"):
                    main(root)
                tcp["server_output_json"]["intervals"] = [interval(0, 1, 1, 300)]
                udp["end"]["sum_received"]["lost_percent"] = 1
                write()
                with self.assertRaisesRegex(SystemExit, "udp-upload.json: sum_received"):
                    main(root)
                udp["end"]["sum_received"]["lost_percent"] = 0
                tcp["start"] = {"test_start": {"duration": 30}}
                write()
                with self.assertRaisesRegex(SystemExit, "insufficient 1s coverage"):
                    main(root)
                tcp["start"]["test_start"]["duration"] = 1
                (root / "tcp-bidir.json").write_text(json.dumps(tcp))
                for path in root.glob("udp-*.json"):
                    path.unlink()
                main(root, tcp_only=True)
                with self.assertRaisesRegex(SystemExit, "expected reports"):
                    main(root)


if __name__ == "__main__":
    unittest.main()
