"""Independent literal framing expectations and bounded CLI regressions."""

import io
import json
from pathlib import Path
import socket
import subprocess  # nosec B404: fixed local Python CLI tests, no shell/foreign code.
import sys
import unittest
from unittest.mock import patch

import framing_lab as lab

HERE = Path(__file__).resolve().parents[1]


def envelope(chunks, eof=True):
    return json.dumps({"profile": lab.PROFILE, "chunks": [c.hex() for c in chunks],
                       "eof": eof}).encode()


def report(wire, eof=True):
    return lab.analyze(envelope([wire[i:i + 4096] for i in range(0, len(wire), 4096)], eof))


def semantic(value):
    return {k: v for k, v in value.items() if k != "trace"}


class FramingTests(unittest.TestCase):
    def test_literal_records_and_offsets(self):
        result = report(b"\x00\x00\x00\x03ABC\x00\x00\x00\x00")
        self.assertEqual(result["frames"], [
            {"index": 0, "start": 0, "end": 7, "length": 3, "payload_hex": "414243"},
            {"index": 1, "start": 7, "end": 11, "length": 0, "payload_hex": ""}])
        self.assertEqual(result["state"], "closed")
        self.assertEqual(result["accepted_payload_bytes"], 3)
        self.assertEqual(result["consumed_bytes"], 11)

    def test_every_partition_of_nine_bytes(self):
        wire = b"\x00\x00\x00\x01A\x00\x00\x00\x00"
        expected = semantic(report(wire))
        for mask in range(256):
            cuts = [0] + [i for i in range(1, 9) if mask & (1 << (i - 1))] + [9]
            chunks = [wire[a:b] for a, b in zip(cuts, cuts[1:])]
            self.assertEqual(semantic(lab.analyze(envelope(chunks))), expected, mask)

    def test_failed_stream_partitions(self):
        wire = b"\x00\x00\x00\x01A\x00\x00\x10\x01tail"
        expected = semantic(report(wire))
        for cut in range(len(wire) + 1):
            self.assertEqual(semantic(lab.analyze(envelope([wire[:cut], wire[cut:]]))), expected)
        self.assertEqual(semantic(lab.analyze(envelope([bytes([c]) for c in wire]))), expected)
        self.assertEqual(expected["failure"], {"code": "frame_length_limit", "frame_start": 5,
                         "detected_at": 9, "pending_header_bytes": 4, "pending_payload_bytes": 0,
                         "reserved_payload_bytes": 0, "declared_length": 4097})
        self.assertEqual(expected["ignored_bytes"], 4)
        self.assertEqual(len(expected["frames"]), 1)

    def test_same_chunk_suffix_and_later_chunk(self):
        result = lab.analyze(envelope([b"\xff\xff\xff\xfftail", b"next"]))
        self.assertEqual(result["consumed_bytes"], 4)
        self.assertEqual(result["ignored_bytes"], 8)
        self.assertEqual([t["ignored_bytes"] for t in result["trace"]], [4, 4])
        self.assertEqual(result["failure"]["declared_length"], 4294967295)
        self.assertEqual(result["buffered_header_bytes"], 0)
        self.assertEqual(result["reserved_payload_bytes"], 0)

    def test_empty_and_open_idle(self):
        for chunks in ([], [b""], [b"", b""]):
            self.assertEqual(lab.analyze(envelope(chunks))["state"], "closed")
            self.assertEqual(lab.analyze(envelope(chunks, False))["state"], "open_idle")

    def test_partial_header_eof_and_open(self):
        for n in (1, 2, 3):
            wire = b"\x00" * n
            closed = report(wire)
            self.assertEqual(closed["failure"]["code"], "truncated_header")
            self.assertEqual(closed["failure"]["pending_header_bytes"], n)
            self.assertEqual(closed["failure"]["detected_at"], n)
            self.assertIsNone(closed["failure"]["declared_length"])
            opened = report(wire, False)
            self.assertEqual(opened["state"], "need_header")
            self.assertEqual(opened["remaining_bytes"], 4 - n)

    def test_partial_payload_accounting_and_eof(self):
        wire = b"\x00\x00\x00\x03A"
        opened = report(wire, False)
        self.assertEqual((opened["accepted_payload_bytes"], opened["reserved_payload_bytes"],
                          opened["buffered_payload_bytes"], opened["remaining_bytes"]), (0, 3, 1, 2))
        closed = report(wire)
        self.assertEqual(closed["failure"], {"code": "truncated_payload", "frame_start": 0,
                         "detected_at": 5, "pending_header_bytes": 4, "pending_payload_bytes": 1,
                         "reserved_payload_bytes": 3, "declared_length": 3})
        self.assertEqual(closed["accepted_payload_bytes"], 0)
        self.assertEqual(closed["ignored_bytes"], 0)
        self.assertEqual(closed["buffered_payload_bytes"], 0)

    def test_partial_eof_partition_invariance(self):
        prefix = b"\x00\x00\x00\x01A"
        for tail in (b"\x00\x00", b"\x00\x00\x00\x03B"):
            wire = prefix + tail
            expected = semantic(report(wire))
            self.assertEqual(expected["failure"]["frame_start"], 5)
            self.assertEqual(len(expected["frames"]), 1)
            for cut in range(len(wire) + 1):
                self.assertEqual(semantic(lab.analyze(envelope([wire[:cut], wire[cut:]]))), expected)
            self.assertEqual(semantic(lab.analyze(envelope([bytes([c]) for c in wire]))), expected)

    def test_frame_length_exact_and_one_past(self):
        exact = report(b"\x00\x00\x10\x00" + b"A" * 4096)
        self.assertEqual(exact["frames"][0]["length"], 4096)
        rejected = report(b"\x00\x00\x10\x01")
        self.assertEqual(rejected["failure"]["code"], "frame_length_limit")
        self.assertEqual(rejected["failure"]["reserved_payload_bytes"], 0)

    def test_frame_count_zero_length_and_order(self):
        self.assertEqual(len(report(b"\x00" * 256)["frames"]), 64)
        rejected = report(b"\x00" * 256 + b"\xff\xff\xff\xfftail")
        self.assertEqual(len(rejected["frames"]), 64)
        self.assertEqual(rejected["failure"]["code"], "frame_limit")
        self.assertEqual(rejected["failure"]["frame_start"], 256)
        self.assertEqual(rejected["ignored_bytes"], 4)

    def test_aggregate_exact_transfer_and_early_reservation(self):
        frame = b"\x00\x00\x10\x00" + b"A" * 4096
        exact = report(frame * 4)
        self.assertEqual(exact["accepted_payload_bytes"], 16384)
        self.assertEqual(exact["reserved_payload_bytes"], 0)
        rejected = report(frame * 4 + b"\x00\x00\x00\x01A")
        self.assertEqual(rejected["failure"]["code"], "aggregate_payload_limit")
        self.assertEqual(rejected["consumed_bytes"], 16404)
        self.assertEqual(rejected["ignored_bytes"], 1)
        zero = report(frame * 4 + b"\x00\x00\x00\x00")
        self.assertEqual(len(zero["frames"]), 5)

    def test_terminal_stickiness(self):
        decoder = lab._Decoder()
        decoder.feed(b"\xff\xff\xff\xff")
        before = (decoder.failure.copy(), decoder.snapshot(), decoder.consumed)
        self.assertEqual(decoder.feed(b"\x00" * 4), "rejected_failed")
        decoder.finish()
        self.assertEqual((decoder.failure, decoder.snapshot(), decoder.consumed), before)
        closed = lab._Decoder()
        closed.finish()
        self.assertEqual(closed.feed(b"anything"), "rejected_closed")
        closed.finish()
        self.assertEqual(closed.consumed, 0)
        self.assertEqual(closed.snapshot()["state"], "closed")

    def test_carry_bounds_large_split_frame(self):
        decoder = lab._Decoder()
        wire = b"\x00\x00\x10\x00" + b"A" * 4096
        for c in wire:
            decoder.feed(bytes([c]))
            self.assertLessEqual(len(decoder.header), 4)
            self.assertLessEqual(len(decoder.payload), 4096)
        self.assertEqual(decoder.accepted, 4096)
        self.assertEqual(len(decoder.payload), 0)

    def test_hex_inertness_and_uppercase(self):
        result = lab.analyze(b'{"profile":"u32be-records-v1","chunks":["000000031B00FF"],"eof":true}')
        self.assertEqual(result["frames"][0]["payload_hex"], "1b00ff")
        self.assertNotIn(b"\x1b", lab._encode(result))

    def test_invalid_hex_fields_and_types(self):
        for value in ("0", "0x00", "00 00", "\n", "ＦＦ", 0, False, None, [], {}):
            root = {"profile": lab.PROFILE, "chunks": [value], "eof": True}
            with self.subTest(value=value), self.assertRaises(lab.LabError):
                lab.analyze(json.dumps(root).encode())
        for root in ({}, [], {"profile": lab.PROFILE, "chunks": [], "eof": 1},
                     {"profile": "other", "chunks": [], "eof": True},
                     {"profile": lab.PROFILE, "chunks": "", "eof": True},
                     {"profile": lab.PROFILE, "chunks": [], "eof": True, "x": 1}):
            with self.assertRaises(lab.LabError):
                lab.analyze(json.dumps(root).encode())

    def test_admission_precedes_failure(self):
        with patch.object(lab._Decoder, "feed", side_effect=AssertionError("simulation started")):
            for bad in ("0", "g0", "00 " * 5):
                with self.assertRaises(lab.LabError):
                    lab.analyze(json.dumps({"profile": lab.PROFILE, "chunks": ["ffffffff", bad], "eof": True}).encode())

    def test_exact_bytes_no_coercion(self):
        class Foreign:
            def __bytes__(self):
                raise AssertionError("coercion invoked")
        class Derived(bytes):
            pass
        for value in (bytearray(b"{}"), "{}", Foreign(), Derived(b"{}"), None):
            with self.assertRaises(lab.LabError):
                lab.analyze(value)

    def test_json_grammar_unicode_duplicate_and_numbers(self):
        for raw in (b"", b"\xff", b'{"chunks":[],"chunks":[]}',
                    b'{"chunks":[],"ch\\u0075nks":[]}', b'{"x":"\\ud800"}',
                    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}',
                    b'{"x":12345678901}', b"[" * 7 + b"]" * 7,
                    b'{"x":"' + b"a" * 8193 + b'"}', b'{"x":1,}',
                    b'{"x":"unterminated}', b'{}{}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(lab.LabError):
                lab.analyze(raw)

    def test_admission_budget_boundaries(self):
        base = envelope([])
        self.assertEqual(lab.analyze(base + b" " * (lab.MAX_INPUT - len(base)))["state"], "closed")
        with self.assertRaises(lab.LabError):
            lab.analyze(base + b" " * (lab.MAX_INPUT + 1 - len(base)))
        self.assertEqual(len(lab.analyze(envelope([b""] * 256))["trace"]), 256)
        for chunks in ([b""] * 257, [b"A" * 4097], [b"A" * 4096] * 16 + [b"A"]):
            with self.assertRaises(lab.LabError):
                lab.analyze(envelope(chunks))
        # Full supplied budget is admitted, then fails framing, rather than admission.
        self.assertEqual(lab.analyze(envelope([b"\xff" * 4096] * 16))["supplied_bytes"], 65536)

    def test_no_network_or_process_capability(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(report(b"\x00" * 4)["state"], "closed")

    def test_output_guard_narrow_seam(self):
        with patch.object(lab, "MAX_OUTPUT", 1), self.assertRaises(lab.LabError):
            report(b"")

    def test_independent_examples(self):
        expectations = {"split": ("closed", None, 2), "coalesced": ("closed", None, 2),
                        "partial-header": ("failed", "truncated_header", 0),
                        "partial-payload": ("failed", "truncated_payload", 0),
                        "prefix-failure": ("failed", "frame_length_limit", 1),
                        "open": ("need_payload", None, 0), "empty": ("closed", None, 0)}
        for name, expected in expectations.items():
            value = lab.analyze((HERE / "examples" / (name + ".json")).read_bytes())
            self.assertEqual((value["state"], value["failure"]["code"] if value["failure"] else None,
                              len(value["frames"])), expected)


class CliTests(unittest.TestCase):
    def run_cli(self, data):
        flags = ["-O"] if sys.flags.optimize else []
        return subprocess.run([sys.executable, *flags, str(HERE / "framing_lab.py"), "-"],
                              input=data, capture_output=True, timeout=10)  # nosec B603: fixed owned CLI, synthetic stdin.

    def test_cli_statuses(self):
        for data, status in ((envelope([]), 0), (envelope([b"\x00"]), 3), (b"{}", 2)):
            child = self.run_cli(data)
            self.assertEqual(child.returncode, status)
            if status == 2:
                self.assertEqual(child.stdout, b"")
            else:
                self.assertEqual(json.loads(child.stdout)["profile"], lab.PROFILE)

    def test_cli_file_and_missing_file(self):
        flags = ["-O"] if sys.flags.optimize else []
        for path, status in ((HERE / "examples" / "empty.json", 0), (HERE / "absent.json", 2)):
            child = subprocess.run([sys.executable, *flags, str(HERE / "framing_lab.py"), str(path)],
                                   capture_output=True, timeout=10)  # nosec B603: fixed local fixture paths.
            self.assertEqual(child.returncode, status)

    def test_short_write_and_flush(self):
        class Sink:
            def __init__(self, mode):
                self.mode = mode
            def write(self, data):
                return len(data) - 1 if self.mode == "short" else len(data)
            def flush(self):
                if self.mode == "flush":
                    raise OSError("synthetic flush")
        class Wrapper:
            def __init__(self, buffer):
                self.buffer = buffer
        for mode in ("short", "flush"):
            with patch.object(sys, "stdout", Wrapper(Sink(mode))), \
                 patch.object(sys, "stdin", Wrapper(io.BytesIO(envelope([])))), \
                 patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(lab.main(["-"]), 2)
                self.assertIsNone(sys.stdout)

    def test_actual_closed_receiving_pipe(self):
        flags = ["-O"] if sys.flags.optimize else []
        child = subprocess.Popen([sys.executable, *flags, str(HERE / "framing_lab.py"), "-"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)  # nosec B603: fixed owned CLI, no shell.
        try:
            child.stdout.close()
            child.stdin.write(envelope([]))
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 2)
            self.assertNotIn(b"Exception ignored", child.stderr.read())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stderr.close()

    def test_closed_diagnostic_after_delivery_failure(self):
        class Sink:
            def write(self, data):
                return 0
        class Diagnostic:
            def write(self, text):
                raise OSError("diagnostic pipe closed")
        class Wrapper:
            def __init__(self, buffer):
                self.buffer = buffer
        with patch.object(sys, "stdout", Wrapper(Sink())), \
             patch.object(sys, "stdin", Wrapper(io.BytesIO(envelope([])))), \
             patch.object(sys, "stderr", Diagnostic()):
            self.assertEqual(lab.main(["-"]), 2)
            self.assertIsNone(sys.stderr)

    def test_both_receiving_pipes_closed(self):
        flags = ["-O"] if sys.flags.optimize else []
        child = subprocess.Popen([sys.executable, *flags, str(HERE / "framing_lab.py"), "-"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)  # nosec B603: fixed owned CLI, synthetic stdin.
        try:
            child.stdout.close()
            child.stderr.close()
            child.stdin.write(envelope([]))
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 2)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
