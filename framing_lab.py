"""Bounded invented-byte incremental record framing; contract in SCHEMA.md."""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys

PROFILE = "u32be-records-v1"
MAX_INPUT = 262144
MAX_OUTPUT = 262144
MAX_FRAME = 4096
MAX_FRAMES = 64
MAX_PAYLOAD = 16384
MAX_SUPPLIED = 65536


class LabError(ValueError):
    """Invalid input representation or failed report delivery."""


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise LabError("duplicate JSON key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > 10:
        raise LabError("numeric token exceeds 10 characters")
    return int(token)


def _noninteger(token: str) -> None:
    raise LabError("non-integer numbers/constants unsupported")


def _strings(value: object) -> None:
    if isinstance(value, str):
        if len(value) > 8192 or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise LabError("string exceeds bound or contains surrogate")
    elif isinstance(value, dict):
        for key, child in value.items():
            _strings(key)
            _strings(child)
    elif isinstance(value, list):
        for child in value:
            _strings(child)


def _load(data: bytes) -> object:
    # Adapted from Jake's MIT DNS/route labs. Preflight bounds nesting only;
    # json.loads remains the syntax authority, including bracket/escape grammar.
    if type(data) is not bytes or len(data) > MAX_INPUT:
        raise LabError("input must be exact bytes within 262144 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LabError("input must be UTF-8") from exc
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 6:
                raise LabError("JSON nesting exceeds 6")
        elif char in "]}":
            depth -= 1
    try:
        root = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_noninteger, parse_constant=_noninteger)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LabError("invalid JSON") from exc
    _strings(root)
    return root


def _validate(root: object) -> tuple[list[bytes], bool]:
    if type(root) is not dict or set(root) != {"profile", "chunks", "eof"}:
        raise LabError("invalid, unknown or missing fields")
    if type(root["profile"]) is not str or root["profile"] != PROFILE:
        raise LabError("unknown profile")
    if type(root["eof"]) is not bool:
        raise LabError("eof must be boolean")
    if type(root["chunks"]) is not list or len(root["chunks"]) > 256:
        raise LabError("chunks must be an array within 256 entries")
    chunks, total = [], 0
    for value in root["chunks"]:
        if type(value) is not str or len(value) > 8192 or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value):
            raise LabError("chunk must be strict hex within 4096 bytes")
        total += len(value) // 2
        if total > MAX_SUPPLIED:
            raise LabError("supplied bytes exceed 65536")
        chunks.append(bytes.fromhex(value))
    return chunks, root["eof"]


class _Decoder:
    """Internal bounded state machine; callers supply already-admitted chunks."""

    def __init__(self) -> None:
        self.header = bytearray()
        self.payload = bytearray()
        self.declared = None
        self.start = 0
        self.consumed = 0
        self.accepted = 0
        self.frames = []
        self.failure = None
        self.terminal = None

    def snapshot(self) -> dict:
        if self.terminal:
            state, remaining = self.terminal, 0
        elif self.declared is not None:
            state, remaining = "need_payload", self.declared - len(self.payload)
        elif self.header:
            state, remaining = "need_header", 4 - len(self.header)
        else:
            state, remaining = "open_idle", 0
        return {"state": state, "accepted_frames": len(self.frames),
                "accepted_payload_bytes": self.accepted,
                "reserved_payload_bytes": self.declared if self.declared is not None else 0,
                "buffered_header_bytes": len(self.header),
                "buffered_payload_bytes": len(self.payload), "remaining_bytes": remaining}

    def _fail(self, code: str) -> None:
        # Preserve pending evidence before clearing storage; never overwrite it.
        self.failure = {"code": code, "frame_start": self.start,
                        "detected_at": self.consumed,
                        "pending_header_bytes": len(self.header),
                        "pending_payload_bytes": len(self.payload),
                        "reserved_payload_bytes": self.declared if self.declared is not None else 0,
                        "declared_length": self.declared}
        self.header.clear()
        self.payload.clear()
        self.declared = None
        self.terminal = "failed"

    def _complete(self) -> None:
        self.frames.append({"index": len(self.frames), "start": self.start,
                            "end": self.consumed, "length": self.declared,
                            "payload_hex": self.payload.hex()})
        self.accepted += self.declared
        self.declared = None
        self.header.clear()
        self.payload.clear()

    def feed(self, chunk: bytes) -> str:
        if self.terminal:
            return "rejected_" + self.terminal
        cursor = 0
        while cursor < len(chunk) and not self.terminal:
            if self.declared is None:
                if not self.header:
                    self.start = self.consumed
                take = min(4 - len(self.header), len(chunk) - cursor)
                self.header.extend(chunk[cursor:cursor + take])
                cursor += take
                self.consumed += take
                if len(self.header) < 4:
                    continue
                length = struct.unpack("!I", self.header)[0]
                # A decoded but rejected length is NOT a reserved declaration.
                code = ("frame_limit" if len(self.frames) >= MAX_FRAMES else
                        "frame_length_limit" if length > MAX_FRAME else
                        "aggregate_payload_limit" if self.accepted + length > MAX_PAYLOAD else None)
                if code:
                    self._fail(code)
                    self.failure["declared_length"] = length
                    continue
                self.declared = length
                if length == 0:
                    self._complete()
                    continue
            take = min(self.declared - len(self.payload), len(chunk) - cursor)
            self.payload.extend(chunk[cursor:cursor + take])
            cursor += take
            self.consumed += take
            if len(self.payload) == self.declared:
                self._complete()
        return "fed"

    def finish(self) -> None:
        if self.terminal:
            return
        if self.declared is not None:
            self._fail("truncated_payload")
        elif self.header:
            self._fail("truncated_header")
        else:
            self.terminal = "closed"


def _encode(report: dict) -> bytes:
    encoded = (json.dumps(report, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT:
        raise LabError("serialized output exceeds 262144 bytes")
    return encoded


def analyze(data: bytes) -> dict:
    """Validate exact UTF-8 JSON bytes and simulate custom record framing.

    Raises LabError for admission/output-limit errors before returning a report.
    A framed-stream failure returns its accepted prefix and preserved first error.
    No network, payload interpretation, process execution or system inspection.
    """
    chunks, eof = _validate(_load(data))
    decoder, trace = _Decoder(), []
    for index, chunk in enumerate(chunks):
        before = decoder.consumed
        decoder.feed(chunk)
        used = decoder.consumed - before
        trace.append({"chunk_index": index, "chunk_bytes": len(chunk),
                      "consumed_bytes": used, "ignored_bytes": len(chunk) - used,
                      **decoder.snapshot()})
    if eof:
        decoder.finish()
    supplied = sum(map(len, chunks))
    state = decoder.snapshot()
    del state["accepted_frames"]
    report = {"profile": PROFILE, **state, "frames": decoder.frames,
              "consumed_bytes": decoder.consumed, "supplied_bytes": supplied,
              "ignored_bytes": supplied - decoder.consumed,
              "failure": decoder.failure, "trace": trace}
    _encode(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="invented-byte JSON file, or - for stdin")
    args = parser.parse_args(argv)
    writing = False
    try:
        if args.scenario == "-":
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
        else:
            with open(args.scenario, "rb") as stream:
                data = stream.read(MAX_INPUT + 1)
        report = analyze(data)
        output = _encode(report)
        writing = True
        if sys.stdout.buffer.write(output) != len(output):
            raise LabError("short output write")
        sys.stdout.buffer.flush()
        return 3 if report["state"] == "failed" else 0
    except (LabError, OSError) as exc:
        if writing:
            # Prevent CPython's shutdown retry from replacing exit 2 with 120.
            sys.stdout = None
        message = str(exc) if isinstance(exc, LabError) else "input/output operation failed"
        try:
            print("framing-lab: " + message, file=sys.stderr)
        except OSError:
            # A second closed sink must not replace the output-failure status.
            sys.stderr = None
            return 2
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
