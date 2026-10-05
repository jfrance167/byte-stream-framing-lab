# Byte-stream framing lab — proposed plan

Research reviewed October 5, 2026. Tier 3 educational parser project.
**Stages 1–4 APPROVED at the coordinator's October 5 02:20 checkpoint.**
Authorization: Jake's overnight successor delegation, coordinator decision in
`.private/coordination/2026-10-05/SUCCESSORS.md`, 02:01 checkpoint. Sole owner:
existing scanner/DNS/route chat `01a10a3b-a383-7ee2-a193-8afb04ddba29`.
No new scope after October 6, 08:00 Eastern.

## Problem and success

Application records may span supplied byte chunks or share one chunk. A correct
incremental decoder must reconstruct the declared records independently of those
chunk boundaries, detect incomplete EOF and reject resource-exhaustion declarations.
Success means reproducible invented-byte demonstrations and independently fixed
expected results, with explicit partial/failure state and bounded retained data.

Recommend BUILD an original Python 3.11+ standard-library model. Use `struct !I`
for the header and `unittest`; reuse the reviewed DNS/route bounded JSON admission
design with attribution and adapted limits. Twisted is a source/test reference,
not a runtime dependency or copied implementation. No dependency installation.

Alternative: an MTU/header-size arithmetic lab could compare fictional packet sizes
with supplied limits, but would not establish application boundaries or discover a
path MTU. Defer it. Existing PCAP analysis, route selection and JSON canonicalization
answer different questions; preserve them unchanged.

## Frozen proposed contract

Profile `u32be-records-v1` is a custom teaching format: exactly four unsigned
big-endian bytes declare payload length, excluding the header. Payload bytes are
opaque; zero length is valid and consumes four bytes. No magic, checksum, encoding,
delimiter, padding, compression or resynchronization. No TCP/RFC 6587 interoperability
claim, record authenticity or payload safety claim.

Public API: `analyze(data: exact bytes) -> dict`; reject subclasses/foreign objects
without coercion. CLI accepts one bounded JSON input from a file or stdin and writes
one inert JSON report to stdout. Input has exactly `profile`, `chunks`, `eof`.
Profile must match; eof must be a JSON boolean; chunks is an array of zero to 256
strict hexadecimal strings (even length, ASCII 0-9/a-f/A-F, no whitespace/prefix).
Empty chunks are valid. Whole representation validates before any model processing;
a malformed later chunk cannot be hidden by an earlier framing failure.

Limits: raw UTF-8 JSON 256 KiB, nesting depth 6, number token 10 characters,
decoded string 8192 characters; individual decoded chunk 4096 bytes, aggregate
decoded supplied bytes 65536. Reject duplicate decoded keys, nonfinite numbers,
invalid UTF-8/surrogates, unknown fields and wrong exact types. These are admission
errors, distinct from a valid representation containing a bad framed stream.

Model budgets: payload per frame 4096 bytes; at most 64 completed frames; aggregate
accepted/reserved payload 16384 bytes. On each completed header check, in order:
frame count (a prospective 65th frame), per-frame declared length, then aggregate
accepted payload plus this declaration. Reject immediately before retaining its
payload. No allocation or loop proportional to an unchecked u32 declaration.
Carry storage is bounded by four header bytes and 4096 payload bytes; completed
payload retention is bounded by 16384 bytes. Process each chunk with a cursor,
copying only the needed header/payload portion, rather than concatenating the whole
stream. Representation and report storage are additionally bounded; these are
logical storage bounds, not measured hard process RSS/time guarantees.

Internal decoder states: OPEN/header, OPEN/payload, CLOSED, FAILED. Each feed may
produce several frames, an incomplete tail, or the first failure. Completed frames
before failure remain accepted, including earlier frames in that same chunk. The
failed current frame is never accepted. Preserve failure code, wire offset and
pending counts, then clear carry bytes. FAILED is sticky: later supplied chunks are
counted as ignored with no parsing, allocation of payload or recovery. EOF cannot
replace the first failure. Internal feed after CLOSED returns an explicit terminal
rejection without changing retained frames; no reset method is exposed.

EOF true with no pending bytes closes successfully, including an empty stream.
EOF with 1–3 header bytes produces `truncated_header`; a complete admitted header
with insufficient payload produces `truncated_payload`. EOF false leaves an open
state (`open_idle`, `need_header`, or `need_payload`) and reports the exact remaining
byte count; an open idle stream does not establish that the sender has finished.

Report includes profile, state, accepted frame index/start/end wire offsets,
payload length and lowercase hex, accepted totals, pending/expected counts, first
failure, ignored byte count and bounded per-chunk state/count trace. No payload
UTF-8 decoding or terminal rendering. Hex is reversible data, not redaction.
Output including newline capped at 256 KiB before writing; defensive overflow is
an explicit error, no partial success. Status 0 for valid open/closed simulation,
3 for framed-stream failure, 2 for admission/I/O/output failure. Detect short writes,
flush failures and closed-pipe shutdown; diagnostics must not echo payload input.

## Threat model and exclusions

Attacker-controlled JSON, length prefixes, empty-frame floods, partial tails and
control bytes may seek oversized allocation, incorrect boundaries, misleading
success or terminal effects. Mitigations: whole-input bounded admission, prospective
header checks, finite frames/trace, sticky failure and inert hex output. A parser
defect or unsafe downstream use remains possible.

Use invented in-memory bytes only. No sockets, packet captures, live hosts, device
settings, subprocess execution by the application, payload interpretation/execution,
real logs, canonical JSON comparison, TLS, actual stream transport or publication.
Test subprocesses may run this local CLI against invented bytes only. No host
configuration, new chat/scheduler/subagent, repository creation or parent Git edits.

## Stages proposed for approval

1. Freeze SCHEMA and independently hand-encoded examples: split header/payload,
   coalesced records, zero-length, clean/open EOF, partial header/payload, oversized
   header, accepted prefix then failure and ignored suffix. Record fixtures/hashes.
2. Implement strict admission, incremental internal decoder and JSON CLI in thin
   slices; explain header/payload state and the learning goal before implementation.
3. Verify normal and optimized Python runs, CLI statuses and actual broken-output
   behavior. Cover exact bounds and one-past, maximum u32 declaration, empty-frame
   floods, aggregate reservation, invalid-later-input precedence, sticky failure and
   terminal feeds. Independently literal golden headers; all partitions of a small
   nine-byte two-frame fixture, plus bytewise/whole/one-cut larger fixtures. Compare
   accepted records, offsets and first failure across partitions; traces may differ.
   Patch network/process entry points during API checks to catch accidental use.
   Two meaningful mutations: wrong header byte order and acceptance past the
   per-frame limit, detected by assertion failures with source restored afterward.
   If output cap cannot be reached under tighter limits, test only its narrow guard
   and document that reachability rather than fabricate an overflow demonstration.
4. ECC self-review actual code/callers/tests, fix defects and rerun affected checks;
   Bandit and compile checks using existing tooling, no new install. README, MIT
   license/attribution/AI disclosure, SECURITY, STATE, DECISIONS, LEARNING and exact
   verification receipt; update relevant Obsidian note. No independent audit, other
   runtime, Linux or hosted CI claim unless actually checked.

Research-at-approval evidence: primary/candidate inspection and one reviewed local extraction;
no project implementation, correctness tests, candidate execution or live traffic.
Implementation proceeds under the 02:20 addendum recorded in STATE and SCHEMA.
