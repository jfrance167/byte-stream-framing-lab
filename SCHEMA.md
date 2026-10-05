# u32be-records-v1 contract

Authoritative version 1 contract frozen before code October 5, 02:20 approval.
See PLAN for admission/budget limits, threat model and excluded capabilities.

Input JSON has exactly profile="u32be-records-v1", chunks=[strict hex strings],
eof=true/false. Uppercase input hex accepted, output lowercase; no whitespace,
prefix, odd digits or payload text. All chunks validate before simulation.

Every frame is four unsigned big-endian header bytes followed by that many payload
bytes. Wire offsets count consumed bytes from zero, with half-open frame spans
[start,end) including the header. Frame indices start at zero. Header length checks
precede payload retention: prospective frame 65, length >4096, accepted payload plus
declared length >16384, in that order. Zero frames consume header and frame budget.

Top-level report fields exactly:
- profile, state: open_idle / need_header / need_payload / closed / failed.
- frames: [{index,start,end,length,payload_hex}], completed accepted prefix only.
- consumed_bytes: count parsed before first failure, including its rejected header.
- supplied_bytes: sum of all admitted chunks; ignored_bytes = supplied-consumed
  after failure (otherwise zero). Same-chunk suffix and all later chunks count.
- accepted_payload_bytes, reserved_payload_bytes, buffered_header_bytes,
  buffered_payload_bytes, remaining_bytes, failure, trace.

Reserved is the full admitted current declaration, including buffered bytes;
accepted excludes it. Completing a frame transfers its length to accepted and
clears reservation and carry. Buffered counts show actual current storage. Idle
remaining=0; partial header remaining=4-header_count; partial payload
remaining=declared-buffered. Failure/closed clear carry, reservation and remaining.

failure is null or exactly {code,frame_start,detected_at,pending_header_bytes,
pending_payload_bytes,reserved_payload_bytes,declared_length}. frame_start is the
rejected/incomplete header start; detected_at is the consumed boundary (at complete
header for budget errors, end of supplied stream for EOF errors). The preserved
pending snapshot precedes clear. declared_length is null until header complete.
Codes: frame_limit, frame_length_limit, aggregate_payload_limit, truncated_header,
truncated_payload. Successful frames remain visible after framing failure. An
invalid representation yields no report/accepted-prefix claim.

trace has one entry per supplied chunk, exactly {chunk_index,chunk_bytes,
consumed_bytes,ignored_bytes,state,accepted_frames,accepted_payload_bytes,
reserved_payload_bytes,buffered_header_bytes,buffered_payload_bytes,remaining_bytes}.
consumed/ignored trace counts apply to that chunk; other fields are cumulative
state at its end, before final EOF handling. Trace does not contain payloads.
Semantic final fields are partition invariant; traces describe different supplied
partitions. All pending EOF bytes have been consumed, not ignored.

Internal feed returns fed / rejected_failed / rejected_closed; terminal calls
retain frames and first failure. A failed feed may consume prefix then reject
same-chunk suffix; it returns fed, its state becomes failed. finish is idempotent
after closed/failed. No public decoder/reset/coercing-byte API.

CLI status 0 valid open/closed, 3 framed-stream failure, 2 admission/input/output
error. No report on admission failure. Output delivery is nontransactional: a
write/flush failure may leave partial output, but never status 0/3. Broken pipe
must exit 2 without a shutdown flush retry overriding it. Hex is reversible.
