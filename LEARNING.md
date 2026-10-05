# Learning

TCP application reads/writes do not define record boundaries. This lab avoids a
transport entirely and asks what a declared application framing rule can establish
from supplied byte chunks. Packet MTU and JSON semantic canonicalization answer
different questions.

The state machine needs at most a partial four-byte header and one admitted payload.
Complete headers are checked before their lengths influence payload storage. Zero
length still advances four wire bytes and consumes frame budget, preventing empty
record floods from bypassing limits.

A reservation is the full current admitted payload length; buffered bytes are what
has actually arrived. Accepted totals include only completed frames. Failure clears
storage while retaining the pre-clear evidence. Declared EOF distinguishes an
unfinished header/payload from an open parser waiting for more input.

Test expected bytes independently: encoding and decoding through the same buggy
helper can hide an endian error. The nine-byte literal has 256 possible partitions;
all yield the same frames and offsets. Failure/EOF partition checks keep the same
prefix and first error even though chunk traces differ.

Output error handling includes runtime shutdown. CPython may retry a failed stream
flush and replace exit 2 with 120. Preserve error status after stdout failure and
after a second failed diagnostic sink; real subprocess regressions complement mocks.

Optional exercise: predict how splitting a rejected four-byte header across chunks
changes the trace while keeping frame_start/detected_at/ignored totals identical.
