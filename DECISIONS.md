# Decisions

- October 5, 02:20: coordinator approved PLAN stages 1–4 under Jake's verified
  successor mandate. Separate directory/sole writer, no repository/publication,
  transport, dependencies or new concurrency; cutoff October 6 08:00 Eastern.
- Original stdlib model: Twisted's inspected tested parser is a useful reference,
  but its async framework/dependencies/callback lifecycle exceed the in-memory goal.
  MTU arithmetic deferred because it answers a different layer's size question.
- Custom opaque u32 big-endian records, including zero length. No resynchronization,
  charset, checksum, authenticity or real protocol interoperability claims.
- Whole representation admission precedes processing. Framing failures preserve a
  completed prefix; malformed later input invalidates all simulation evidence.
- Zero-based half-open wire spans; first failure identifies header start and separate
  detection boundary. Reservations only represent admitted headers; rejected lengths
  are recorded separately. Accepted/reserved/pending counts never double charge.
- Successful earlier frames in the failing chunk remain accepted, giving partition
  invariant semantic evidence. Same-chunk suffix and later chunks are ignored.
- Compact bounded JSON/hex reports. Defensive output cap is unreachable under current
  tighter budgets, so verify its narrow guard rather than claim an overflow demo.
- Self-review retained local-first extraction, Codex parser/security decisions and
  exact-source mutation restoration. No free remote call needed after local success.
