# Local verification — October 5, 2026

Approved PLAN stages 1–4 complete locally on Windows CPython 3.13.7. Standard-library
API/CLI, frozen exact SCHEMA, seven invented examples, tests, reusable verifier and
portfolio/security/learning records. No repository or external publication.

| Check | Actual result |
|---|---|
| Normal unittest | 28 passed; normal.log |
| Optimized unittest and optimized CLI children | 28 passed; optimized.log |
| compileall application/tests/verifier | exit 0; compile.log |
| Bandit 1.9.4 application/tests/verifier | exit 0, zero findings/errors; bandit.json |
| Every partition of literal nine-byte stream | all 256 same records/offsets |
| Failed and partial-EOF stream partitions | one-cut/bytewise/coalesced semantic equivalence |
| Admission/budget/terminal checks | exact/one-past, max u32, 65th empty frame, aggregate reservation, invalid later chunk and sticky terminal evidence passed |
| Output checks | short write/flush/closed diagnostic mocks and real stdout/both-pipe closure return 2, normal/-O |
| Wrong endian mutation | exit 1, seven assertion failures |
| Weakened frame-length limit mutation | exit 1, three assertion failures |
| Restoration and final checks | exact original bytes restored, final normal/-O/checks pass |
| Seven demos | four status 0, three status 3; receipt includes states/accepted frames |

`receipt.json` binds application/tests/verifier/schema and seven source fixtures
with SHA256. Current application hash
`a34dd81233736b17d3bf7a091f5267cfdf14f251f15c8f25c61063b2408e1f39`.
Fixture contents/expected outcomes were frozen before code; hashes captured in final
receipt after verification. No claim that pre-code fixture hashes were captured.
`verify.py` is the reusable check entry point; README documents its inputs, outputs,
restoration assumptions and usage. Successful runs update own logs and receipt.

## ECC self-review

Used installed ecc-code-review pinned checklist and ecc-verification-loop approach;
read actual parser/state machine, public analyze/CLI callers, tests, examples,
verifier and surrounding contracts. Reviewed exact-byte boundary, full admission,
zero-length progress, lengths/copy bounds, offsets/reservations, terminal behavior,
failure snapshots, output delivery, test oracle independence and capability scope.
Implementing-agent self-review, not independent audit.

Confirmed medium defect: CLI diagnostic print after short output/flush failure could
raise a second OSError, losing the specified status 2 (`main` diagnostic branch,
now lines 267–273). `test_closed_diagnostic_after_delivery_failure` reproduced it;
red trace in ecc-diagnostic-before.log. Fixed by handling a failed diagnostic sink
and disabling its shutdown retry. Regression and real both-pipe-closed subprocess
checks pass in normal/optimized runs. No unresolved confirmed application defect
identified in this scoped self-review.

Seven narrow Bandit rule exclusions, all explained at exact subprocess sites:
test subprocess import B404, four test command sites B603, verifier import B404
and verifier fixed Python command B603. Application has no suppressions. No shell,
third-party execution, unapproved dependencies or real payloads.

## Bounds and limitations

Output cap tested at a narrow seam with MAX_OUTPUT temporarily reduced to one byte.
No valid end-to-end 256 KiB overflow is claimed: a conservative compact-JSON bound
is 256 trace entries ×512 bytes +64 frame metadata entries ×256 bytes +32768
payload-hex characters +2048 bytes envelope/failure metadata =182272 bytes, below
262144. Fixed field names/state strings and bounded integer widths fit those
conservative per-entry allowances. Actual encoded guard remains defensive.

Logical retained payload budgets do not equal Python RSS: hex uses two characters
per byte, and input/JSON/report copies and Python object overhead remain. No hard
wall-time/RSS guarantee. API forbidden-network/process mocks catch covered calls,
not a containment proof. Verification only Windows 3.13.7; other versions/Linux,
hosted CI/CodeQL, advisory/Scorecard results, dedicated secret/history scanning and
independent audit NOT RUN. Authored files reviewed for private material; not a
secret-scanner guarantee. Prior scanner/DNS/route records untouched; original
scanner live Linux SYN remains unrun.
