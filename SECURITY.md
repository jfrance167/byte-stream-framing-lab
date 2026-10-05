# Security scope

This offline educational parser accepts invented JSON/hex fixtures only. It never
connects to hosts, loads captures, executes/decodes payloads, invokes processes or
changes devices. The CLI reads one requested file/stdin and writes its report.
Tests and the verification helper launch the installed Python with fixed owned
scripts and synthetic inputs; no shell or downloaded execution.

Untrusted representations can contain oversized JSON/strings/depth/arrays, duplicate
keys, deceptive hex or length declarations. Whole admission precedes simulation.
Unchecked u32 lengths never control payload allocation. Frame/aggregate budgets
are checked at header completion; failed tails are cleared with preserved counts,
and errors are sticky. Accepted prefixes are meaningful only under this custom
model and fully valid input representation.

Hex retains exact payload information. Do not use real secrets, personal/client
data or executable samples. No authenticity, safe payload, TCP behavior, hard
CPU/RSS containment or downstream-use guarantee. Output may be partial on delivery
failure; status 2 is mandatory. No dependency installation/publication/security
alert dismissal is authorized by this lab. No independent audit or hosted checks.

Raise a suspected defect with a small invented reproducer and expected/actual
state; avoid confidential evidence. No external reporting contact is configured.
