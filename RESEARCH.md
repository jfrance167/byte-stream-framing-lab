# Framing research — October 5, 2026

Historical research baseline below. Stages 1–4 subsequently approved at 02:20 and
completed locally; current outcomes are in STATE and verification/REPORT.md.

Recommendation: build the bounded original standard-library educational model in
[PLAN.md](PLAN.md); adopt standard primitives, use Twisted as a reference, do not
fork/install its framework. Research is targeted, not an exhaustive safety audit.

## Primary grounding and alternative

[RFC 9293 §3.7](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7)
explains that TCP segmentation does not preserve application buffer boundaries;
§3.9.1.2 also states PSH is not a record marker. This motivates framing; the lab
does not implement TCP. [Python struct](https://docs.python.org/3.13/library/struct.html)
documents `!` big-endian standard layout and unsigned `I` size four bytes.
[asyncio streams](https://docs.python.org/3.13/library/asyncio-stream.html)
documents exact reads and partial EOF exceptions, but supplies no application
length-prefix budget policy.

MTU/packet-size interpretation is a viable separate arithmetic lab. RFC 9293 §3.7.1
distinguishes MSS and effective segment/header limits;
[RFC 8200 §5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5)
defines IPv6 packet-size constraints. Neither determines message boundaries nor
allows fictional arithmetic to claim measured path MTU. Framing is the clearer gap.

## Candidate inspection

Connected GitHub repository search `Python length prefixed framing` returned
CNT5715-Network-Framing-Lab, ClienteServidorSockets, protobridge and c2-pair. Their
names/search metadata do not establish quality/license/security; no execution or
recommendation based on those results. A focused established reference was stronger.

Twisted at `d7679d96eed8d28ad5d926e3138f99a1332f2af2`:
- [Actual parser](https://github.com/twisted/twisted/blob/d7679d96eed8d28ad5d926e3138f99a1332f2af2/src/twisted/protocols/basic.py),
  blob `399dea51b3eb2184c472dd2a5f82cf205d3c0278`, inspected IntN dataReceived,
  lengthLimitExceeded and Int32StringReceiver. Uses `!I`, retains incomplete tails,
  parses coalesced frames, checks MAX_LENGTH before delivery; default overflow
  disconnects a transport. Its callback/compatibility buffer lifecycle and incoming
  concatenation do not provide this proposed lab's aggregate/sticky-error contract.
- [Actual tests](https://github.com/twisted/twisted/blob/d7679d96eed8d28ad5d926e3138f99a1332f2af2/src/twisted/protocols/test/test_basic.py),
  blob `1d287f51792ef1c317984e82f207cb110ec278e4`, inspected lines 700–1030:
  IntNTestCaseMixin bytewise receive, partial tails, oversized headers/no delivery,
  mutable recvd behavior and Int32Tests literal header example. Tests were read,
  not run. These support useful test categories, not our implementation correctness.
- [LICENSE](https://github.com/twisted/twisted/blob/d7679d96eed8d28ad5d926e3138f99a1332f2af2/LICENSE),
  blob `49acef5ac7cff86111a74fe2b69a8d11aab019ec`, full permission/warranty text
  inspected: MIT, preserve copyright/license on copied substantial portions.
- [Metadata](https://github.com/twisted/twisted/blob/d7679d96eed8d28ad5d926e3138f99a1332f2af2/pyproject.toml),
  blob `0d1976d11b7911bd8ae5d61cea855855de3369dd`, Python >=3.10; seven runtime
  dependencies (zope.interface, constantly, incremental, automat, hyperlink, attrs,
  typing_extensions), build dependencies and optional networking extras. This broader
  asynchronous framework is unnecessary for in-memory simulation.
- Recent [commit](https://github.com/twisted/twisted/commit/d7679d96eed8d28ad5d926e3138f99a1332f2af2)
  dated October 4, 2026 upgrades Ubuntu in Actions. CI-maintenance evidence, not a
  hosted test pass. Focused issue search returned historic #3478 AMP length checking
  and #2315 int8 support; these are historic reports, not current reproduced defects
  in Int32StringReceiver. No Scorecard/advisory assessment or security certification.

CPython v3.13.7 [streams.py](https://github.com/python/cpython/blob/v3.13.7/Lib/asyncio/streams.py)
blob `64aac4cc50d15a5e076d5ad43ea8a9017f12a72e`, lines 730–795 inspected:
readexactly waits until n bytes, zero returns empty, EOF clears buffer and raises
IncompleteReadError.partial; n is not capped by StreamReader's configured limit.
[Actual tests](https://github.com/python/cpython/blob/v3.13.7/Lib/test/test_asyncio/test_streams.py),
blob `3040ca55fae0e99fa359921762345eb240afa670`, readexactly zero/negative, coalesced
feed, limit=3/read=5, partial EOF and stored exception cases inspected. Stdlib
readexactly is appropriate in a future async transport with separate application
bounds; this lab requires neither transport nor event loop. No CPython source copied;
Python's PSF licensing remains governed by the installed runtime's license.
Pinned [LICENSE](https://github.com/python/cpython/blob/v3.13.7/LICENSE) lines 45–100
were read (blob `14603b95c2e23b5a4cd6ff93f50348d1817f7638`): PSF License v2,
copyright/license retention and derivative-change-summary obligations; incorporated
components may carry other licenses. No source adaptation is proposed.

## Reuse, drafting and retrieval limits

Read vault Home/Codex Integration, Python Input and Serialization Boundaries and
JSON Canonicalization Lab Research. Canonicalization explicitly defers framing.
Targeted local README searches found archive metadata framing and PCAP analysis,
not a matching incremental raw-record implementation. Reuse DNS/route admission
patterns and output-error lessons after reading their actual source during stage 1;
keep their authoritative files unchanged. No exhaustive local inventory claim.

Read shared STARTUP, routing guide and ECC integration status. Native full ECC
plugin remains blocked; narrowly installed ECC review entry point is available.
Laya's classification/triage schema is unnecessary here. Ollama qwen3.5:2b returned
the four requested labels in 6098 ms, 25 output tokens, done_reason stop; reviewed
and accepted only those labels. Raw brief/draft/metadata remain in research/.
Initial sandbox loopback failure sent no inference; its reserved file was preserved.
A second exclusive-file guard also stopped before inference; a fresh loopback-only
output completed with app approval. This is one successful inference, no model retry.
OpenRouter was explicitly considered; adequate local extraction required no remote
draft, pricing check or inference. Codex performed source/security judgments.

GitHub transport failures, one wrong test path and empty out-of-range excerpts were
not successful inspections; correct bounded pinned paths later supplied the evidence
above. Raw web endpoints failed; connected GitHub and official documentation worked.
No candidates installed/run, no application code/tests, network model validation,
independent audit, publication or additional spending.
