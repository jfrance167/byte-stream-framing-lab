"""Repeat this lab's local checks; mutations restore exact source in finally.

Usage: python verification/verify.py from any directory. Outputs owned logs and a
receipt beside this file. Requires installed Python/Bandit; installs nothing.
Only launches the installed Python on this project's source and invented fixtures.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess  # nosec B404: reviewed fixed local verification commands.
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "verification"
SOURCE = ROOT / "framing_lab.py"


def run(name, args):
    child = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                           timeout=60)  # nosec B603: no shell, fixed installed Python/owned scripts.
    (OUT / (name + ".log")).write_bytes(child.stdout + child.stderr)
    return child


def clear_cache():
    # Remove only this module's derived cache files, never source/evidence folders.
    for optimization in (None, "1", "2"):
        cache = Path(importlib.util.cache_from_source(str(SOURCE), optimization=optimization))
        cache.unlink(missing_ok=True)


def main():
    OUT.mkdir(exist_ok=True)
    original = SOURCE.read_bytes()
    results = {}
    test_args = ["-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    try:
        for name, old, new in (("wrong-endian", b'struct.unpack("!I"', b'struct.unpack("<I"'),
                               ("length-limit", b"length > MAX_FRAME", b"length > MAX_FRAME + 1")):
            if original.count(old) != 1:
                raise RuntimeError("mutation target must occur exactly once")
            SOURCE.write_bytes(original.replace(old, new))
            clear_cache()
            child = run("mutation-" + name, test_args)
            text = (child.stdout + child.stderr).decode("utf-8", errors="replace")
            assertions = len(re.findall(r"^FAIL: ", text, re.MULTILINE))
            results[name] = {"exit": child.returncode, "assertion_failures": assertions}
            if child.returncode == 0 or assertions == 0:
                raise RuntimeError("mutation not detected by an assertion failure")
            SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
        clear_cache()
    for name, args in (("normal", test_args), ("optimized", ["-O", *test_args]),
                       ("compile", ["-m", "compileall", "-q", "framing_lab.py", "tests", "verification/verify.py"]),
                       ("bandit", ["-m", "bandit", "-q", "-r", "framing_lab.py", "tests", "verification/verify.py",
                                   "-f", "json", "-o", str(OUT / "bandit.json")])):
        child = run(name, args)
        results[name] = {"exit": child.returncode}
        if child.returncode:
            raise RuntimeError(name + " check failed; see log")
    demos = {}
    for fixture in sorted((ROOT / "examples").glob("*.json")):
        child = run("demo-" + fixture.stem, [str(SOURCE), str(fixture)])
        expected = 3 if fixture.stem in {"partial-header", "partial-payload", "prefix-failure"} else 0
        if child.returncode != expected:
            raise RuntimeError("demo status mismatch")
        value = json.loads(child.stdout)
        demos[fixture.name] = {"exit": child.returncode, "state": value["state"],
                              "accepted_frames": len(value["frames"])}
    files = [SOURCE, ROOT / "tests/test_framing_lab.py", Path(__file__).resolve(), ROOT / "SCHEMA.md",
             *sorted((ROOT / "examples").glob("*.json"))]
    receipt = {"python": sys.version, "checks": results, "demos": demos,
               "source_restored": SOURCE.read_bytes() == original,
               "sha256": {str(p.relative_to(ROOT)).replace("\\", "/"):
                          hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
