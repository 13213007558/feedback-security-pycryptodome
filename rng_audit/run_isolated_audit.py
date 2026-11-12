"""Run every RNG probe in a fresh, isolated subprocess and tabulate results.

Isolation matters because binding of ``get_random_bytes`` happens at import
time for half of the library. Each probe is therefore a separate interpreter
with a clean module cache; no monkeypatch can leak into another case or into
the interpreter running application code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "probe_rng.py")

ENTRIES = ["RSA_GENERATE", "ECC_GENERATE", "OAEP_ENCRYPT", "PSS_SIGN",
           "AES_CBC_IV", "AES_GCM_NONCE", "CHACHA20_NONCE"]

# (subprocess args suffix, human label)
COUNT_STYLES = [
    (["count", "{}", "GLOBAL_POST"], "patch AFTER import"),
    (["count", "{}", "GLOBAL_POST_PRELOADED"], "patch after pre-load"),
    (["count", "{}", "GLOBAL_PRE"], "patch BEFORE import"),
    (["count", "{}", "EXPLICIT"], "explicit randfunc"),
]
FAIL_STYLES = [
    (["fail", "{}"], "failing patch (post-import)"),
    (["fail_explicit", "{}"], "failing explicit randfunc"),
]


def _spawn(args):
    env = dict(os.environ)
    env["PYTHONPATH"] = HERE + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, PROBE] + args,
        capture_output=True, text=True, env=env, timeout=300,
    )
    payload = None
    for line in proc.stdout.splitlines():
        if line.startswith("JSON "):
            payload = json.loads(line[5:])
    if payload is None:
        payload = {"case": args[-1], "error": "no JSON emitted",
                   "stderr": proc.stderr[-400:], "rc": proc.returncode}
    return payload


def main():
    rows = []
    for entry in ENTRIES:
        for template, label in COUNT_STYLES:
            args = [a.format(entry) for a in template]
            rows.append((entry, label, _spawn(args)))
        for template, label in FAIL_STYLES:
            args = [a.format(entry) for a in template]
            rows.append((entry, label, _spawn(args)))

    print("=" * 100)
    print("PyCryptodome RNG injection audit (each row is a separate process)")
    print("=" * 100)
    hdr = f"{'entry':<16}{'style':<28}{'intercepted':<13}{'calls':<22}detail"
    print(hdr)
    print("-" * 100)
    for entry, label, r in rows:
        if "error" in r and "intercepted" not in r:
            detail = "ERROR: " + r.get("error", "?")
            if "stderr" in r:
                detail += " | " + r["stderr"].strip().splitlines()[-1][:60]
            print(f"{entry:<16}{label:<28}{'-':<13}{'-':<22}{detail[:50]}")
            continue
        intercepted = r.get("intercepted")
        calls = r.get("call_sizes", r.get("fail_calls", []))
        calls_s = ("n=%d, %s" % (len(calls), calls[:4])) if calls else str(calls)
        os_calls = r.get("os_urandom_calls", [])
        if "silent_fallback" in r or "propagated_error" in r:
            detail = "silent_fallback=%s os.urandom=%s" % (
                r.get("silent_fallback"), os_calls)
            if r.get("propagated_error"):
                detail += " | raised " + r["propagated_error"][:40]
        elif r.get("bypassed_to_os"):
            detail = "BYPASS: injection ignored, real OS RNG used"
        else:
            detail = r.get("evidence", r.get("error", ""))[:55]
        print(f"{entry:<16}{label:<28}{str(intercepted):<13}{calls_s:<22}{detail}")

    # Machine-readable artifact for the report.
    out = os.path.join(HERE, "audit_results.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump([{"entry": e, "style": l, "result": r} for e, l, r in rows],
                  fh, indent=2, ensure_ascii=False)
    print("\nSaved machine-readable results to", out)


if __name__ == "__main__":
    main()
