"""One synthetic official API request. Prints only timing/structure metadata."""
from __future__ import annotations

import json
import math
from pathlib import Path
import re
import sys
import threading
import time

from native_analysis import NativeAnalysis, _default_analyze


def main():
    started = time.monotonic()
    calls = 0
    completed = threading.Event()
    callbacks = []
    options_ok = False

    def analyze_once(turns, **options):
        nonlocal calls, options_ok
        if calls:
            raise RuntimeError("Smoke test permits one request")
        calls += 1
        options_ok = (options.get("timeout") == 40 and options.get("analysis_only") is True
                      and options.get("jev_provider") == "typesafe"
                      and options.get("jev_model") == "jev-latest"
                      and options.get("context") <= 12)
        try:
            return _default_analyze(turns, **options)
        finally:
            completed.set()

    scheduler = NativeAnalysis(lambda *args: callbacks.append(args), analyze_fn=analyze_once)
    snapshot = {
        "conversation": "synthetic:general-communication-smoke",
        "messages": [
            {"id": "synthetic-peer", "generation": 1, "who": "her", "name": "老板",
             "text": "这周能把剩下的需求做完吗？"},
            {"id": "synthetic-self", "generation": 1, "who": "me", "name": "我",
             "text": "我先确认范围和优先级。"},
        ],
    }
    scheduler.on_snapshot(snapshot)
    deadline = started + 50
    # Stop immediately after the first worker returns; never enter a retry window.
    while time.monotonic() < deadline:
        scheduler.tick()
        if callbacks or (completed.is_set() and not scheduler.busy):
            break
        time.sleep(0.05)
    elapsed = time.monotonic() - started
    formatted = callbacks[0][2] if callbacks else ""
    lines = formatted.splitlines()
    probabilities = re.findall(r"^• .+：([0-9]+(?:\.[0-9]+)?)%$", formatted, re.MULTILINE)
    report = {
        "python_311": sys.version_info[:2] == (3, 11),
        "foreign_cwd": Path.cwd() != Path(__file__).resolve().parent,
        "one_request": calls == 1,
        "options_ok": options_ok,
        "callback": len(callbacks) == 1,
        "matching_binding": bool(callbacks and callbacks[0][:2] == ("synthetic-peer", 1)),
        "question_title": bool(lines and lines[0].startswith("Jev｜") and ("？" in lines[0] or "?" in lines[0])),
        "two_probabilities": len(probabilities) == 2 and all(math.isfinite(float(p)) and 0 <= float(p) <= 100 for p in probabilities),
        "risk": bool(re.search(r"^风险：[0-9]+(?:\.[0-9]+)?/10$", formatted, re.MULTILINE)),
        "action": any(line.startswith("行动：") and len(line) > 3 for line in lines),
        "bounded_text": bool(formatted) and len(formatted) <= 420,
        "within_host_deadline": elapsed < 50,
        "elapsed_seconds": round(elapsed, 3),
    }
    scheduler.close()
    report["passed"] = all(value for key, value in report.items() if key != "elapsed_seconds")
    # No API body, formatted content, exception text, or credentials are emitted.
    print(json.dumps(report, ensure_ascii=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
