#!/usr/bin/env python3
"""
run_tests.py
------------
Runs the full test corpus against the guardrail, prints a summary, and exports
a PDF report (reports/guardrail_report.pdf) plus a JSON detail file.

Usage:
    python3 run_tests.py

No external dependencies.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardrail import analyze
from guardrail.report import build_report
from tests.test_cases import CASES


SEVERITY = {"ALLOW": 0, "FLAG": 1, "BLOCK": 2}


def meets(expected, actual):
    """A result passes if its severity is at least the expected severity,
    except ALLOW which must match exactly (benign must not be flagged)."""
    if expected == "ALLOW":
        return actual == "ALLOW"
    return SEVERITY[actual] >= SEVERITY[expected]


def main():
    results = []
    passed = 0
    by_diff = {}
    by_cat = {}

    for c in CASES:
        r = analyze(c["text"])
        ok = meets(c["expected"], r.verdict)
        passed += ok
        rec = {
            "name": c["name"],
            "text": c["text"],
            "category": c["category"],
            "difficulty": c["difficulty"],
            "language": c["language"],
            "expected": c["expected"],
            "verdict": r.verdict,
            "score": r.score,
            "families": sorted(r.families),
            "passed": ok,
        }
        results.append(rec)

        d = by_diff.setdefault(c["difficulty"], {"total": 0, "passed": 0})
        d["total"] += 1
        d["passed"] += ok
        k = by_cat.setdefault(c["category"], {"total": 0, "passed": 0})
        k["total"] += 1
        k["passed"] += ok

    total = len(CASES)
    failed = total - passed
    langs = len({c["language"] for c in CASES})
    cats = len(by_cat)

    # order difficulties logically
    order = ["easy", "medium", "hard", "complex", "very_complex", "extreme"]
    by_diff_ordered = {k: by_diff[k] for k in order if k in by_diff}

    summary = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "detection_rate": 100.0 * passed / total if total else 0.0,
        "categories": cats,
        "languages": langs,
        "by_difficulty": by_diff_ordered,
    }

    # ---- console output ----
    print("=" * 64)
    print("GUARDRAIL v1.0 — TEST RUN")
    print("=" * 64)
    print(f"Total cases     : {total}")
    print(f"Passed          : {passed}")
    print(f"Failed          : {failed}")
    print(f"Detection rate  : {summary['detection_rate']:.2f}%")
    print(f"Languages       : {langs}")
    print(f"Categories      : {cats}")
    print("-" * 64)
    for d, st in by_diff_ordered.items():
        print(f"  {d:<13}: {st['passed']}/{st['total']}")
    print("-" * 64)
    if failed:
        print("FAILURES:")
        for r in results:
            if not r["passed"]:
                print(f"  [{r['difficulty']}/{r['category']}] {r['name']}: "
                      f"expected {r['expected']} got {r['verdict']} "
                      f"(score {r['score']})")
    else:
        print("All cases passed.")
    print("=" * 64)

    # ---- exports ----
    os.makedirs("reports", exist_ok=True)
    pdf_path = os.path.join("reports", "guardrail_report.pdf")
    json_path = os.path.join("reports", "guardrail_report.json")
    build_report(pdf_path, summary, results)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": results}, f,
                  ensure_ascii=False, indent=2)
    print(f"PDF report : {pdf_path}")
    print(f"JSON report: {json_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
