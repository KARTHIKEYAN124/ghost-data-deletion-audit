"""Public-label evaluation only. Prediction engine never imports this module."""
from collections import Counter
import csv
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import run
from local_model import authorize, LocalModel
from audit import read_csv
from test_cases import AuditSafetyTests


def signature(step):
    return tuple((k, step[k]) for k in sorted(step) if k != "step_no")


def evaluate(root):
    rows, corpus, usage = run(root / "dataset", root / "dataset/sample_deletion_requests.csv",
                              root / "sample_predictions.csv", root / ".cache")
    gold = {r["case_id"]: r for r in read_csv(root / "dataset/sample_output.csv")}
    status = sequence = exact_rows = matched = predicted = expected = field_matches = field_total = 0
    failures = []
    for row in rows:
        g = gold[row["case_id"]]
        a, b = json.loads(row["steps_json"]), json.loads(g["steps_json"])
        ok = row["deletion_status"] == g["deletion_status"]
        status += ok
        sequence += a == b
        exact_rows += ok and a == b
        ac, bc = Counter(map(signature, a)), Counter(map(signature, b))
        hit = sum((ac & bc).values())
        matched += hit; predicted += len(a); expected += len(b)
        field_total += 7 * max(len(a), len(b))
        field_matches += sum(sum(x.get(k) == y.get(k) for k in
            ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")) for x, y in zip(a, b))
        if not ok or a != b:
            failures.append(f"| {row['case_id']} | {row['deletion_status']} / {g['deletion_status']} | {len(a)} / {len(b)} | {hit} |")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuditSafetyTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    n = len(rows)
    precision, recall = matched / predicted, matched / expected
    report = f"""# Evaluation report

## Public validation (32 cases)

Only `dataset/sample_output.csv` is used as ground truth, exclusively in this evaluation program.
These are development-set measurements after inspecting failures, not unbiased held-out accuracy.
Hidden full-dataset accuracy is unknown. No hidden answers or organizer files were read.

| Metric | Result |
|---|---:|
| Case-level status accuracy | {status}/{n} ({status/n:.2%}) |
| Exact output row accuracy | {exact_rows}/{n} ({exact_rows/n:.2%}) |
| Exact step precision (all fields except step number) | {matched}/{predicted} ({precision:.2%}) |
| Exact step recall | {matched}/{expected} ({recall:.2%}) |
| Exact step F1 | {2*precision*recall/(precision+recall):.2%} |
| Positional field accuracy (7 fields, missing steps counted wrong) | {field_matches}/{field_total} ({field_matches/field_total:.2%}) |
| Exact ordered sequence accuracy | {sequence}/{n} ({sequence/n:.2%}) |
| Independent synthetic safety tests | {result.testsRun-len(result.failures)-len(result.errors)}/{result.testsRun} |

Step matching uses multisets of exact phase/system/resource/operation/state/evidence tuples.
Sequence accuracy requires exact equality of parsed JSON arrays, including step numbers.
Positional field accuracy deliberately penalizes missing steps and resulting shifts.

## Additional cases created for this solution

1. Explicit non-deletion and negation: marketing opt-out/export/name correction must not authorize deletion, even if the LLM votes yes.
2. Active connector with live profile and exposed shared support message: disable connector, delete profile, redact support, preserve security journal; future checks have empty evidence IDs.
3. Future absence snapshot following a current live profile: future evidence must not turn an incomplete case into complete.
4. Absent primary with a still-present replica: report the surviving copy.
5. Later verified cleanup of that same replica: old positives must not override newer compliant state.
6. Redacted tombstone plus retained journal: preserve both, verify permitted stable reference and required journal availability.
7. Historical email change: resolve the old email hash while preventing a future email from entering an earlier identity graph.
8. Colliding names: a shared name alone cannot link two people, and a direct email takes precedence over a mismatching name.

Executable assertions live in `evaluation/test_cases.py`; synthetic names and resources do not occur in inference logic.

## Failures found and improvements made

- Raw small-model batch intent votes were inconsistent even for explicit deletion language. Added general linguistic authorization/negation safeguards, multilingual deletion vocabulary, and marketing-only exclusion; model decisions remain the fallback for ambiguous language.
- Added SQL JSON payload decoding, nested business-message PII detection, canonical service mapping for replicas, and direct-identifier checks on tombstones.
- Resource lookup query keys identify the subject but are not treated as PII remaining in the returned record.
- Independent replica copies survive an absent primary; only later evidence for the same copy supersedes them.
- Added capture-time and observation-time cutoffs. Historical evidence helps identity linkage, while assertions of completion use observations during the request review window.
- Negative collection evidence is used only for already-attributed resource IDs and a subject present in that export's scope.

Known limitations: the current linker cannot attribute some negative and anonymized observations to their subjects. Additional identity or cross-artifact reconstruction may improve this; the measurements do not prove that the dataset lacks such links. The implementation does not guess resource IDs from case numbers or sample answers. This causes omitted verification steps and conservative INCOMPLETE results when no attributable state evidence exists. OCR may miss or corrupt identifiers; catalog aliases support business-artifact matching, but table row layout is imperfect. No claim of perfect reconstruction is made.

## Remaining public mismatches

| Case | Predicted / expected status | Predicted / expected steps | Exact matched steps |
|---|---|---:|---:|
""" + "\n".join(failures) + "\n"
    (root / "code/evaluation/evaluation_report.md").write_text(report, encoding="utf-8")
    if not result.wasSuccessful(): raise SystemExit(1)
    print(f"Status {status}/{n}; exact sequences {sequence}/{n}; step precision {precision:.2%}; recall {recall:.2%}")


if __name__ == "__main__":
    evaluate(Path(__file__).resolve().parents[2])
