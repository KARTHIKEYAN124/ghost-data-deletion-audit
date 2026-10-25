# Evaluation report

## Public validation (32 cases)

Only `dataset/sample_output.csv` is used as ground truth, exclusively in this evaluation program.
These are development-set measurements after inspecting failures, not unbiased held-out accuracy.
Hidden full-dataset accuracy is unknown. No hidden answers or organizer files were read.

| Metric | Result |
|---|---:|
| Case-level status accuracy | 29/32 (90.62%) |
| Exact output row accuracy | 9/32 (28.12%) |
| Exact step precision (all fields except step number) | 158/158 (100.00%) |
| Exact step recall | 158/193 (81.87%) |
| Exact step F1 | 90.03% |
| Positional field accuracy (7 fields, missing steps counted wrong) | 960/1351 (71.06%) |
| Exact ordered sequence accuracy | 9/32 (28.12%) |
| Independent synthetic safety tests | 8/8 |

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
| case_01 | INCOMPLETE / COMPLETE | 0 / 1 | 0 |
| case_02 | INCOMPLETE / COMPLETE | 0 / 1 | 0 |
| case_03 | COMPLETE / COMPLETE | 2 / 3 | 2 |
| case_04 | INCOMPLETE / COMPLETE | 0 / 2 | 0 |
| case_06 | INCOMPLETE / INCOMPLETE | 3 / 4 | 3 |
| case_07 | INCOMPLETE / INCOMPLETE | 3 / 4 | 3 |
| case_08 | INCOMPLETE / INCOMPLETE | 3 / 4 | 3 |
| case_09 | INCOMPLETE / INCOMPLETE | 3 / 5 | 3 |
| case_10 | INCOMPLETE / INCOMPLETE | 3 / 4 | 3 |
| case_18 | INCOMPLETE / INCOMPLETE | 12 / 14 | 12 |
| case_20 | INCOMPLETE / INCOMPLETE | 6 / 8 | 6 |
| case_21 | COMPLETE / COMPLETE | 1 / 3 | 1 |
| case_22 | INCOMPLETE / INCOMPLETE | 7 / 8 | 7 |
| case_23 | INCOMPLETE / INCOMPLETE | 6 / 8 | 6 |
| case_24 | INCOMPLETE / INCOMPLETE | 6 / 7 | 6 |
| case_25 | COMPLETE / COMPLETE | 1 / 3 | 1 |
| case_26 | COMPLETE / COMPLETE | 4 / 6 | 4 |
| case_27 | COMPLETE / COMPLETE | 4 / 6 | 4 |
| case_28 | COMPLETE / COMPLETE | 4 / 6 | 4 |
| case_29 | INCOMPLETE / INCOMPLETE | 12 / 14 | 12 |
| case_30 | INCOMPLETE / INCOMPLETE | 12 / 14 | 12 |
| case_31 | COMPLETE / COMPLETE | 2 / 3 | 2 |
| case_32 | INCOMPLETE / INCOMPLETE | 4 / 5 | 4 |
