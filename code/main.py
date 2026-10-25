"""Run: python code/main.py --dataset dataset --output output.csv"""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import sys

from audit import Corpus, PHASES, OPERATIONS, read_csv
from local_model import LocalModel, authorize


def extract_images(dataset, cache):
    """Read real pixels, using Windows OCR or Tesseract; cache keyed by file digest."""
    import hashlib
    images = sorted((dataset / "evidence" / "images").glob("*.png"))
    digest = hashlib.sha256(b"".join(p.read_bytes() for p in images)).hexdigest()
    textfile = cache / "ocr.json"
    if textfile.exists():
        stored = json.loads(textfile.read_text(encoding="utf-8-sig"))
        if stored.get("digest") == digest: return stored["texts"]
    cache.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(Path(__file__).with_name("ocr_windows.ps1")),
                        "-ImageDirectory", str((dataset / "evidence/images").resolve()),
                        "-OutputPath", str((cache / "ocr_raw.json").resolve())], check=True)
        texts = json.loads((cache / "ocr_raw.json").read_text(encoding="utf-8-sig"))
    elif shutil.which("tesseract"):
        texts = {p.name: subprocess.check_output(["tesseract", str(p), "stdout"], text=True) for p in images}
    else:
        raise RuntimeError("Install Tesseract for image OCR, or run on Windows with Windows OCR installed")
    textfile.write_text(json.dumps({"digest": digest, "texts": texts}), encoding="utf-8")
    return texts


def validate(rows, requests, corpus):
    state_by_operation = {
        "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
        "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
        "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}
    if [r["case_id"] for r in rows] != sorted(r["case_id"] for r in requests):
        raise ValueError("Prediction rows must exactly match sorted requests")
    evidence_times = {m["file_id"]: m["captured_at"] for m in read_csv(corpus.dataset / "evidence_files.csv")}
    evidence_times.update({a["activity_id"]: a["event_time"] for a in corpus.activities})
    evidence_times.update({a["audit_id"]: a["event_time"] for a in corpus.identities.history})
    requests_by_id = {r["case_id"]: r for r in requests}
    for row in rows:
        if row["deletion_status"] not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"): raise ValueError("Invalid status")
        steps = json.loads(row["steps_json"])
        if row["deletion_status"] == "NOT_APPLICABLE" and steps: raise ValueError("Unauthorized steps")
        for i, s in enumerate(steps, 1):
            if set(s) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}: raise ValueError("Step schema")
            if s["step_no"] != i or s["operation"] not in OPERATIONS[s["phase"]]: raise ValueError("Step sequence")
            if s["state"] != state_by_operation[s["operation"]]: raise ValueError("Operation/state mismatch")
            if row["deletion_status"] == "COMPLETE" and s["phase"] != "VERIFICATION": raise ValueError("Complete case has remediation")
            needs_evidence = row["deletion_status"] == "COMPLETE" or s["phase"] == "FINDING"
            if needs_evidence:
                if s["evidence_id"] not in evidence_times: raise ValueError("Invalid evidence reference")
                if evidence_times[s["evidence_id"]] > requests_by_id[row["case_id"]]["audit_at"]: raise ValueError("Future evidence")
            elif s["evidence_id"]: raise ValueError("Future action must not claim evidence")
        ordered = sorted(steps, key=lambda s: (PHASES.index(s["phase"]), OPERATIONS[s["phase"]].index(s["operation"]), s["system_id"], s["resource_id"]))
        if ordered != steps: raise ValueError("Operation order")


def run(dataset, request_path, output, cache, model="qwen2.5:1.5b", endpoint="http://localhost:11434"):
    import csv
    requests = read_csv(request_path)
    interpreter = LocalModel(cache / "intent.json", model, endpoint)
    intent = interpreter.classify([r["request_text"] for r in requests])
    corpus = Corpus(dataset, extract_images(dataset, cache))
    print(f"Read {len(corpus.coverage)} evidence files, extracted {len(corpus.observations)} observations", flush=True)
    rows = []
    for n, request in enumerate(sorted(requests, key=lambda r: r["case_id"]), 1):
        rows.append(corpus.decide(request, authorize(request["request_text"], intent[request["request_text"]])))
        if n % 50 == 0: print(f"Audited {n}/{len(requests)} requests", flush=True)
    validate(rows, requests, corpus)
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader(); writer.writerows(rows)
    usage = {**interpreter.usage, "requests": len(requests), "statuses": dict(Counter(r["deletion_status"] for r in rows)),
             "evidence_files_read": len(corpus.coverage), "observations": len(corpus.observations)}
    (cache / (output.stem + "_usage.json")).write_text(json.dumps(usage, indent=2))
    print(json.dumps(usage, indent=2), flush=True)
    return rows, corpus, usage


def write_usage_report(path, usage):
    total = usage["input_tokens"] + usage["output_tokens"]
    n = usage["requests"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""# Final full-dataset run: token usage and cost

The numbers below come from the actual Ollama `prompt_eval_count` and `eval_count`
fields returned during the run that generated `output.csv`. No paid API was used.
Model messages are deduplicated by exact full text; each uncached batch contains at most 12 messages.
The final run uses a separate cache directory to avoid relying on evaluation/calibration predictions.

| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Estimated API cost |
|---|---:|---:|---:|---:|---:|
| {usage['provider']} / {usage['model']} | {usage['calls']} | {usage['input_tokens']} | {usage['output_tokens']} | {total} | $0.00 |
| Overall | {usage['calls']} | {usage['input_tokens']} | {usage['output_tokens']} | {total} | $0.00 |

- Requests processed: {n}.
- Average tokens per request: {total/n:.2f} ({usage['input_tokens']/n:.2f} input, {usage['output_tokens']/n:.2f} output).
- Average model calls per request: {usage['calls']/n:.4f}.
- Duplicate/already-cached message occurrences: {usage['cache_hits']}.
- Total and average API fees: $0.00 total; $0.00 per request. Hardware, electricity, and model download costs are not estimated.
- Evidence files read: {usage['evidence_files_read']}; observations extracted: {usage['observations']}.
- Status totals: {json.dumps(usage['statuses'], sort_keys=True)}.

PDF text extraction, Windows OCR, SQLite processing, policy evaluation, and synthetic safety tests make no LLM calls.
Development calibration was separate: a combined 550-message full/public-sample pass made 34 local calls,
using 18,855 input tokens and 1,076 output tokens (19,931 total), also $0.00 in API fees.
Those development tokens are excluded from the final-run totals above.

Cached reruns make fewer calls; use an empty `--cache` directory to repeat cold-run accounting.
The local model prompt and schema are included in source; no credential is required.
""", encoding="utf-8")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=root / "dataset")
    parser.add_argument("--requests", type=Path)
    parser.add_argument("--output", type=Path, default=root / "output.csv")
    parser.add_argument("--cache", type=Path, default=root / ".cache")
    parser.add_argument("--model", default="qwen2.5:1.5b")
    parser.add_argument("--endpoint", default="http://localhost:11434")
    parser.add_argument("--usage-report", type=Path, default=root / "code/evaluation/usage_report.md")
    args = parser.parse_args()
    rows, corpus, usage = run(args.dataset, args.requests or args.dataset / "deletion_requests.csv", args.output, args.cache, args.model, args.endpoint)
    write_usage_report(args.usage_report, usage)
