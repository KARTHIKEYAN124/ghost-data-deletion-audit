# Ghost Data deletion audit agent

Terminal application using a free local Ollama model, identity reconstruction, multimodal evidence extraction, and a deterministic policy planner. No paid API or API key is used. Local computation still consumes electricity and hardware time.

## Setup

Use Python 3.10 or newer. Keep `code/` beside the challenge's `dataset/` folder.

```powershell
python -m pip install -r code/requirements.txt
ollama pull qwen2.5:1.5b
```

Start Ollama if it is not running (`ollama serve`). Windows uses its installed Windows OCR language pack. On Linux/macOS install Tesseract with English language data; the code invokes its CLI. PDFs use PyMuPDF text extraction. All supplied PNGs are read from their actual pixels, not filenames or hand-entered transcriptions.

## Generate predictions

```powershell
python code/main.py
```

This reads `dataset/deletion_requests.csv` and writes root-level `output.csv`. An uncached CPU run can take several minutes. Progress is printed during intent inference and every 50 audited cases. The model must be installed locally; the application never silently substitutes an unavailable model or a remote provider.

Options: `--dataset PATH`, `--requests PATH`, `--output PATH`, `--cache PATH`, `--model NAME`, `--endpoint URL`. Use a fresh `--cache` directory to measure a cold run. `.cache` is outside the submitted code tree and stores content-addressed intent and OCR results. Reuse only caches from trusted local runs. Model calls and token counts come from Ollama's actual response statistics.

## Evaluate

```powershell
python code/evaluation/main.py
python -m unittest discover -s code/evaluation -p test_cases.py -v
```

Evaluation generates sample predictions and `code/evaluation/evaluation_report.md`, with public status, row, step, field, and sequence metrics. It also runs eight independent synthetic safety tests. Public expected answers are read only by evaluation; the prediction modules never read them. Existing report measurements are development validation, not hidden-test results.

## How it works

1. **Intent:** a local Qwen 2.5 1.5B prompt classifies full messages in schema-constrained batches. Explicit authorization, negation, multilingual deletion language, and marketing-only safeguards constrain its votes. The prompt is in `local_model.py`; messages are data, not instructions.
2. **Identity:** roll back future identity changes, accumulate current and historical identifiers available by `audit_at`, normalize email case and phone formatting, and derive historical email hashes. Exact identifiers and catalog aliases link resources; names are never fuzzily merged.
3. **Evidence:** read the manifest and every local file. Parse real SQL into an isolated in-memory SQLite database, decode JSON payloads, reconstruct correlated log traces across six layouts, read handover records, extract PDF text, and OCR images. Preserve capture timestamps, observation timestamps, source IDs, and independent replica channels.
4. **State:** ignore workflow success claims as proof. Restrict evidence to the audit cutoff. Use actual query responses, record contents, snapshots, and configuration reads. Historical observations may link identity; assertions about reviewed state use the request's review window. A primary deletion cannot erase a surviving replica.
5. **Policy:** load category actions from `deletion_rules.csv`. Delete subject-only copies; redact shared support/tombstone records; anonymize analytics; preserve required journals/holds; disable active flows and block unsafe restores. Never actually mutate source systems.
6. **Planning and validation:** generate findings, remediation, and verification in the exact operation-table order, then system/resource order. Incomplete future actions have empty citations; complete verification uses actual evidence. Validate row coverage, schema, ordering, authorization, and citation cutoff before writing the CSV.

## Limits and interpretation

The included evaluation report documents remaining failures, especially missing verification steps for already-unlinked records. The system never derives resource IDs from request numbers or copies expected answers. Missing attributable evidence produces a conservative `INCOMPLETE` with no invented findings. This is an audit proposal generator; it does not execute deletions. The required output schema cannot express an UNKNOWN verdict, missing retention recovery, or confidence, so those cases need human investigation rather than blind execution.

OCR extraction is imperfect, particularly for screenshots containing unrelated table rows. A small local language model can also misread subtle requests despite safeguards. Request-window evidence handling is conservative and may omit an older observation that still describes current state. Public validation demonstrates these practical limits; do not treat a COMPLETE result as a general legal certification.

## Files

- `main.py`: command-line runner, media extraction orchestration, output checks.
- `audit.py`: identity graph, evidence parsers, temporal state, policy planner.
- `local_model.py`: local inference, prompt, intent safeguards, token accounting.
- `ocr_windows.ps1`: Windows OCR adapter; Tesseract is the other-platform fallback.
- `evaluation/`: reproducible evaluator, synthetic cases, measured reports.

API references: [Ollama generation and structured outputs](https://docs.ollama.com/api/generate), [PyMuPDF text extraction](https://pymupdf.readthedocs.io/en/latest/page.html#Page.get_text).

Package only `code/` source and Markdown reports, excluding `__pycache__`, virtual environments, caches, datasets, nested archives, and credentials. Upload the generated `output.csv` and root `log.txt` separately.
