# Final full-dataset run: token usage and cost

The numbers below come from the actual Ollama `prompt_eval_count` and `eval_count`
fields returned during the run that generated `output.csv`. No paid API was used.
Model messages are deduplicated by exact full text; each uncached batch contains at most 12 messages.
The final run uses a separate cache directory to avoid relying on evaluation/calibration predictions.

| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Estimated API cost |
|---|---:|---:|---:|---:|---:|
| Ollama (local) / qwen2.5:1.5b | 32 | 17887 | 931 | 18818 | $0.00 |
| Overall | 32 | 17887 | 931 | 18818 | $0.00 |

- Requests processed: 518.
- Average tokens per request: 36.33 (34.53 input, 1.80 output).
- Average model calls per request: 0.0618.
- Duplicate/already-cached message occurrences: 143.
- Total and average API fees: $0.00 total; $0.00 per request. Hardware, electricity, and model download costs are not estimated.
- Evidence files read: 94; observations extracted: 2911.
- Status totals: {"COMPLETE": 155, "INCOMPLETE": 353, "NOT_APPLICABLE": 10}.

PDF text extraction, Windows OCR, SQLite processing, policy evaluation, and synthetic safety tests make no LLM calls.
Development calibration was separate: a combined 550-message full/public-sample pass made 34 local calls,
using 18,855 input tokens and 1,076 output tokens (19,931 total), also $0.00 in API fees.
Those development tokens are excluded from the final-run totals above.

Cached reruns make fewer calls; use an empty `--cache` directory to repeat cold-run accounting.
The local model prompt and schema are included in source; no credential is required.
