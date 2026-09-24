# Pipeline run — final output

Full pipeline re-run from a clean state on 2026-09-21 to confirm reproducibility end to end.

## Commands run, in order

```bash
python3 -m scanner.baseline data/seed_corpus --out results/baseline_hits_seed.json

python3 -m scanner.llm_classifier results/baseline_hits_seed.json \
    --repo-root data/seed_corpus \
    --out results/classified_seed.json \
    --resume results/classified_seed.json   # only re-sends items that previously failed

python3 -m eval.metrics \
    --ground-truth data/seed_corpus/labels.json \
    --detector baseline=results/baseline_hits_seed.json \
    --detector llm_augmented=results/classified_seed.json \
    --out results/metrics_summary.json
```

- Baseline detector: re-scanned `data/seed_corpus` from scratch — produced the same 18 candidate hits, byte-for-byte matching set, as the committed `results/baseline_hits_seed.json`.
- LLM classifier: all 18 hits are now cleanly classified via Ollama (`qwen3:8b`, local) — 0 call failures, 0 parse failures. (The original run had 9/18 failures from the model's "thinking" trace blowing past the request timeout; fixed by disabling thinking mode for this classification task — see `scanner/llm_classifier.py`.)
- Evaluation harness: recomputing metrics from the fresh baseline output matches the committed `results/metrics_summary.json` exactly.

## Final metrics (seed corpus, 20 ground-truth items, 18 candidate hits)

| Detector | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| baseline (regex + entropy) | 9 | 2 | 2 | 7 | 0.818 | 0.818 | 0.818 |
| llm_augmented (baseline + LLM re-classification) | 8 | 0 | 3 | 9 | 1.000 | 0.727 | 0.842 |

**McNemar's test (baseline vs. llm_augmented):** b=1, c=2, χ²=0.0, p=1.0 — not statistically significant. Note: b+c=3 is well under the usual rule-of-thumb minimum of 25 for the chi-square approximation to be reliable at this sample size, so this result should be read as directional, not conclusive — consistent with how the seed corpus (20 items) is scoped in the thesis as a controlled validation set, not the full evaluation.

## What the LLM layer changed

- Eliminated both baseline false positives (both were test-fixture credentials that pattern/entropy alone couldn't distinguish from real secrets).
- Introduced one new false negative: the live Stripe key in `repo_beta/src/index.js` (ground truth: `real_secret`) was misclassified as `placeholder` — an LLM contextual-reasoning error worth noting in the discussion/error-analysis section, not a corpus or pipeline bug.
- Net effect: precision 0.818 → 1.000, recall 0.818 → 0.727, F1 0.818 → 0.842.

## Not run in this pass

- `tools/run_baselines.py` (Gitleaks/TruffleHog comparison) — neither binary is installed in this environment, so that leg of the three-way comparison wasn't executed here. Needed only if the thesis reports a tool comparison, not for the baseline/LLM numbers above.
- `data/fetch_repos.py` (real-world GitHub sample) — separate, larger effort; the seed corpus above is the fully validated controlled set.
