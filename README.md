# Secret Scanning Thesis — Project Code

Companion codebase for *Detecting Leaked Secrets in Public Code Repositories:
A Comparative Study of Pattern-Based and LLM-Assisted Scanning*. Implements
and evaluates three detectors side by side: a regex+entropy baseline, an
LLM-augmented version of that baseline, and the established tools
Gitleaks/TruffleHog — against the same repository sample, per the proposal's
Section 5 methodology.

Everything in this repo has been written and smoke-tested against the
included seed corpus. The two pieces that need external services (real
GitHub sampling, a live LLM) are validated for correctness but haven't been
run against live data yet — see "What's tested vs. what isn't" below.

## Layout

```
scanner/
  patterns.py        regex definitions for known secret formats
  baseline.py         Phase 2: regex + Shannon-entropy detector
  llm_classifier.py    Phase 3: LLM contextual re-classification layer
tools/
  run_baselines.py     wraps Gitleaks/TruffleHog, normalizes their output
data/
  seed_corpus/          hand-built repos with known ground truth (labels.json)
  fetch_repos.py         GitHub API stratified sampling + snapshot download
eval/
  metrics.py            precision/recall/F1 + McNemar's test
  verify_hits.py         interactive tool for labeling real-world hits
results/                 output lands here (gitignored except .gitkeep)
config.py                 all tunables in one place
.env.example              copy to .env and fill in secrets
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in GITHUB_TOKEN / ANTHROPIC_API_KEY as needed
```

For the local LLM backend (recommended primary — see the proposal's
Resources section for why): install [Ollama](https://ollama.com), then
`ollama pull qwen3:8b`. For the hosted backend, set `LLM_BACKEND=hosted` and
`ANTHROPIC_API_KEY` in `.env`.

For the tool-comparison baseline: install
[Gitleaks](https://github.com/gitleaks/gitleaks#installing) and
[TruffleHog](https://github.com/trufflesecurity/trufflehog#installation)
and confirm both are on `PATH` (`gitleaks version`, `trufflehog --version`).

## Walkthrough (mirrors the proposal's phase plan)

**Phase 2 — baseline scanner.** Try it against the included seed corpus
first, since that's what validates your setup end to end:

```bash
python -m scanner.baseline data/seed_corpus --out results/baseline_hits_seed.json
python -m eval.metrics \
  --ground-truth data/seed_corpus/labels.json \
  --detector baseline=results/baseline_hits_seed.json \
  --out results/metrics_summary.json
```

On the seed corpus as shipped, this scores **precision 0.818 / recall
0.818 / F1 0.818** (9 TP, 2 FP, 2 FN, 7 TN) — and that's deliberate, not a
bug. The 2 false positives are the two test-fixture API keys in
`tests/test_auth.py`: real-looking credentials that are actually inert
test values, which is *exactly* the class of error the LLM layer in Phase
3 exists to fix. The 2 false negatives are seeded edge cases the current
regex set can't catch by design — a 10-character short-lived token
(`config.py` line 27, below the entropy fallback's minimum length) and a
credential embedded in a connection URL rather than a `key=value`
assignment (`repo_beta/.env.production` line 11). Both are flagged inline
in the seed files and in `labels.json`, and both map directly to RQ3 in
the proposal ("what categories of secrets remain hardest to detect").
Tune `ENTROPY_THRESHOLD` and extend `scanner/patterns.py` against this
corpus before moving to real repositories.

**Phase 3 — LLM classification layer.**

```bash
python -m scanner.llm_classifier results/baseline_hits_seed.json \
  --repo-root data/seed_corpus \
  --out results/classified_seed.json

python -m eval.metrics \
  --ground-truth data/seed_corpus/labels.json \
  --detector baseline=results/baseline_hits_seed.json \
  --detector llm=results/classified_seed.json \
  --out results/metrics_summary.json
```

A correctly-behaving classifier should reclassify both `test_auth.py`
false positives as `test_fixture`, pushing precision from 0.818 to 1.0
while recall stays the same (the LLM layer only *filters*, it doesn't add
new detections) — this was validated with a simulated ideal classifier
during development; run it for real once your backend is configured, and
expect to spend real iteration time on the system prompt in
`scanner/llm_classifier.py` if results look off.

**Phase 4 — real-world sample + tool comparison.**

```bash
# 1. Sample and download real public repos (needs GITHUB_TOKEN in .env)
python -m data.fetch_repos --count 50 --languages python,javascript --out data/repos

# 2. Run all three/four detectors against each downloaded repo
python -m scanner.baseline data/repos/<org>__<repo> --out results/baseline_<repo>.json
python -m scanner.llm_classifier results/baseline_<repo>.json --repo-root data/repos/<org>__<repo> --out results/llm_<repo>.json
python -m tools.run_baselines data/repos/<org>__<repo> --tool both

# 3. Manually verify a sample of hits to build ground truth for THIS repo
python -m eval.verify_hits results/baseline_<repo>.json \
  --repo-root data/repos/<org>__<repo> \
  --labels-out data/real_world_labels.json \
  --sample 100

# 4. Compare
python -m eval.metrics --ground-truth data/real_world_labels.json \
  --detector baseline=results/baseline_<repo>.json \
  --detector llm=results/llm_<repo>.json \
  --detector gitleaks=results/gitleaks_hits.json \
  --detector trufflehog=results/trufflehog_hits.json \
  --out results/metrics_summary_<repo>.json
```

Repeat step 2–4 per downloaded repo, or write a small loop script once
you're comfortable with the individual commands — deliberately left as
separate steps here so each is easy to debug independently first.

## What's tested vs. what isn't

Actually run and verified in this environment: the baseline scanner (all
18 seed-corpus hits checked by hand against `labels.json`), the evaluation
harness (precision/recall/F1 and McNemar's test both validated, including
against a simulated classifier to confirm the LLM-aware filtering path),
the Gitleaks/TruffleHog wrapper's failure handling (degrades cleanly when
the binaries aren't installed), and the LLM classifier's prompt-building
and response-parsing logic (unit-tested against clean, messy, and
malformed model output).

Not run end-to-end here, because this sandbox has no outbound internet
beyond a couple of restricted tools: `data/fetch_repos.py` against the
real GitHub API, and `scanner/llm_classifier.py` against a live Ollama
server or the Anthropic API. Both are worth a small manual test run on
your own machine before trusting them at scale — start with `--count 3` on
`fetch_repos.py` and a handful of hits through `llm_classifier.py` to
confirm your API key / Ollama setup is correct before a full run.

## Ethics note

Per the proposal's Section 9, `data/fetch_repos.py` only reads public
repository content via the GitHub API within its rate limits, and nothing
in this repo attempts to validate or use a discovered credential against a
live service. If Phase 4 turns up a real, apparently-live secret in a real
repository, do not commit it anywhere (including `results/` or git
history) — record only the redacted form already produced by
`redact()` in `scanner/baseline.py` / `tools/run_baselines.py`, and follow
the responsible-disclosure note in the proposal before doing anything
else with it.
