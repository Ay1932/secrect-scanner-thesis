"""
Phase 3: LLM-based contextual classification layer.

Takes the candidate hits produced by scanner/baseline.py and asks an LLM
to judge each one using surrounding code context -- this is the piece that
targets the false-positive weakness of pure regex/entropy detection (see
Related Work: Rahman et al. 2025, Ahmed et al. 2024/25, Baby et al. 2026).

Supports two interchangeable backends, controlled by config.LLM_BACKEND:
  - "ollama": free, local, reproducible (recommended primary for the thesis)
  - "hosted": Anthropic API (secondary comparison point)

Usage:
    python -m scanner.llm_classifier results/baseline_hits_alpha.json \\
        --repo-root data/seed_corpus/repo_alpha \\
        --out results/classified_alpha.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

CATEGORIES = ["real_secret", "placeholder", "test_fixture", "non_secret_high_entropy"]

SYSTEM_PROMPT = """You are a security analyst reviewing a candidate secret flagged by an automated scanner in a source code repository. You will be shown the flagged line plus surrounding code context. Classify the flagged value into exactly one of these categories:

- real_secret: a credential that plausibly grants access to a live system if valid (API key, password, private key, token) and does not appear to be a placeholder or test fixture.
- placeholder: template/example text a developer is meant to replace (e.g. "your_api_key_here", "changeme", a vendor's own published documentation example key).
- test_fixture: a fake credential used intentionally in test code, clearly scoped to a test file or test function, not meant to be a real working secret.
- non_secret_high_entropy: a high-entropy string that is not a credential at all (a hash, UUID, generated ID, encoded asset reference).

Respond with ONLY a JSON object, no other text: {"category": "<one of the four above>", "confidence": <0-1 float>, "rationale": "<one sentence>"}"""


def build_context(repo_root: Path, file_rel: str, line_no: int) -> str:
    file_path = repo_root / file_rel
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    start = max(0, line_no - 1 - config.CONTEXT_WINDOW_LINES)
    end = min(len(lines), line_no + config.CONTEXT_WINDOW_LINES)
    numbered = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


def build_user_prompt(hit: dict, context: str) -> str:
    return (
        f"File: {hit['file']}\n"
        f"Flagged line: {hit['line']}\n"
        f"Detection rule: {hit['rule_id']} ({hit['description']})\n"
        f"Redacted value: {hit['matched_value_redacted']}\n"
        f"Entropy: {hit['entropy']}\n\n"
        f"Context:\n{context}\n\n"
        "Classify the flagged value per the categories in your instructions. "
        "JSON only."
    )


def parse_model_json(raw: str) -> dict:
    """Models occasionally wrap JSON in prose or code fences -- extract the
    first {...} block rather than assuming a clean response."""
    raw = raw.strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1:
        return {"category": "real_secret", "confidence": 0.0, "rationale": f"PARSE_FAILURE: {raw[:200]}"}
    try:
        parsed = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return {"category": "real_secret", "confidence": 0.0, "rationale": f"PARSE_FAILURE: {raw[:200]}"}
    if parsed.get("category") not in CATEGORIES:
        parsed["category"] = "real_secret"  # fail closed: unclear -> treat as real
        parsed.setdefault("rationale", "UNRECOGNIZED_CATEGORY, defaulted to real_secret")
    return parsed


def classify_with_ollama(system_prompt: str, user_prompt: str) -> str:
    import requests

    resp = requests.post(
        f"{config.OLLAMA_BASE_URL}/api/chat",
        json={
            "model": config.OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            # qwen3 is a hybrid-thinking model that otherwise emits a long
            # reasoning trace before the final answer -- this is what was
            # blowing past the timeout on roughly half of all calls in the
            # first full run. Classification here doesn't need chain-of-
            # thought, so disable it: same output format, much faster.
            "think": False,
            # keep the model resident between calls instead of letting
            # Ollama unload it and pay a cold-start reload on the next hit
            "keep_alive": "15m",
            "options": {"temperature": 0, "num_predict": 200},
        },
        timeout=config.LLM_TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def classify_with_hosted(system_prompt: str, user_prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    resp = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=200,
        temperature=0,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return resp.content[0].text


def classify_hit(hit: dict, repo_root: Path, retries: int = 2) -> dict:
    context = build_context(repo_root, hit["file"], hit["line"])
    user_prompt = build_user_prompt(hit, context)

    backend_fn = classify_with_ollama if config.LLM_BACKEND == "ollama" else classify_with_hosted

    last_err = None
    for attempt in range(retries + 1):
        try:
            raw = backend_fn(SYSTEM_PROMPT, user_prompt)
            result = parse_model_json(raw)
            return {**hit, **result, "backend": config.LLM_BACKEND, "model": config.OLLAMA_MODEL if config.LLM_BACKEND == "ollama" else config.ANTHROPIC_MODEL}
        except Exception as e:  # noqa: BLE001 -- log and retry, don't crash a whole run over one bad call
            last_err = e
            time.sleep(1.5 * (attempt + 1))

    return {**hit, "category": "real_secret", "confidence": 0.0, "rationale": f"CALL_FAILED after retries: {last_err}", "backend": config.LLM_BACKEND}


def _hit_key(hit: dict) -> tuple:
    return (hit["file"], hit["line"], hit["rule_id"])


def is_failed(entry: dict) -> bool:
    """True if a previously-classified entry is a call/parse failure that
    should be retried rather than trusted as-is."""
    rationale = entry.get("rationale", "")
    return "CALL_FAILED" in rationale or "PARSE_FAILURE" in rationale


def classify_all(hits: list[dict], repo_root: Path, checkpoint_path: Path | None = None) -> list[dict]:
    try:
        from tqdm import tqdm
        iterator = tqdm(hits, desc=f"classifying via {config.LLM_BACKEND}")
    except ImportError:
        print(f"(tip: pip install tqdm for a progress bar) classifying {len(hits)} hits via {config.LLM_BACKEND}...")
        iterator = hits

    results = []
    for hit in iterator:
        results.append(classify_hit(hit, repo_root))
        # Write after every item, not just at the end -- a slow local model
        # means a run can take minutes, and losing all progress to one
        # interrupted call is worse than a few extra small writes.
        if checkpoint_path is not None:
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            checkpoint_path.write_text(json.dumps(results, indent=2))
    return results


def main():
    ap = argparse.ArgumentParser(description="LLM contextual classification of baseline scanner hits")
    ap.add_argument("hits_file", type=Path, help="JSON output from scanner.baseline")
    ap.add_argument("--repo-root", type=Path, required=True, help="Root the file paths in hits_file are relative to")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--resume",
        type=Path,
        default=None,
        help="Path to a previous run's output. Entries that already classified "
        "successfully are kept as-is; only entries missing or marked "
        "CALL_FAILED/PARSE_FAILURE are re-sent to the LLM. Use this instead of "
        "re-running the whole corpus after a partial failure.",
    )
    args = ap.parse_args()

    hits = json.loads(args.hits_file.read_text())

    previous_by_key = {}
    if args.resume and args.resume.exists():
        previous_by_key = {_hit_key(e): e for e in json.loads(args.resume.read_text())}

    to_classify = [h for h in hits if is_failed(previous_by_key.get(_hit_key(h), {"rationale": "CALL_FAILED"}))] \
        if previous_by_key else hits
    already_ok = [previous_by_key[_hit_key(h)] for h in hits if _hit_key(h) in previous_by_key and not is_failed(previous_by_key[_hit_key(h)])]

    if previous_by_key:
        print(f"Resuming from {args.resume}: {len(already_ok)} already classified, "
              f"{len(to_classify)} to (re)classify")

    print(f"Classifying {len(to_classify)} candidate hits via backend={config.LLM_BACKEND} model="
          f"{config.OLLAMA_MODEL if config.LLM_BACKEND == 'ollama' else config.ANTHROPIC_MODEL}")

    checkpoint = args.out if args.out else None
    newly_classified = classify_all(to_classify, args.repo_root, checkpoint_path=checkpoint) if to_classify else []

    # Preserve original hit order in the final output.
    by_key = {_hit_key(e): e for e in already_ok + newly_classified}
    classified = [by_key[_hit_key(h)] for h in hits]

    still_failed = sum(1 for c in classified if is_failed(c))
    if still_failed:
        print(f"WARNING: {still_failed} hit(s) still failed after this run -- re-run with --resume to retry just those.")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(classified, indent=2))
        print(f"Wrote {len(classified)} classified hits to {args.out}")
    else:
        print(json.dumps(classified, indent=2))


if __name__ == "__main__":
    main()
