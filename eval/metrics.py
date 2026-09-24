"""
Evaluation harness: precision / recall / F1 per detector against ground
truth, plus McNemar's test for whether two detectors' disagreements are
statistically significant (paired comparison, not independent samples --
see proposal Section 7).

Ground truth format (see data/seed_corpus/labels.json for the seeded
corpus, or eval/verify_hits.py for building one from manual review of a
real-world sample):
    {"labels": [{"file": ..., "line": ..., "category": "real_secret" | "placeholder"
                 | "test_fixture" | "non_secret_high_entropy" | "not_a_candidate"}, ...]}

Detector output format (what scanner/baseline.py, scanner/llm_classifier.py,
and tools/run_baselines.py all produce):
    [{"file": ..., "line": ..., "rule_id": ..., "category": <only if LLM-classified>, ...}, ...]

Usage:
    python -m eval.metrics \\
        --ground-truth data/seed_corpus/labels.json \\
        --detector baseline=results/baseline_hits_alpha.json \\
        --detector llm=results/classified_alpha.json \\
        --detector gitleaks=results/gitleaks_hits.json \\
        --out results/metrics_summary.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scipy.stats import chi2


def load_ground_truth(path: Path) -> dict[tuple[str, int], str]:
    data = json.loads(path.read_text())
    return {(entry["file"], entry["line"]): entry["category"] for entry in data["labels"]}


def load_detector_flags(path: Path, positive_categories: set[str] | None = None) -> set[tuple[str, int]]:
    """Returns the set of (file, line) keys this detector flagged as positive.

    For a raw regex/entropy or Gitleaks/TruffleHog output, EVERY hit counts
    as a positive prediction (that's the whole point of the comparison --
    they have no way to say "flagged, but I think it's fine").

    For LLM-classified output, only hits classified as "real_secret" count
    as positive -- everything reclassified as placeholder/test_fixture/
    non_secret_high_entropy is treated as the detector saying "not a secret."
    """
    hits = json.loads(path.read_text())
    flagged = set()
    for hit in hits:
        key = (hit["file"], hit["line"])
        if positive_categories is not None:
            if hit.get("category") in positive_categories:
                flagged.add(key)
        else:
            flagged.add(key)
    return flagged


def confusion_counts(flagged: set[tuple[str, int]], ground_truth: dict[tuple[str, int], str]):
    """TP/FP/FN/TN against every labeled item in ground truth (not just
    items the detector happened to flag) -- this is what makes recall and
    true-negative-based stats meaningful rather than just precision."""
    tp = fp = fn = tn = 0
    for key, category in ground_truth.items():
        is_real = category == "real_secret"
        was_flagged = key in flagged
        if is_real and was_flagged:
            tp += 1
        elif not is_real and was_flagged:
            fp += 1
        elif is_real and not was_flagged:
            fn += 1
        else:
            tn += 1

    # Anything the detector flagged that ISN'T in ground truth at all (e.g.
    # a real-world hit nobody has manually verified yet) is reported
    # separately rather than silently dropped or silently counted as a TP.
    unverified = len(flagged - set(ground_truth.keys()))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "unverified": unverified}


def precision_recall_f1(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def mcnemar_test(flagged_a: set, flagged_b: set, ground_truth: dict) -> dict:
    """Paired significance test for whether detector A and B differ, using
    only the cases where they disagree (b = A right & B wrong, c = A wrong
    & B right, in the sense of matching ground truth's is-a-secret label).
    Uses the continuity-corrected chi-square form; falls back to reporting
    raw discordant counts when the sample is too small for the
    approximation to be reliable (b + c < 25 is a common rule of thumb --
    use an exact binomial test by hand in that case instead)."""
    b = c = 0  # b: A correct & B incorrect, c: A incorrect & B correct
    for key, category in ground_truth.items():
        is_real = category == "real_secret"
        a_correct = (key in flagged_a) == is_real
        b_correct = (key in flagged_b) == is_real
        if a_correct and not b_correct:
            b += 1
        elif b_correct and not a_correct:
            c += 1

    if b + c == 0:
        return {"b": b, "c": c, "statistic": 0.0, "p_value": 1.0, "note": "no discordant pairs -- detectors agree on every labeled item"}

    statistic = (abs(b - c) - 1) ** 2 / (b + c)
    p_value = float(chi2.sf(statistic, df=1))
    note = None if (b + c) >= 25 else "b+c < 25: chi-square approximation may be unreliable, consider an exact binomial test"
    return {"b": b, "c": c, "statistic": round(statistic, 4), "p_value": round(p_value, 4), "note": note}


def evaluate(ground_truth_path: Path, detector_paths: dict[str, Path]) -> dict:
    ground_truth = load_ground_truth(ground_truth_path)
    llm_positive_categories = {"real_secret"}

    flagged_by_detector = {}
    for name, path in detector_paths.items():
        is_llm_classified = "category" in json.loads(path.read_text())[0] if json.loads(path.read_text()) else False
        flagged_by_detector[name] = load_detector_flags(
            path, positive_categories=llm_positive_categories if is_llm_classified else None
        )

    summary = {"ground_truth_size": len(ground_truth), "detectors": {}}
    for name, flagged in flagged_by_detector.items():
        counts = confusion_counts(flagged, ground_truth)
        metrics = precision_recall_f1(counts["tp"], counts["fp"], counts["fn"])
        summary["detectors"][name] = {**counts, **metrics}

    summary["pairwise_mcnemar"] = {}
    names = list(flagged_by_detector.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b_name = names[i], names[j]
            key = f"{a}_vs_{b_name}"
            summary["pairwise_mcnemar"][key] = mcnemar_test(
                flagged_by_detector[a], flagged_by_detector[b_name], ground_truth
            )

    return summary


def main():
    ap = argparse.ArgumentParser(description="Compute precision/recall/F1 and McNemar's test across detectors")
    ap.add_argument("--ground-truth", type=Path, required=True)
    ap.add_argument(
        "--detector", action="append", required=True,
        help="name=path/to/hits.json, repeatable, e.g. --detector baseline=results/baseline_hits.json",
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    detector_paths = {}
    for spec in args.detector:
        name, _, path = spec.partition("=")
        detector_paths[name] = Path(path)

    summary = evaluate(args.ground_truth, detector_paths)

    print(f"\n{'Detector':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Unverif.':>9}  {'Precision':>9} {'Recall':>7} {'F1':>6}")
    for name, d in summary["detectors"].items():
        print(f"{name:<12} {d['tp']:>4} {d['fp']:>4} {d['fn']:>4} {d['tn']:>4} {d['unverified']:>9}  "
              f"{d['precision']:>9.3f} {d['recall']:>7.3f} {d['f1']:>6.3f}")

    print("\nPairwise McNemar's test (b = discordant favoring first, c = favoring second):")
    for pair, result in summary["pairwise_mcnemar"].items():
        sig = "significant (p<0.05)" if result["p_value"] < 0.05 else "not significant"
        print(f"  {pair}: b={result['b']} c={result['c']} chi2={result['statistic']} p={result['p_value']} -> {sig}")
        if result.get("note"):
            print(f"    note: {result['note']}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(summary, indent=2))
        print(f"\nWrote full summary to {args.out}")


if __name__ == "__main__":
    main()
