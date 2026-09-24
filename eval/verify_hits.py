"""
Interactive helper for Phase 4's manual verification step: walks you
through a detector's hits one at a time, shows the context, and lets you
assign a ground-truth category. Appends to (or creates) a labels.json file
in the same format eval/metrics.py expects -- so this is how you build
ground truth for the real-world repository sample, the same way the seed
corpus's labels.json was built by hand.

Designed to be resumable: already-labeled (file, line) pairs are skipped,
so you can label 50 hits today and 50 more tomorrow without redoing work.

Usage:
    python -m eval.verify_hits results/baseline_hits_realworld.json \\
        --repo-root data/repos/some_org__some_repo \\
        --labels-out data/real_world_labels.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

CATEGORIES = {
    "1": "real_secret",
    "2": "placeholder",
    "3": "test_fixture",
    "4": "non_secret_high_entropy",
    "5": "not_a_candidate",
    "s": "SKIP",   # can't tell / come back later
}


def load_existing_labels(path: Path) -> dict:
    if path.exists():
        data = json.loads(path.read_text())
        return {(l["file"], l["line"]): l for l in data.get("labels", [])}
    return {}


def show_context(repo_root: Path, file_rel: str, line_no: int, window: int = 4) -> None:
    file_path = repo_root / file_rel
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        print("  (could not read file)")
        return
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    for i in range(start, end):
        marker = ">>" if i == line_no - 1 else "  "
        print(f"  {marker} {i + 1}: {lines[i]}")


def main():
    ap = argparse.ArgumentParser(description="Manually label detector hits to build evaluation ground truth")
    ap.add_argument("hits_file", type=Path)
    ap.add_argument("--repo-root", type=Path, required=True)
    ap.add_argument("--labels-out", type=Path, required=True)
    ap.add_argument("--sample", type=int, default=None,
                     help="Only review a random-order stratified sample of N hits, not all of them "
                          "(useful for the real-world corpus, per proposal Section 7: 'a subset of "
                          "each tool's flagged hits is manually reviewed'). Omit to review every hit.")
    args = ap.parse_args()

    hits = json.loads(args.hits_file.read_text())
    if args.sample and len(hits) > args.sample:
        import random
        hits = random.sample(hits, args.sample)

    existing = load_existing_labels(args.labels_out)
    print(f"{len(hits)} hits loaded, {len(existing)} already labeled in {args.labels_out}\n")
    print("Categories: [1] real_secret  [2] placeholder  [3] test_fixture  "
          "[4] non_secret_high_entropy  [5] not_a_candidate  [s] skip for now  [q] quit\n")

    labeled = dict(existing)
    reviewed_this_session = 0

    for hit in hits:
        key = (hit["file"], hit["line"])
        if key in labeled and labeled[key]["category"] != "SKIP":
            continue

        print("=" * 70)
        print(f"File: {hit['file']}:{hit['line']}   rule={hit.get('rule_id', '?')}   "
              f"entropy={hit.get('entropy', '?')}   redacted={hit.get('matched_value_redacted', '?')}")
        show_context(args.repo_root, hit["file"], hit["line"])
        print()

        choice = input("Category [1-5/s/q]: ").strip().lower()
        if choice == "q":
            break
        category = CATEGORIES.get(choice)
        if category is None:
            print("  (unrecognized input, treating as skip)")
            category = "SKIP"

        labeled[key] = {"file": hit["file"], "line": hit["line"], "category": category, "note": "manually verified"}
        reviewed_this_session += 1

        # Save after every label, not just at the end -- don't lose work to a crash/Ctrl-C.
        final = {"labels": [v for v in labeled.values() if v["category"] != "SKIP"]}
        args.labels_out.parent.mkdir(parents=True, exist_ok=True)
        args.labels_out.write_text(json.dumps(final, indent=2))

    print(f"\nReviewed {reviewed_this_session} new items this session. "
          f"Total labeled (excluding skips): {len(json.loads(args.labels_out.read_text())['labels']) if args.labels_out.exists() else 0}")


if __name__ == "__main__":
    main()
