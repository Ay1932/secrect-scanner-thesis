"""
Runs Gitleaks and/or TruffleHog against a target directory and normalizes
their output into the same schema scanner/baseline.py produces:
    {file, line, rule_id, description, matched_value_redacted, entropy, line_text, source}

This is what makes the three-way comparison in eval/metrics.py possible --
every detector's output ends up in one shared shape regardless of how the
underlying tool reports things.

Requires the `gitleaks` and/or `trufflehog` binaries to be installed and on
PATH. Install (one-time, not part of the Python requirements):
    # Gitleaks: https://github.com/gitleaks/gitleaks#installing
    # TruffleHog: https://github.com/trufflesecurity/trufflehog#installation

Usage:
    python -m tools.run_baselines /path/to/repo --tool gitleaks --out results/gitleaks_hits.json
    python -m tools.run_baselines /path/to/repo --tool trufflehog --out results/trufflehog_hits.json
    python -m tools.run_baselines /path/to/repo --tool both
"""
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def check_binary(name: str) -> bool:
    if shutil.which(name) is None:
        print(f"WARNING: '{name}' not found on PATH -- install it first (see module docstring). Skipping.", file=sys.stderr)
        return False
    return True


def run_gitleaks(target: Path) -> list[dict]:
    if not check_binary("gitleaks"):
        return []
    report_path = target.parent / f"_gitleaks_report_{target.name}.json"
    cmd = [
        "gitleaks", "detect",
        "--source", str(target),
        "--no-git",  # scan working tree, not just commit history -- matches our own scanner's scope
        "--report-format", "json",
        "--report-path", str(report_path),
        "--exit-code", "0",  # don't fail the process just because it found things
    ]
    subprocess.run(cmd, capture_output=True, text=True)
    if not report_path.exists():
        return []
    raw = json.loads(report_path.read_text() or "[]")
    report_path.unlink(missing_ok=True)

    normalized = []
    for finding in raw:
        value = finding.get("Secret", "")
        normalized.append({
            "file": finding.get("File", ""),
            "line": finding.get("StartLine", -1),
            "rule_id": finding.get("RuleID", "gitleaks_unknown"),
            "description": finding.get("Description", ""),
            "matched_value_redacted": redact(value),
            "entropy": round(finding.get("Entropy", shannon_entropy(value)), 2),
            "line_text": (finding.get("Match", "") or "")[:200],
            "source": "gitleaks",
        })
    return normalized


def run_trufflehog(target: Path) -> list[dict]:
    if not check_binary("trufflehog"):
        return []
    cmd = ["trufflehog", "filesystem", str(target), "--json", "--no-update"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    normalized = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = finding.get("Raw", "")
        source_meta = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        normalized.append({
            "file": source_meta.get("file", ""),
            "line": source_meta.get("line", -1),
            "rule_id": finding.get("DetectorName", "trufflehog_unknown"),
            "description": finding.get("DetectorName", ""),
            "matched_value_redacted": redact(value),
            "entropy": round(shannon_entropy(value), 2),
            "line_text": "",  # TruffleHog doesn't return the raw line by default
            "source": "trufflehog",
        })
    return normalized


def main():
    ap = argparse.ArgumentParser(description="Run Gitleaks/TruffleHog and normalize output for comparison")
    ap.add_argument("path", type=Path)
    ap.add_argument("--tool", choices=["gitleaks", "trufflehog", "both"], default="both")
    ap.add_argument("--out", type=Path, default=None, help="For a single tool. Ignored with --tool both (writes both files next to results/).")
    args = ap.parse_args()

    if args.tool in ("gitleaks", "both"):
        hits = run_gitleaks(args.path)
        out = args.out if args.tool == "gitleaks" and args.out else Path("results/gitleaks_hits.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print(f"Gitleaks: {len(hits)} hits -> {out}")

    if args.tool in ("trufflehog", "both"):
        hits = run_trufflehog(args.path)
        out = args.out if args.tool == "trufflehog" and args.out else Path("results/trufflehog_hits.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print(f"TruffleHog: {len(hits)} hits -> {out}")


if __name__ == "__main__":
    main()
