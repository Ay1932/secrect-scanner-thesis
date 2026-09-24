"""
Phase 2 baseline detector: regex pattern matching + Shannon entropy fallback.

This mirrors the Meli et al. (2019) / classical-baseline methodology your
thesis compares against: known-format regexes catch structured secrets,
entropy catches everything else that "looks random enough," and a simple
placeholder-word filter cuts the most obvious false positives before
anything is reported.

Usage:
    python -m scanner.baseline /path/to/repo --out results/baseline_hits.json
    python -m scanner.baseline /path/to/repo  # prints to stdout
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from scanner.patterns import PATTERNS, looks_like_placeholder

# Matches "name = 'value'" / "name: value" style assignments generically,
# used to find high-entropy candidates that don't match a known key format.
ASSIGNMENT_RE = re.compile(
    r"(?i)([A-Za-z_][A-Za-z0-9_]{2,40})\s*[=:]\s*[\"']([A-Za-z0-9/+_\-\.=]{%d,})[\"']"
    % config.MIN_CANDIDATE_LENGTH
)


@dataclass
class Hit:
    file: str
    line: int
    rule_id: str
    description: str
    matched_value_redacted: str
    entropy: float
    line_text: str
    source: str = "baseline"


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def redact(value: str) -> str:
    """Keep enough of the string to be useful for manual review without
    leaving a fully-intact, copy-pasteable secret sitting in a results file."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def should_skip_path(path: Path) -> bool:
    if any(part in config.SKIP_DIR_NAMES for part in path.parts):
        return True
    if path.suffix.lower() in config.SKIP_EXTENSIONS:
        return True
    return False


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not should_skip_path(path):
            yield path


def scan_line(line: str, line_no: int, relpath: str) -> list[Hit]:
    hits: list[Hit] = []
    matched_spans: list[tuple[int, int]] = []

    # 1. Known-format regex patterns
    for rule_id, pattern, description in PATTERNS:
        for m in pattern.finditer(line):
            value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            if looks_like_placeholder(value):
                continue
            hits.append(
                Hit(
                    file=relpath,
                    line=line_no,
                    rule_id=rule_id,
                    description=description,
                    matched_value_redacted=redact(value),
                    entropy=round(shannon_entropy(value), 2),
                    line_text=line.strip()[:200],
                )
            )
            matched_spans.append(m.span())

    # 2. Entropy fallback on generic assignments not already caught above
    for m in ASSIGNMENT_RE.finditer(line):
        span = m.span()
        if any(s <= span[0] < e or s < span[1] <= e for s, e in matched_spans):
            continue  # already matched by a known pattern
        var_name, value = m.group(1), m.group(2)
        if looks_like_placeholder(value) or looks_like_placeholder(var_name):
            continue
        ent = shannon_entropy(value)
        if ent >= config.ENTROPY_THRESHOLD:
            hits.append(
                Hit(
                    file=relpath,
                    line=line_no,
                    rule_id="high_entropy_candidate",
                    description=f"High-entropy value assigned to '{var_name}'",
                    matched_value_redacted=redact(value),
                    entropy=round(ent, 2),
                    line_text=line.strip()[:200],
                )
            )

    return hits


def scan_repo(repo_path: Path) -> list[Hit]:
    all_hits: list[Hit] = []
    for file_path in iter_text_files(repo_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        relpath = file_path.relative_to(repo_path).as_posix()
        for i, line in enumerate(text.splitlines(), start=1):
            if len(line) > 2000:
                continue  # skip minified/bundled lines, not worth scanning
            all_hits.extend(scan_line(line, i, relpath))
    return all_hits


def main():
    ap = argparse.ArgumentParser(description="Regex + entropy baseline secret scanner")
    ap.add_argument("path", type=Path, help="Directory to scan")
    ap.add_argument("--out", type=Path, default=None, help="Write JSON results here")
    args = ap.parse_args()

    hits = scan_repo(args.path)
    result = [asdict(h) for h in hits]

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"Wrote {len(result)} candidate hits to {args.out}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
