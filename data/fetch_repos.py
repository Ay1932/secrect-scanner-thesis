"""
Stratified sampling of public GitHub repositories for the real-world half
of the evaluation (Section 7 of the proposal). Downloads a tarball snapshot
of each repo's default branch -- NOT a live clone -- so your evaluation is
against a fixed, reproducible snapshot rather than a moving target.

Ethics note (see proposal Section 9): this only reads public repository
content via the GitHub API within its documented rate limits. It does not
attempt to use, validate, or exploit anything found. Read that section
before running this against real repositories at any scale.

Usage:
    python -m data.fetch_repos --count 50 --languages python,javascript --out data/repos
    python -m data.fetch_repos --count 50 --languages python --min-size 100 --max-size 5000
"""
from __future__ import annotations

import argparse
import io
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config


def get_github_client():
    from github import Github, Auth

    if not config.GITHUB_TOKEN:
        print(
            "WARNING: no GITHUB_TOKEN set in .env -- you'll be limited to ~60 "
            "unauthenticated requests/hour instead of 5,000. Set one for any "
            "real sampling run.",
            file=sys.stderr,
        )
        return Github()
    return Github(auth=Auth.Token(config.GITHUB_TOKEN))


def stratified_sample(gh, count: int, languages: list[str], min_size_kb: int, max_size_kb: int):
    """Pull `count` repos roughly evenly split across `languages`, filtered
    by repo size (in KB, as GitHub reports it) to avoid both toy repos and
    unmanageably large monorepos skewing the sample."""
    per_language = max(1, count // len(languages))
    sampled = []

    for lang in languages:
        query = f"language:{lang} size:{min_size_kb}..{max_size_kb} is:public archived:false"
        try:
            results = gh.search_repositories(query=query, sort="stars", order="desc")
        except Exception as e:  # noqa: BLE001
            print(f"Search failed for language={lang}: {e}", file=sys.stderr)
            continue

        taken = 0
        for repo in results:
            if taken >= per_language:
                break
            sampled.append(repo)
            taken += 1
            time.sleep(0.2)  # stay well under secondary rate limits

    return sampled[:count]


def download_snapshot(repo, dest_root: Path) -> Path | None:
    """Downloads the repo's default-branch tarball and extracts it, giving
    a fixed point-in-time snapshot rather than a live git clone."""
    import requests

    dest = dest_root / repo.full_name.replace("/", "__")
    if dest.exists():
        return dest  # already fetched in a previous run

    try:
        url = repo.get_archive_link("tarball", ref=repo.default_branch)
    except Exception as e:  # noqa: BLE001
        print(f"Could not get archive link for {repo.full_name}: {e}", file=sys.stderr)
        return None

    resp = requests.get(url, timeout=60)
    if resp.status_code != 200:
        print(f"Download failed for {repo.full_name}: HTTP {resp.status_code}", file=sys.stderr)
        return None

    try:
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
            dest.mkdir(parents=True, exist_ok=True)
            tar.extractall(dest, filter="data")  # 'data' filter: refuse unsafe paths/links (Python 3.12+)
    except Exception as e:  # noqa: BLE001
        print(f"Extraction failed for {repo.full_name}: {e}", file=sys.stderr)
        return None

    return dest


def main():
    ap = argparse.ArgumentParser(description="Stratified sampling + snapshot download of public GitHub repos")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--languages", type=str, default="python,javascript,java,go",
                     help="comma-separated GitHub search language filters")
    ap.add_argument("--min-size", type=int, default=50, help="min repo size in KB")
    ap.add_argument("--max-size", type=int, default=20000, help="max repo size in KB")
    ap.add_argument("--out", type=Path, default=config.REPOS_DIR)
    args = ap.parse_args()

    languages = [l.strip() for l in args.languages.split(",") if l.strip()]
    args.out.mkdir(parents=True, exist_ok=True)

    gh = get_github_client()
    print(f"Sampling ~{args.count} repos across languages={languages} "
          f"(size {args.min_size}-{args.max_size} KB)...")
    repos = stratified_sample(gh, args.count, languages, args.min_size, args.max_size)
    print(f"Selected {len(repos)} repos. Downloading snapshots to {args.out} ...")

    manifest = []
    for repo in repos:
        dest = download_snapshot(repo, args.out)
        if dest:
            manifest.append({
                "full_name": repo.full_name,
                "language": repo.language,
                "size_kb": repo.size,
                "stars": repo.stargazers_count,
                "default_branch": repo.default_branch,
                "local_path": str(dest),
            })
            print(f"  ok: {repo.full_name}")

    manifest_path = args.out / "manifest.json"
    import json
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nDownloaded {len(manifest)}/{len(repos)} repos. Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
