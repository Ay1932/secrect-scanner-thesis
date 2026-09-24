"""
Central configuration for the secret-scanning thesis pipeline.

Everything that varies between a quick local test run and a full
evaluation run lives here, so scripts don't need their own flags
scattered around. Copy `.env.example` to `.env` and fill in secrets
(API keys) rather than editing this file directly for those.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
SEED_CORPUS_DIR = DATA_DIR / "seed_corpus"
REPOS_DIR = DATA_DIR / "repos"          # downloaded real-world repos land here
RESULTS_DIR = ROOT_DIR / "results"

# ---------------------------------------------------------------------------
# LLM classification backend
# ---------------------------------------------------------------------------
# "ollama"  -> free, local, reproducible (recommended primary for the thesis)
# "hosted"  -> Anthropic API, used as a secondary comparison point
LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama")

# Local (Ollama) settings
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
# Raised from the original 120s: qwen3:8b on CPU occasionally still takes
# longer than that per call even with thinking disabled, and a timeout here
# just becomes a wasted retry rather than an actual speedup.
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "180"))

# Hosted (Anthropic) settings
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

# ---------------------------------------------------------------------------
# GitHub data collection
# ---------------------------------------------------------------------------
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")  # personal access token, read-only scope is enough

# ---------------------------------------------------------------------------
# Detection tuning
# ---------------------------------------------------------------------------
# Shannon entropy threshold above which a non-pattern-matched string is
# still flagged as a candidate secret. 4.0-4.5 is a common starting point;
# tune this against the seed corpus in Phase 2.
ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", "4.3"))
MIN_CANDIDATE_LENGTH = 16  # ignore short strings, too noisy to score meaningfully

# How many lines of context (before/after) to send the LLM classifier
CONTEXT_WINDOW_LINES = 6

# File extensions/dirs to skip entirely (binary, vendored, generated)
SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv"}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so",
}
