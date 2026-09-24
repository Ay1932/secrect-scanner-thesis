"""
Regex patterns for known secret formats.

This is the "pattern-based" half of the Phase 2 baseline (Meli et al. 2019
Phase 0/2 approach: survey real API key formats, then match against them).
Coverage isn't exhaustive by design -- the entropy fallback in baseline.py
catches high-entropy strings that don't match any of these -- but this list
covers the highest-impact / most commonly leaked types per the literature
(Google API keys, RSA private keys, AWS keys were the top three in Meli et al.).

Each entry: (rule_id, compiled regex, human-readable description).
Add new patterns here rather than inline in baseline.py.
"""
import re

# (rule_id, regex, description)
PATTERNS = [
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS Access Key ID",
    ),
    (
        "aws_secret_key_assignment",
        re.compile(
            r"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
        "AWS Secret Access Key (assignment context)",
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "Google API Key",
    ),
    (
        "google_oauth_id",
        re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"),
        "Google OAuth Client ID",
    ),
    (
        "github_token",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b"),
        "GitHub Personal Access / App Token",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
        "Slack Token",
    ),
    (
        "stripe_key",
        re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{24,247}\b"),
        "Stripe API Key",
    ),
    (
        "openai_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        "OpenAI API Key",
    ),
    (
        "anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "Anthropic API Key",
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
        "Asymmetric Private Key Header",
    ),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|passwd|password|access[_-]?key)\s*[=:]\s*"
            r"[\"']([A-Za-z0-9/+_\-=]{16,})[\"']"
        ),
        "Generic secret-like assignment (name + quoted value)",
    ),
    (
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "JSON Web Token",
    ),
]

# Strings that make a generic_secret_assignment / entropy hit almost
# certainly a false positive -- checked before anything is reported.
# This is the "word detection" filter from Meli et al. Phase 3.
PLACEHOLDER_MARKERS = (
    "example", "sample", "your_", "your-", "changeme", "change_me", "xxxx",
    "placeholder", "dummy", "fake", "test_key", "test-key", "insert_",
    "replace_with", "<your", "${", "{{", "process.env", "os.environ",
    "getenv", "TODO", "FIXME",
)


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in PLACEHOLDER_MARKERS)
