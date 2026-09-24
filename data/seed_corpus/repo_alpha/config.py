"""Application configuration. Loaded at startup."""
import os

# --- Real secrets (ground truth: TRUE POSITIVE) -----------------------------
AWS_ACCESS_KEY_ID = "AKIAZP7K2M9QXR4TBWLK"
AWS_SECRET_ACCESS_KEY = "ODjfcRNL2EDLbdDZ1c5jAU2rjTbrNLwMtshF6PwK"
DATABASE_PASSWORD = "Xk9mP2vL8qRzT3nQ7w"

# --- AWS's own published example key (ground truth: PLACEHOLDER) ------------
# This is the literal example key from AWS's own documentation. A good
# scanner should recognize "EXAMPLE" and not flag it as a live secret.
DOCS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"

# --- Obvious placeholder (ground truth: PLACEHOLDER) -------------------------
API_KEY = "your_api_key_here"
STRIPE_KEY = "sk_test_replace_with_your_real_key_before_deploy"

# --- Loaded from environment, not hardcoded (ground truth: NOT A CANDIDATE) --
SESSION_SECRET = os.environ.get("SESSION_SECRET")

# --- Non-secret high-entropy value (ground truth: NON-SECRET HIGH ENTROPY) --
# A commit hash, not a credential -- but entropy-only detectors often flag it.
LAST_DEPLOY_COMMIT_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca49"

# --- Short-lived/edge-case token (ground truth: TRUE POSITIVE, edge case) ---
# Shorter than the typical 40-char threshold many scanners assume.
SHORT_LIVED_MFA_TOKEN = "Qz8vN2rXpL"
