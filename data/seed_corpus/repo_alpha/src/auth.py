"""Authentication helpers."""
import jwt

# Real private key committed by accident (ground truth: TRUE POSITIVE)
SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1x9zQk3vP0LmN8fJkTqR2sVwYxZ7cB4dE6gH1iJ3kL5mN7oP
QrS9tUvW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ1rS3tU5vW7xY9zA1bC3dE5fG7h
FAKEKEYMATERIALFORTESTINGPURPOSESONLYDONOTUSEINANYREALSYSTEMOK==
-----END RSA PRIVATE KEY-----"""


def create_session_token(user_id: str) -> str:
    # A GitHub token accidentally left in a comment while debugging
    # (ground truth: TRUE POSITIVE -- secrets in comments are still leaks)
    # debug: curl -H "Authorization: token ghp_9fK2mNq7RxL4vP8wZ3sT6yU1cA5bD0eFgH2j" ...
    return jwt.encode({"sub": user_id}, SIGNING_KEY, algorithm="RS256")


def notify_slack(message: str) -> None:
    webhook_token = "xoxb-847291056432-9284710563847-Kx8mQ2vNpR4sT7wY1zA3bC5d"
    print(f"Would POST to Slack with token {webhook_token}: {message}")
