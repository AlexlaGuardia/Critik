"""Secrets read from the environment — no hardcoded values. Should NOT flag."""
import os

# All pulled from env at runtime. This is the correct pattern; a scanner that flags
# these is producing a false positive.
AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY")
DATABASE_URL = os.environ["DATABASE_URL"]
SLACK_TOKEN = os.getenv("SLACK_BOT_TOKEN")
API_KEY = os.environ["SERVICE_API_KEY"]


def connect():
    return {
        "db": DATABASE_URL,
        "aws": (AWS_ACCESS_KEY, AWS_SECRET),
        "headers": {"Authorization": f"Bearer {API_KEY}"},
    }
