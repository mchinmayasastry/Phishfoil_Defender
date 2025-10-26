# Vercel Python Serverless entrypoint for FastAPI (ASGI)
import sys
from pathlib import Path

# Add the 'phishguard' package to sys.path so we can import the app
repo_root = Path(__file__).resolve().parents[1]
phishguard_path = repo_root / "phishguard"
if str(phishguard_path) not in sys.path:
    sys.path.insert(0, str(phishguard_path))

# Import FastAPI app from your project
from src.api.app import app  # noqa: E402

# Vercel expects a top-level ASGI callable named `app`.
