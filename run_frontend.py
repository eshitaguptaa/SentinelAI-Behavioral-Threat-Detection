#!/usr/bin/env python3
"""Print instructions to launch the SentinelAI React SOC dashboard.

This script intentionally does **not** spawn or manage Node/npm processes.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"


def main() -> None:
    """Display frontend setup and run commands."""
    load_dotenv(ROOT / ".env")
    api_base = os.getenv("VITE_API_BASE_URL", "http://127.0.0.1:8000").strip()

    print("=" * 64)
    print("SentinelAI — Frontend launch instructions")
    print("=" * 64)
    print()
    print("1. Ensure the FastAPI backend is running (python run_backend.py).")
    print(f"2. API base URL for Vite: {api_base}")
    print()
    if not FRONTEND.is_dir():
        print(f"ERROR: frontend directory not found at {FRONTEND}")
        raise SystemExit(1)

    print("3. In a new terminal, run:")
    print()
    print(f"   cd {FRONTEND}")
    print("   npm install")
    print(f'   set VITE_API_BASE_URL={api_base}          # Windows cmd')
    print(f'   $env:VITE_API_BASE_URL="{api_base}"       # Windows PowerShell')
    print(f'   export VITE_API_BASE_URL={api_base}       # macOS / Linux')
    print("   npm run dev")
    print()
    print("4. Open the URL printed by Vite (typically http://127.0.0.1:5173).")
    print()
    print("Optional: create frontend/.env containing:")
    print(f"   VITE_API_BASE_URL={api_base}")
    print("=" * 64)


if __name__ == "__main__":
    main()
