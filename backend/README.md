# SentinelAI Backend

FastAPI service for the SentinelAI cybersecurity platform.

## Structure

```
backend/
├── api/           # Route / router modules
├── core/          # App configuration & shared settings
├── database/      # Database engine, session, migrations hooks
├── models/        # SQLAlchemy ORM models
├── schemas/       # Pydantic request/response schemas
├── services/      # Business/service layer
├── websocket/     # WebSocket handlers
├── ml/            # ML inference helpers used by the API
├── utils/         # Shared utilities
├── main.py        # Application entrypoint
├── requirements.txt
└── .venv/         # Local virtual environment (not committed)
```

## Setup

```bash
# Create venv (already scaffolded as .venv)
python -m venv .venv

# Activate (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate (macOS/Linux)
# source .venv/bin/activate

pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --reload
```

API docs (once running): `http://127.0.0.1:8000/docs`

## Dependencies

- fastapi
- uvicorn
- sqlalchemy
- pydantic
- pandas
- numpy
- faker
- python-dotenv
- websockets

## Notes

Application logic, models, and routes beyond a health check are not implemented yet.
