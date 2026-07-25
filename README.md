# SentinelAI

**Behavioural anomaly detection and risk intelligence for enterprise security operations.**

SentinelAI is an end-to-end cybersecurity platform that generates realistic enterprise activity, extracts behavioural features, detects anomalies with Isolation Forest, scores risk with deterministic rules, explains findings for SOC analysts, and exposes the full pipeline through FastAPI and a React SOC dashboard.

This repository is structured as a polished final-year / portfolio project suitable for demonstration, evaluation, and GitHub publication.

---

## Project Overview

SentinelAI answers a practical SOC question:

> Given one employee’s activity on one simulation day, how anomalous is the behaviour, how severe is the enterprise risk, and why?

The system is **strictly unsupervised for detection** (Isolation Forest) and **deterministic for risk & explainability** (no attack ground-truth leakage into production scoring).

---

## Architecture Diagram

```text
Timeline Events
        ↓
Feature Engineering          (Phase 8 — FeatureVector / ml_features)
        ↓
Isolation Forest             (Phase 9 — AnomalyPrediction)
        ↓
Risk Engine                  (Phase 10 — RiskAssessment)
        ↓
Explainability Engine        (Phase 11 — RiskExplanation)
        ↓
FastAPI Backend              (Phase 12 — REST /predict, /predict/batch)
        ↓
React SOC Dashboard          (Phase 13 — visualisation & investigation)
```

Supporting synthesis layers (Phases 1–7) produce the enterprise, behaviour profiles, multi-day timelines, and attack-injected datasets used for evaluation — not for live risk scoring labels.

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Synthetic data | Python, dataclasses, Faker |
| Feature engineering | Pure Python numerical features |
| Anomaly detection | scikit-learn Isolation Forest |
| Risk & explainability | Deterministic rule engines |
| API | FastAPI, Pydantic, Uvicorn |
| Dashboard | React 18+, TypeScript, Vite, Axios, Recharts |
| Tests | pytest |

---

## Installation

### Prerequisites

- Python **3.11+**
- Node.js **18+** and npm
- Git

### Clone

```bash
git clone <your-repo-url>
cd SentinelAI
```

### Python environment

```bash
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Environment file

```bash
copy .env.example .env          # Windows
# cp .env.example .env          # macOS / Linux
```

Edit `.env` and set `SENTINELAI_MODEL_PATH` after you create a fitted model (see below).

---

## Backend Setup

1. Activate the virtual environment and install `requirements.txt` (above).
2. Produce a fitted Isolation Forest artifact (one-time, outside the API):

```bash
python integration.py --prepare-model
```

This writes `models/sentinelai_iforest.joblib` and prints a sample end-to-end JSON result.

3. Point `.env` at that file:

```env
SENTINELAI_MODEL_PATH=models/sentinelai_iforest.joblib
API_HOST=127.0.0.1
API_PORT=8000
```

4. Start the API:

```bash
python run_backend.py
```

- OpenAPI / Swagger: http://127.0.0.1:8000/docs  
- Health: http://127.0.0.1:8000/health  

The API **never retrains** models. It only loads `SENTINELAI_MODEL_PATH`.

---

## Frontend Setup

```bash
cd frontend
npm install
```

Ensure the Vite app can reach the API (also documented in `.env.example`):

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

You can set this in `frontend/.env` or export it in your shell before `npm run dev`.

---

## Running Instructions

### Option A — helper scripts

```bash
# Terminal 1
python run_backend.py

# Terminal 2
python run_frontend.py
# then follow the printed npm commands
```

### Option B — manual

```bash
# Terminal 1
uvicorn synthetic_data.api.app:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2
cd frontend
npm run dev
```

### End-to-end Python demo (no UI)

```bash
python integration.py
```

### Tests

```bash
pytest tests/ -q
```

Tests use **mocks / deterministic fixtures** and do **not** retrain Isolation Forest models.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Application metadata |
| `GET` | `/health` | Liveness probe |
| `POST` | `/predict` | Single feature vector → anomaly + risk + explanation |
| `POST` | `/predict/batch` | Batch inference |

Example:

```bash
curl -X POST http://127.0.0.1:8000/predict ^
  -H "Content-Type: application/json" ^
  -d "{\"feature_vector\":{\"employee_id\":\"EMP-001\",\"simulation_day\":\"2026-03-10\",\"total_events\":40}}"
```

---

## Folder Structure

```text
SentinelAI/
├── README.md
├── requirements.txt
├── .env.example
├── run_backend.py
├── run_frontend.py
├── integration.py
├── tests/
│   ├── test_pipeline.py
│   ├── test_api.py
│   ├── test_risk_engine.py
│   └── test_explainability.py
├── synthetic_data/
│   ├── generators/          # Enterprise, profiles, timelines
│   ├── attacks/             # Attack injection techniques
│   ├── feature_engineering/ # Phase 8
│   ├── anomaly_detection/   # Phase 9
│   ├── risk_engine/         # Phase 10
│   ├── explainability/      # Phase 11
│   └── api/                 # Phase 12 FastAPI
├── frontend/                # Phase 13 React SOC dashboard
├── models/                  # Fitted Isolation Forest artifacts (local)
├── datasets/
├── docs/
└── backend/                 # Legacy / alternate FastAPI workspace
```

---

## Screenshots Placeholder

> **Screenshots** (add before submission / GitHub release):
>
> 1. SOC Dashboard overview — stats cards + risk distribution chart  
> 2. Employee table with CRITICAL / HIGH highlighting  
> 3. Explanation panel — summary, factors, observations, recommendation  
> 4. Swagger UI (`/docs`) showing `/predict` response  
>
> Place images under `docs/screenshots/` and link them here, for example:
>
> `![SOC Dashboard](docs/screenshots/dashboard.png)`

---

## Future Improvements

- Evaluation harness comparing Isolation Forest scores to simulator attack labels (offline only)
- Model registry & versioning for Isolation Forest artifacts
- Richer timeline → feature export from multi-day simulations into the dashboard
- Role-based access / SSO for production SOC deployments
- Alert routing (email / ticket) for CRITICAL assessments
- Hardened CORS and reverse-proxy deployment guides

---

## License

This project is provided for academic demonstration and portfolio use.

```text
MIT License (recommended for GitHub publication)

Copyright (c) 2026 SentinelAI contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

If your university or hackathon requires a different license, replace this section accordingly.
