# Demo script — Kill-chain campaign (≈30 seconds)

1. Start API + SOC UI (`python run_backend.py`, then the Vite frontend).
2. Open `/app` → **Try sample data**.
3. Sample batch auto-selects **EMP-K01 / 2026-03-09** (Lateral Movement stage).
4. Go to **Investigate** — Kill chain panel shows 3 stages:
   Brute Force (03-08) → Lateral Movement (03-09) → Mass Download (03-10).
5. Expand a stage → MITRE technique + contributing factors.
6. Click **Open this stage as case** to jump along the chain.

API used: `POST /correlate/campaigns` on the scored batch (no retrain).
