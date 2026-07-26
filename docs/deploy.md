# Deploy SentinelAI (API elsewhere + UI on Vercel)

You need **two** deployments:

```
Browser  →  Vercel (React UI)  →  Railway / Fly.io / VPS (FastAPI + Transformer .pt)
```

This guide uses **Railway** as the primary API host (no Render).

---

## Part A — Deploy the API on Railway

### A1. Push code to GitHub

The Transformer weights are gitignored (`*.pt`). Force-add them for deploy:

```bash
git add -f models/sentinelai_transformer.pt models/sentinelai_transformer.meta.json
git commit -m "Add Transformer artifact for deploy"
git push
```

### A2. Create the service

1. Open [railway.app](https://railway.app) → sign in with GitHub  
2. **New Project** → **Deploy from GitHub repo** → select this repo  
3. This repo includes `railway.toml` so Railway uses the root **Dockerfile**  
   (not Railpack). If a deploy fails with “No start command”, confirm  
   **Settings → Build → Builder** is **Dockerfile**, then redeploy.  

Fallback start command (Settings → Deploy → Custom Start Command), if needed.
**Must** use `sh -c` so `$PORT` expands (otherwise uvicorn gets the literal `$PORT`):

```bash
sh -c "exec uvicorn synthetic_data.api.app:app --host 0.0.0.0 --port $PORT"
```

Or clear the Custom Start Command and let the Dockerfile `CMD` handle it.

### A3. Variables (service → Variables)

| Name | Value |
|------|--------|
| `SENTINELAI_MODEL_PATH` | `models/sentinelai_transformer.pt` |
| `CORS_ALLOW_ORIGINS` | *(blank for now — fill in Part C)* |

Railway injects `PORT` automatically.

### A4. Public URL

1. Service → **Settings** → **Networking** → **Generate Domain**  
2. You’ll get something like:  
   `https://sentinelai-production-xxxx.up.railway.app`  
3. Test:  
   `https://YOUR-RAILWAY-URL/health`  
   and `/docs`

### A5. Model check

If `/predict` returns 503, the `.pt` file isn’t in the image. Confirm it was force-pushed, or add it via Railway’s volume / upload and point `SENTINELAI_MODEL_PATH` at that path.

---

## Alternative API hosts (if not Railway)

### Fly.io

```bash
# Once: install flyctl, then from repo root
fly launch --dockerfile Dockerfile --name sentinelai-api
fly secrets set SENTINELAI_MODEL_PATH=models/sentinelai_transformer.pt
fly deploy
```

Generate/open the `*.fly.dev` URL and hit `/health`.

### VPS (DigitalOcean / Linode / any Ubuntu box)

```bash
git clone <your-repo>
cd SentinelAI-Behavioral-Threat-Detection
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# ensure models/sentinelai_transformer.pt exists
export SENTINELAI_MODEL_PATH=models/sentinelai_transformer.pt
export CORS_ALLOW_ORIGINS=https://YOUR-APP.vercel.app
uvicorn synthetic_data.api.app:app --host 0.0.0.0 --port 8000
```

Put Nginx/Caddy in front for HTTPS, or use Cloudflare Tunnel.

---

## Part B — Deploy the UI on Vercel

Prefer the **website** (CLI often fails on corporate SSL networks).

1. [vercel.com/new](https://vercel.com/new) → import the same GitHub repo  
2. Settings:

| Setting | Value |
|---------|--------|
| Root Directory | `frontend` |
| Framework Preset | Vite |
| Build Command | `npm run build` |
| Output Directory | `dist` |

3. Environment variable (Production + Preview):

| Name | Value |
|------|--------|
| `VITE_API_BASE_URL` | `https://YOUR-RAILWAY-URL` *(no trailing slash)* |

4. Deploy → copy `https://….vercel.app`

---

## Part C — Connect CORS

On **Railway** (Variables):

```env
CORS_ALLOW_ORIGINS=https://YOUR-APP.vercel.app
```

Optional preview URLs (comma-separated):

```env
CORS_ALLOW_ORIGINS=https://YOUR-APP.vercel.app,https://YOUR-APP-git-main-you.vercel.app
```

Redeploy/restart the API, then **Redeploy** the Vercel project so `VITE_API_BASE_URL` is baked into the build.

### Quick test

1. Open the Vercel site → **Enter Platform**  
2. **Refresh** → API should show online  
3. **Run sample** → requests go to Railway  

---

## Checklist

- [ ] Railway `/health` works  
- [ ] `models/sentinelai_transformer.pt` on the API host  
- [ ] Vercel `VITE_API_BASE_URL` = Railway HTTPS URL  
- [ ] Railway `CORS_ALLOW_ORIGINS` = Vercel origin (exact match)  
- [ ] Frontend redeployed after setting the env var  

---

## Common failures

| Symptom | Fix |
|---------|-----|
| UI loads, API offline | Wrong `VITE_API_BASE_URL`, or Railway service not public |
| Browser CORS error | `CORS_ALLOW_ORIGINS` typo (must match origin exactly) |
| `/predict` 503 | Model `.pt` missing on Railway |
| Vercel CLI `fetch failed` | Use dashboard deploy |
| Docker build OOM on free tier | Use native Python start on Railway, or a paid instance |
