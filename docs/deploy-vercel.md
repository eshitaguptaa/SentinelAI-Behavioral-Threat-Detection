# Deploy SentinelAI frontend to Vercel

> API must run on **Railway / Fly / VPS** — not Vercel. Full guide: [`deploy.md`](deploy.md).

## Dashboard deploy (recommended)

1. [vercel.com/new](https://vercel.com/new) → import GitHub repo  
2. Root Directory: `frontend`  
3. Env: `VITE_API_BASE_URL=https://your-api.up.railway.app`  
4. Deploy  

## After you have the Vercel URL

On the API host set:

```env
CORS_ALLOW_ORIGINS=https://your-app.vercel.app
```

Then redeploy both sides if needed.
