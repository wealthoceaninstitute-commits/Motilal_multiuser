# Motilal Multi-User Trader (FastAPI)

This repo is a **Motilal-only** web backend (FastAPI) converted from your local CT_FastAPI logic.

## What’s included
- ✅ Motilal client login (MOFSLOPENAPI) + in-memory sessions
- ✅ Multi-user data isolation: `users/<user_id>/clients/motilal/*.json`
- ✅ Clients / Groups / Copy-trading setups
- ✅ Orders / Positions / Holdings / Summary
- ✅ Symbol search via `symbols.db` (rebuilt from GitHub CSV)
- ✅ Optional `/auth` (register + login) mounted from `auth/auth_router.py`

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -r requirements.txt
playwright install chromium --with-deps

uvicorn motilal_trader:app --reload --port 8080
```

API health:
- `GET /health`

## Multi-user usage

### Option A: Use /auth (recommended)
1. `POST /auth/register`  `{ "userid":"u1", "email":"u1@mail.com", "password":"pass" }`
2. `POST /auth/login`     `{ "userid":"u1", "password":"pass" }` → returns `{ userid: "u1" }`
3. Send this header for all trading endpoints:

```
X-User-Id: u1
```

### Option B: No auth
If you don’t want auth, just send `X-User-Id` directly from frontend.

## Env vars (optional GitHub storage)

If these are set, JSON will be read/written to your GitHub repo. Otherwise it will use local `./data`.

- `GITHUB_TOKEN`
- `GITHUB_REPO_OWNER`
- `GITHUB_REPO_NAME`
- `GITHUB_BRANCH` (default: `main`)
- `FRONTEND_ORIGINS` (comma-separated, or `*`)

## Deploy
Dockerfile is included. The container starts:

`uvicorn motilal_trader:app --host 0.0.0.0 --port 8080`
