# motilal_trader.py
"""
Motilal Trader (Multiuser) — Clients/Groups stored in GitHub per user + Auth + Motilal login sessions

v1.2 changes:
- Add "login for all clients" (background) using CT_FastAPI.py logic as reference.
- When a client is added, backend triggers background login for that client.
- New endpoint: POST /login_all_clients  (logs in all clients of the logged-in user)
- Client "session" and "session_active" are persisted back to GitHub (so UI updates from pending → active/failed).
"""

import os
import re
import json
import time
import math
import base64
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests
import pyotp
from fastapi import FastAPI, Request, Body, Query, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ---- Your Motilal SDK (must exist in the Render container) ----
from MOFSLOPENAPI import MOFSLOPENAPI  # type: ignore

# ---- Auth router (your existing auth module) ----
from auth.auth_router import router as auth_router  # type: ignore


###############################################################################
# App
###############################################################################

app = FastAPI(title="Motilal Trader (Multiuser)", version="1.2")

# CORS
_origins = [o.strip() for o in (os.getenv("FRONTEND_ORIGINS") or os.getenv("ALLOWED_ORIGINS") or "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins if _origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount auth router at /auth
app.include_router(auth_router, prefix="/auth")


###############################################################################
# Motilal constants (from CT_FastAPI reference)
###############################################################################

BASE_URL = os.getenv("MOFSL_BASE_URL", "https://openapi.motilaloswal.com")
SOURCE_ID = os.getenv("MOFSL_SOURCE_ID", "Desktop")
BROWSER_NAME = os.getenv("MOFSL_BROWSER_NAME", "chrome")
BROWSER_VERSION = os.getenv("MOFSL_BROWSER_VERSION", "104")

# Active sessions in-memory: (owner_userid, client_userid) -> (Mofsl, client_userid)
mofsl_sessions: Dict[Tuple[str, str], Tuple[Any, str]] = {}
mofsl_sessions_lock = threading.Lock()


###############################################################################
# GitHub storage config
###############################################################################

@app.get("/debug_env")
def debug_env():
    """Safe env diagnostics (does NOT expose secrets)."""
    missing = _github_missing()
    return {
        "github_configured": len(missing) == 0,
        "missing": missing,
        "github_owner_set": bool(GITHUB_OWNER),
        "github_repo_set": bool(GITHUB_REPO),
        "github_branch": GITHUB_BRANCH,
        "github_data_root": GITHUB_DATA_ROOT,
        "github_token_len": len(GITHUB_TOKEN) if GITHUB_TOKEN else 0,
    }

GITHUB_OWNER = _env_first("GITHUB_OWNER", "GITHUB_REPO_OWNER")
GITHUB_REPO = _env_first("GITHUB_REPO", "GITHUB_REPO_NAME")
GITHUB_BRANCH = _env_first("GITHUB_BRANCH", default="main") or "main"
GITHUB_TOKEN = _env_first("GITHUB_TOKEN", "GITHUB_PAT", "GITHUB_ACCESS_TOKEN")

# Root folder in repo that contains "users/...". Typical: "data"
GITHUB_DATA_ROOT = (_env_first("GITHUB_DATA_ROOT", "GITHUB_ROOT", "DATA_ROOT", default="data").strip().strip("/") or "data")

def _github_enabled() -> bool:
    return bool(GITHUB_OWNER and GITHUB_REPO and GITHUB_TOKEN)

def _gh_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def _gh_contents_url(path: str) -> str:
    path = path.lstrip("/")
    return f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"

def gh_get_json(path: str, default: Any) -> Any:
    """
    Read JSON from GitHub repo contents. Returns default if not found.
    """
    if not _github_enabled():
        raise HTTPException(status_code=503, detail="GitHub storage not configured. Set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN in Render Environment.")
    url = _gh_contents_url(path)
    r = requests.get(url, headers=_gh_headers(), params={"ref": GITHUB_BRANCH}, timeout=30)
    if r.status_code == 404:
        return default
    if r.status_code >= 400:
        raise HTTPException(status_code=500, detail=f"GitHub GET failed ({r.status_code}): {r.text[:300]}")
    data = r.json()
    content_b64 = (data.get("content") or "").encode("utf-8")
    if not content_b64:
        return default
    raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except Exception:
        return default

def gh_put_json(path: str, obj: Any, message: str) -> None:
    """
    Create or update JSON file in GitHub repo contents.
    """
    if not _github_enabled():
        raise HTTPException(status_code=503, detail="GitHub storage not configured. Set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN in Render Environment.")
    url = _gh_contents_url(path)

    # Get sha if exists
    sha = None
    r0 = requests.get(url, headers=_gh_headers(), params={"ref": GITHUB_BRANCH}, timeout=30)
    if r0.status_code == 200:
        sha = r0.json().get("sha")
    elif r0.status_code not in (404,):
        raise HTTPException(status_code=500, detail=f"GitHub preflight failed ({r0.status_code}): {r0.text[:200]}")

    payload = {
        "message": message,
        "content": base64.b64encode(json.dumps(obj, indent=2).encode("utf-8")).decode("utf-8"),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=_gh_headers(), json=payload, timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=500, detail=f"GitHub PUT failed ({r.status_code}): {r.text[:300]}")


###############################################################################
# Multiuser paths
###############################################################################

def _safe_userid(u: str) -> str:
    u = (u or "").strip()
    # handle "pra" (with quotes) from frontend logs
    u = u.strip('"').strip("'").strip()
    # allow simple ids only
    u = re.sub(r"[^a-zA-Z0-9_\-\.@]", "", u)
    return u

def _request_userid(request: Request) -> str:
    # Prefer header from frontend; allow query fallback for compatibility
    u = request.headers.get("X-User-Id") or request.query_params.get("userid") or request.query_params.get("user_id") or ""
    u = _safe_userid(u)
    if not u:
        raise HTTPException(status_code=401, detail="Missing user. Send X-User-Id header (or userid query param).")
    return u

def user_clients_path(owner_userid: str) -> str:
    return f"{GITHUB_DATA_ROOT}/users/{owner_userid}/clients.json"

def user_groups_path(owner_userid: str) -> str:
    return f"{GITHUB_DATA_ROOT}/users/{owner_userid}/groups.json"


###############################################################################
# Clients storage model
###############################################################################

def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _client_key(client: Dict[str, Any]) -> str:
    # Unique in UI: broker-client_id ; here single broker "motilal"
    cid = str(client.get("client_id") or client.get("userid") or "").strip()
    return f"motilal-{cid}"

def load_clients(owner_userid: str) -> List[Dict[str, Any]]:
    data = gh_get_json(user_clients_path(owner_userid), default={"clients": []})
    clients = data.get("clients") if isinstance(data, dict) else []
    return clients if isinstance(clients, list) else []

def save_clients(owner_userid: str, clients: List[Dict[str, Any]], message: str) -> None:
    gh_put_json(user_clients_path(owner_userid), {"clients": clients, "updated_at": _now_iso()}, message=message)

def upsert_client(owner_userid: str, client: Dict[str, Any]) -> Dict[str, Any]:
    clients = load_clients(owner_userid)
    key = _client_key(client)
    found = False
    for i, c in enumerate(clients):
        if _client_key(c) == key:
            # merge
            merged = {**c, **client}
            clients[i] = merged
            found = True
            client = merged
            break
    if not found:
        clients.append(client)
    save_clients(owner_userid, clients, message=f"[motilal] upsert client {key} for {owner_userid}")
    return client

def set_client_session(owner_userid: str, client_id: str, session_active: bool, session_text: str, last_login_ts: Optional[str]=None) -> None:
    clients = load_clients(owner_userid)
    target = str(client_id).strip()
    changed = False
    for c in clients:
        cid = str(c.get("client_id") or c.get("userid") or "").strip()
        if cid == target:
            c["session_active"] = bool(session_active)
            c["session"] = session_text  # UI shows this
            c["last_login_ts"] = last_login_ts or _now_iso()
            changed = True
            break
    if changed:
        save_clients(owner_userid, clients, message=f"[motilal] update session {target} for {owner_userid}")


###############################################################################
# Motilal login logic (based on CT_FastAPI.py)
###############################################################################

def motilal_login_client(owner_userid: str, client: Dict[str, Any]) -> Dict[str, Any]:
    """
    Login one client and persist session_active back to GitHub.
    Reference behavior:
    - CT_FastAPI.login_client logs in and updates session_active in the client file. (see CT_FastAPI.py)
    """
    # Map our webapp schema to CT_FastAPI fields
    name = (client.get("name") or client.get("display_name") or "").strip() or "Client"
    userid = str(client.get("client_id") or client.get("userid") or "").strip()
    creds = client.get("creds") or {}
    password = creds.get("password") or client.get("password") or ""
    pan = str(creds.get("pan") or client.get("pan") or "")
    apikey = creds.get("apikey") or creds.get("api_key") or client.get("apikey") or ""
    totp_key = creds.get("totpkey") or creds.get("totp_key") or client.get("totpkey") or ""

    # status update: pending -> trying
    set_client_session(owner_userid, userid, False, "logging_in")

    session_status = False
    msg = "pending"
    try:
        totp = pyotp.TOTP(totp_key).now() if totp_key else ""
        mofsl = MOFSLOPENAPI(apikey, BASE_URL, None, SOURCE_ID, BROWSER_NAME, BROWSER_VERSION)
        resp = mofsl.login(userid, password, pan, totp, userid)
        if isinstance(resp, dict) and resp.get("status") == "SUCCESS":
            session_status = True
            msg = "active"
            with mofsl_sessions_lock:
                mofsl_sessions[(owner_userid, userid)] = (mofsl, userid)
        else:
            session_status = False
            # keep a short message for UI
            msg = "failed"
    except Exception as e:
        session_status = False
        msg = "failed"

    set_client_session(owner_userid, userid, session_status, msg, last_login_ts=_now_iso())
    return {"client_id": userid, "name": name, "session_active": session_status, "session": msg}

def motilal_login_all(owner_userid: str) -> Dict[str, Any]:
    clients = load_clients(owner_userid)
    results = []
    for c in clients:
        # only motilal broker clients
        if (c.get("broker") or "motilal").lower() != "motilal":
            continue
        cid = str(c.get("client_id") or c.get("userid") or "").strip()
        if not cid:
            continue
        results.append(motilal_login_client(owner_userid, c))
    return {"count": len(results), "results": results}


###############################################################################
# Health
###############################################################################

@app.get("/health")
def health():
    return {"ok": True, "version": "1.2"}


###############################################################################
# API: Clients
###############################################################################

@app.get("/get_clients")
def get_clients(request: Request):
    owner = _request_userid(request)
    clients = load_clients(owner)
    # normalize output expected by UI
    out = []
    for c in clients:
        cid = str(c.get("client_id") or c.get("userid") or "").strip()
        out.append({
            "name": c.get("name") or c.get("display_name") or "",
            "client_id": cid,
            "capital": c.get("capital") or 0,
            "session": c.get("session") or ("active" if c.get("session_active") else "pending"),
            "session_active": bool(c.get("session_active", False)),
            "last_login_ts": c.get("last_login_ts") or "",
        })
    return {"clients": out}

# Alias used by UI in some builds
@app.get("/clients")
def clients_alias(request: Request):
    return get_clients(request)

@app.post("/add_client")
async def add_client(request: Request, background_tasks: BackgroundTasks, payload: Dict[str, Any] = Body(...)):
    owner = _request_userid(request)

    broker = (payload.get("broker") or "motilal").lower()
    if broker != "motilal":
        raise HTTPException(status_code=400, detail="This service is Motilal-only. broker must be 'motilal'.")

    client_id = str(payload.get("client_id") or "").strip()
    name = (payload.get("display_name") or payload.get("name") or "").strip() or client_id
    capital = payload.get("capital") or 0
    creds = payload.get("creds") or {}

    if not client_id:
        raise HTTPException(status_code=400, detail="client_id required")

    # Store client with "pending" initially
    client_obj = {
        "broker": "motilal",
        "name": name,
        "client_id": client_id,
        "capital": capital,
        "creds": {
            "password": creds.get("password") or creds.get("mpin") or "",
            "pan": creds.get("pan") or "",
            "apikey": creds.get("apikey") or creds.get("api_key") or "",
            "totpkey": creds.get("totpkey") or creds.get("totp_key") or "",
        },
        "session_active": False,
        "session": "pending",
        "created_at": payload.get("created_at") or _now_iso(),
        "updated_at": _now_iso(),
    }

    upsert_client(owner, client_obj)

    # Start background login for this client (like CT_FastAPI startup login_client)
    background_tasks.add_task(motilal_login_client, owner, client_obj)

    return {"success": True, "message": "Client saved. Login started in background."}

# Alias for UI variants
@app.post("/clients")
async def clients_post_alias(request: Request, background_tasks: BackgroundTasks, payload: Dict[str, Any] = Body(...)):
    return await add_client(request, background_tasks, payload)

@app.post("/login_all_clients")
async def login_all_clients(request: Request, background_tasks: BackgroundTasks):
    """
    Triggers login for all Motilal clients of the logged-in user (background).
    UI can call this when opening Clients tab or via a 'Refresh Session' button.
    """
    owner = _request_userid(request)
    background_tasks.add_task(motilal_login_all, owner)
    return {"success": True, "message": "Login started for all clients in background."}


###############################################################################
# API: Groups (minimal, GitHub-backed)
###############################################################################

@app.get("/groups")
def get_groups(request: Request):
    owner = _request_userid(request)
    data = gh_get_json(user_groups_path(owner), default={"groups": []})
    groups = data.get("groups") if isinstance(data, dict) else []
    return {"groups": groups if isinstance(groups, list) else []}

@app.post("/groups")
async def add_group(request: Request, payload: Dict[str, Any] = Body(...)):
    owner = _request_userid(request)
    group = payload or {}
    name = (group.get("group_name") or group.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="group_name required")
    data = gh_get_json(user_groups_path(owner), default={"groups": []})
    groups = data.get("groups") if isinstance(data, dict) else []
    groups = groups if isinstance(groups, list) else []
    # de-dupe by name
    groups = [g for g in groups if (g.get("group_name") or g.get("name")) != name]
    groups.append({
        "group_name": name,
        "clients": group.get("clients") or [],
        "multiplier": group.get("multiplier") or 1,
        "updated_at": _now_iso(),
    })
    gh_put_json(user_groups_path(owner), {"groups": groups, "updated_at": _now_iso()}, message=f"[groups] upsert {name} for {owner}")
    return {"success": True}

@app.delete("/groups")
def delete_group(request: Request, group_name: str = Query("", alias="group_name")):
    owner = _request_userid(request)
    name = (group_name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="group_name required")
    data = gh_get_json(user_groups_path(owner), default={"groups": []})
    groups = data.get("groups") if isinstance(data, dict) else []
    groups = [g for g in (groups if isinstance(groups, list) else []) if (g.get("group_name") or g.get("name")) != name]
    gh_put_json(user_groups_path(owner), {"groups": groups, "updated_at": _now_iso()}, message=f"[groups] delete {name} for {owner}")
    return {"success": True}


###############################################################################
# NOTE:
# Trading endpoints (place_order/get_orders/positions/etc.) should use mofsl_sessions
# keyed by (owner_userid, client_id). If you want, I can wire those next.
###############################################################################


