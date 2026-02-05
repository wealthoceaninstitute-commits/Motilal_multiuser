# motilal_trader.py
"""
Motilal Trader (Multiuser) — Full Backend (Clients + Groups + CopyTrading + Trading APIs)

Fixes in this version:
- Restores missing endpoints expected by UI: /clients, /groups (and keeps /get_clients, /get_groups).
- Adds background login for clients (auto-login after add, and optional login-all).
- Makes GitHub storage env compatible with BOTH naming styles:
  * GITHUB_OWNER / GITHUB_REPO / GITHUB_BRANCH / GITHUB_TOKEN
  * GITHUB_REPO_OWNER / GITHUB_REPO_NAME / GITHUB_BRANCH / GITHUB_TOKEN
- Keeps Symbols DB + /search_symbols
"""

from __future__ import annotations

import os
import json
import base64
import time
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware

# --- Local modules (present in your repo zip) ---
from auth.auth_router import router as auth_router
from MOFSLOPENAPI import MOFSLOPENAPI

try:
    import pyotp
except Exception:
    pyotp = None

# ---------------------------
# App & CORS
# ---------------------------
app = FastAPI(title="Motilal Multiuser Trader", version="1.2")

_allowed = os.getenv("ALLOWED_ORIGINS", "")
if _allowed.strip():
    allowed_origins = [x.strip() for x in _allowed.split(",") if x.strip()]
else:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://multibroker-trader-multiuser.vercel.app",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])

# ---------------------------
# GitHub storage helpers
# ---------------------------
def _env_first(*keys: str, default: str = "") -> str:
    for k in keys:
        v = os.getenv(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default

def github_config() -> Tuple[bool, Dict[str, str], List[str]]:
    token = _env_first("GITHUB_TOKEN")
    owner = _env_first("GITHUB_OWNER", "GITHUB_REPO_OWNER")
    repo  = _env_first("GITHUB_REPO", "GITHUB_REPO_NAME")
    branch = _env_first("GITHUB_BRANCH", "GITHUB_BRANCH_NAME", default="main")
    root = _env_first("GITHUB_DATA_ROOT", default="data")

    missing = []
    if not token: missing.append("GITHUB_TOKEN")
    if not owner: missing.append("GITHUB_OWNER/GITHUB_REPO_OWNER")
    if not repo: missing.append("GITHUB_REPO/GITHUB_REPO_NAME")
    ok = (len(missing) == 0)

    return ok, {"token": token, "owner": owner, "repo": repo, "branch": branch, "root": root}, missing

def github_read_json(rel_path: str) -> Optional[dict]:
    ok, cfg, missing = github_config()
    if not ok:
        raise HTTPException(status_code=503, detail=f"GitHub storage not configured. Missing: {missing}")

    rel_path = rel_path.lstrip("/")
    url = f"https://api.github.com/repos/{cfg['owner']}/{cfg['repo']}/contents/{rel_path}?ref={cfg['branch']}"
    headers = {
        "Authorization": f"token {cfg['token']}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "motilal-multiuser-trader",
    }
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"GitHub read failed: {r.status_code} {r.text[:200]}")
    j = r.json()
    if isinstance(j, dict) and j.get("type") == "file":
        content_b64 = j.get("content", "")
        if not content_b64:
            return None
        raw = base64.b64decode(content_b64).decode("utf-8")
        return json.loads(raw)
    return None

def github_write_json(rel_path: str, data: dict) -> None:
    ok, cfg, missing = github_config()
    if not ok:
        raise HTTPException(status_code=503, detail=f"GitHub storage not configured. Missing: {missing}")

    rel_path = rel_path.lstrip("/")
    url = f"https://api.github.com/repos/{cfg['owner']}/{cfg['repo']}/contents/{rel_path}"
    headers = {
        "Authorization": f"token {cfg['token']}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "motilal-multiuser-trader",
    }

    # get sha if exists
    sha = None
    r0 = requests.get(url + f"?ref={cfg['branch']}", headers=headers, timeout=30)
    if r0.status_code == 200:
        sha = r0.json().get("sha")

    payload = {
        "message": f"update {rel_path}",
        "content": base64.b64encode(json.dumps(data, indent=2).encode("utf-8")).decode("utf-8"),
        "branch": cfg["branch"],
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=headers, json=payload, timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"GitHub write failed: {r.status_code} {r.text[:200]}")

# ---------------------------
# Local storage fallback
# ---------------------------
DATA_DIR = os.getenv("DATA_DIR", "/mnt/data")

def _local_path(rel_path: str) -> str:
    rel_path = rel_path.lstrip("/")
    return os.path.join(DATA_DIR, rel_path)

def read_json_any(rel_path: str) -> Optional[dict]:
    # Prefer GitHub if configured
    ok, _, _ = github_config()
    if ok:
        return github_read_json(rel_path)

    fp = _local_path(rel_path)
    if not os.path.exists(fp):
        return None
    with open(fp, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json_any(rel_path: str, data: dict) -> None:
    ok, _, _ = github_config()
    if ok:
        github_write_json(rel_path, data)
        return

    fp = _local_path(rel_path)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ---------------------------
# User data helpers
# ---------------------------
def _user_clients_path(userid: str) -> str:
    return f"data/users/{userid}/clients.json"

def _user_groups_path(userid: str) -> str:
    return f"data/users/{userid}/groups.json"

def _user_copy_path(userid: str) -> str:
    return f"data/users/{userid}/copy_setups.json"

def get_clients(userid: str) -> List[dict]:
    data = read_json_any(_user_clients_path(userid)) or {"clients": []}
    return data.get("clients", [])

def save_clients(userid: str, clients: List[dict]) -> None:
    write_json_any(_user_clients_path(userid), {"clients": clients})

def get_groups(userid: str) -> List[dict]:
    data = read_json_any(_user_groups_path(userid)) or {"groups": []}
    return data.get("groups", [])

def save_groups(userid: str, groups: List[dict]) -> None:
    write_json_any(_user_groups_path(userid), {"groups": groups})

def get_copy_setups(userid: str) -> List[dict]:
    data = read_json_any(_user_copy_path(userid)) or {"setups": []}
    return data.get("setups", [])

def save_copy_setups(userid: str, setups: List[dict]) -> None:
    write_json_any(_user_copy_path(userid), {"setups": setups})

def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

# ---------------------------
# Motilal login/session cache (in-memory)
# ---------------------------
# Sessions are runtime only (Render restarts will clear).
# We persist session_active / last_login_ts back into storage so UI can show status.
SESSIONS: Dict[str, dict] = {}  # key = f"{userid}:{client_id}"

def _session_key(userid: str, client_id: str) -> str:
    return f"{userid}:{client_id}"

def _mofsl_client_from_env(userid: str) -> MOFSLOPENAPI:
    # These are the same defaults used in CT_FastAPI; keep compatible.
    apikey = _env_first("MOFSL_API_KEY", "MOTILAL_API_KEY", default=_env_first("API_KEY"))
    base_url = _env_first("MOFSL_BASE_URL", default="https://openapi.motilaloswal.com")
    source_id = _env_first("MOFSL_SOURCE_ID", default="API")
    browsername = _env_first("MOFSL_BROWSER_NAME", default="chrome")
    browserversion = _env_first("MOFSL_BROWSER_VERSION", default="1.0")
    return MOFSLOPENAPI(apikey, base_url, None, source_id, browsername, browserversion)

def _extract_login_fields(client: dict) -> Tuple[str, str, str, Optional[str]]:
    # We support both schemas:
    # 1) creds: { type:'motilal', client_code, password, mpin, totp_key? }
    # 2) credentials: { password, pan/mpin, totp_key? } etc.
    creds = client.get("creds") or client.get("credentials") or {}
    client_id = client.get("client_id") or client.get("userid") or creds.get("client_code") or creds.get("client_id") or ""
    password = creds.get("password") or ""
    twofa = creds.get("mpin") or creds.get("pan") or creds.get("2fa") or ""
    totp_key = creds.get("totp_key") or creds.get("totp") or client.get("totp_key")
    return client_id, password, twofa, totp_key

def login_one_client(userid: str, client_id: str) -> dict:
    clients = get_clients(userid)
    idx = next((i for i,c in enumerate(clients) if (c.get("client_id") or c.get("userid")) == client_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Client not found")

    client = clients[idx]
    cid, password, twofa, totp_key = _extract_login_fields(client)

    if not cid or not password or not twofa:
        # mark as not active but keep pending
        client["session_active"] = False
        client["last_login_ts"] = _now_iso()
        client["last_login_error"] = "Missing login fields (client_id/password/2FA)."
        clients[idx] = client
        save_clients(userid, clients)
        return {"status": "FAILED", "message": client["last_login_error"]}

    totp = None
    if totp_key and pyotp:
        try:
            totp = pyotp.TOTP(totp_key).now()
        except Exception:
            totp = None

    try:
        mof = _mofsl_client_from_env(userid)
        resp = mof.login(cid, password, twofa, totp, cid)
        if resp and resp.get("status") == "SUCCESS":
            # store session runtime
            SESSIONS[_session_key(userid, client_id)] = {
                "client_id": client_id,
                "login_ts": _now_iso(),
                "raw": resp,
            }
            client["session_active"] = True
            client["session"] = "active"
            client["last_login_ts"] = _now_iso()
            client.pop("last_login_error", None)
        else:
            client["session_active"] = False
            client["session"] = "pending"
            client["last_login_ts"] = _now_iso()
            client["last_login_error"] = (resp or {}).get("message") or "Login failed"
        clients[idx] = client
        save_clients(userid, clients)
        return resp or {"status": "FAILED", "message": "Login failed"}
    except Exception as e:
        client["session_active"] = False
        client["session"] = "pending"
        client["last_login_ts"] = _now_iso()
        client["last_login_error"] = str(e)
        clients[idx] = client
        save_clients(userid, clients)
        return {"status": "ERROR", "message": str(e)}

def login_all_clients(userid: str) -> dict:
    clients = get_clients(userid)
    out = []
    for c in clients:
        cid = c.get("client_id") or c.get("userid")
        if not cid:
            continue
        out.append({"client_id": cid, "result": login_one_client(userid, cid)})
        time.sleep(0.2)
    return {"ok": True, "count": len(out), "results": out}

# ---------------------------
# Health / Debug
# ---------------------------
@app.get("/health")
def health():
    return {"ok": True, "ts": _now_iso()}

@app.get("/debug_env")
def debug_env():
    ok, cfg, missing = github_config()
    return {
        "github_configured": ok,
        "missing": missing,
        "github_owner_set": bool(cfg.get("owner")),
        "github_repo_set": bool(cfg.get("repo")),
        "github_branch": cfg.get("branch"),
        "github_data_root": cfg.get("root"),
        "github_token_len": len(cfg.get("token") or ""),
        "allowed_origins": allowed_origins,
    }

# ---------------------------
# Symbols (kept from your minimal file)
# ---------------------------
SYMBOLS_DB_PATH = os.getenv("SYMBOLS_DB_PATH", _local_path("symbols_db.json"))

def _load_symbols() -> List[dict]:
    try:
        if os.path.exists(SYMBOLS_DB_PATH):
            with open(SYMBOLS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_symbols(rows: List[dict]) -> None:
    os.makedirs(os.path.dirname(SYMBOLS_DB_PATH), exist_ok=True)
    with open(SYMBOLS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(rows, f)

@app.post("/symbols/rebuild")
def symbols_rebuild():
    # Placeholder: keep endpoint stable. If you already rebuild elsewhere, wire it here.
    # For now, we just ensure the file exists.
    rows = _load_symbols()
    _save_symbols(rows)
    return {"ok": True, "count": len(rows)}

@app.get("/search_symbols")
def search_symbols(q: str = Query("", min_length=0), limit: int = 20):
    qn = (q or "").strip().lower()
    rows = _load_symbols()
    if not qn:
        return {"results": rows[:limit], "count": min(len(rows), limit)}
    out = []
    for r in rows:
        hay = " ".join([str(r.get("symbol","")), str(r.get("name","")), str(r.get("exchange",""))]).lower()
        if qn in hay:
            out.append(r)
            if len(out) >= limit:
                break
    return {"results": out, "count": len(out)}

# ---------------------------
# Clients API (UI expects)
# ---------------------------
@app.get("/get_clients")
def api_get_clients(userid: str = "", user_id: str = "", auto_login: int = 0, bg: BackgroundTasks = None):
    uid = (userid or user_id or "").strip().strip('"')
    if not uid:
        raise HTTPException(status_code=400, detail="userid required")
    clients = get_clients(uid)

    # normalize for UI
    for c in clients:
        if "session" not in c:
            c["session"] = "active" if c.get("session_active") else "pending"

    if auto_login and bg is not None:
        bg.add_task(login_all_clients, uid)

    return {"userid": uid, "clients": clients}

# REST alias expected by some UI builds
@app.get("/clients")
def api_clients(userid: str = "", user_id: str = ""):
    return api_get_clients(userid=userid, user_id=user_id)

@app.post("/add_client")
def api_add_client(payload: dict, background: BackgroundTasks):
    userid = (payload.get("userid") or payload.get("user_id") or payload.get("userId") or "").strip().strip('"')
    if not userid:
        raise HTTPException(status_code=400, detail="userid required in payload")

    client_id = (payload.get("client_id") or payload.get("userid") or payload.get("clientId") or "").strip()
    display_name = payload.get("display_name") or payload.get("name") or payload.get("client_name") or client_id

    creds = payload.get("creds") or payload.get("credentials") or {}
    # If frontend uses { broker, client_id, display_name, capital, creds }, keep compatible
    capital = payload.get("capital")

    clients = get_clients(userid)
    if any((c.get("client_id") or c.get("userid")) == client_id for c in clients):
        raise HTTPException(status_code=400, detail="Client already exists")

    newc = {
        "broker": "motilal",
        "client_id": client_id,
        "name": display_name,
        "capital": capital,
        "creds": creds,
        "session_active": False,
        "session": "pending",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    clients.append(newc)
    save_clients(userid, clients)

    # Auto-login newly added client
    background.add_task(login_one_client, userid, client_id)

    return {"ok": True, "client_id": client_id}

@app.post("/delete_client")
def api_delete_client(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    client_id = (payload.get("client_id") or "").strip()
    if not userid or not client_id:
        raise HTTPException(status_code=400, detail="userid and client_id required")

    clients = get_clients(userid)
    clients2 = [c for c in clients if (c.get("client_id") or c.get("userid")) != client_id]
    save_clients(userid, clients2)
    SESSIONS.pop(_session_key(userid, client_id), None)
    return {"ok": True}

@app.post("/login_client")
def api_login_client(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    client_id = (payload.get("client_id") or "").strip()
    if not userid or not client_id:
        raise HTTPException(status_code=400, detail="userid and client_id required")
    return login_one_client(userid, client_id)

@app.post("/login_all_clients")
def api_login_all(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    if not userid:
        raise HTTPException(status_code=400, detail="userid required")
    return login_all_clients(userid)

# ---------------------------
# Groups API (UI expects)
# ---------------------------
@app.get("/get_groups")
def api_get_groups(userid: str = "", user_id: str = ""):
    uid = (userid or user_id or "").strip().strip('"')
    if not uid:
        raise HTTPException(status_code=400, detail="userid required")
    return {"userid": uid, "groups": get_groups(uid)}

@app.get("/groups")
def api_groups(userid: str = "", user_id: str = ""):
    return api_get_groups(userid=userid, user_id=user_id)

@app.post("/create_group")
def api_create_group(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    name = (payload.get("group_name") or payload.get("name") or "").strip()
    members = payload.get("members") or payload.get("client_ids") or []
    if not userid or not name:
        raise HTTPException(status_code=400, detail="userid and group_name required")

    groups = get_groups(userid)
    if any(g.get("name") == name for g in groups):
        raise HTTPException(status_code=400, detail="Group already exists")

    groups.append({"name": name, "members": members, "created_at": _now_iso()})
    save_groups(userid, groups)
    return {"ok": True}

@app.post("/delete_group")
def api_delete_group(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    name = (payload.get("group_name") or payload.get("name") or "").strip()
    if not userid or not name:
        raise HTTPException(status_code=400, detail="userid and group_name required")
    groups = [g for g in get_groups(userid) if g.get("name") != name]
    save_groups(userid, groups)
    return {"ok": True}

# ---------------------------
# CopyTrading setups (kept compatible with CT_FastAPI UI tabs)
# ---------------------------
@app.post("/save_copytrading_setup")
def api_save_copy(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    if not userid:
        raise HTTPException(status_code=400, detail="userid required")
    setups = get_copy_setups(userid)
    setups.append({**payload, "saved_at": _now_iso()})
    save_copy_setups(userid, setups)
    return {"ok": True}

@app.get("/list_copytrading_setups")
def api_list_copy(userid: str = "", user_id: str = ""):
    uid = (userid or user_id or "").strip().strip('"')
    if not uid:
        raise HTTPException(status_code=400, detail="userid required")
    return {"userid": uid, "setups": get_copy_setups(uid)}

@app.post("/delete_copy_setup")
def api_delete_copy(payload: dict):
    userid = (payload.get("userid") or payload.get("user_id") or "").strip().strip('"')
    setup_id = payload.get("setup_id")
    if not userid or setup_id is None:
        raise HTTPException(status_code=400, detail="userid and setup_id required")
    setups = [s for s in get_copy_setups(userid) if s.get("setup_id") != setup_id]
    save_copy_setups(userid, setups)
    return {"ok": True}

@app.post("/enable_copy_setup")
def api_enable_copy(payload: dict):
    payload["enabled"] = True
    return api_save_copy(payload)

@app.post("/disable_copy_setup")
def api_disable_copy(payload: dict):
    payload["enabled"] = False
    return api_save_copy(payload)

# ---------------------------
# Trading endpoints placeholders (wire your existing Motilal functions here)
# ---------------------------
@app.post("/place_order")
def place_order(payload: dict):
    # Implement using active session in SESSIONS + MOFSLOPENAPI as in your CT_FastAPI.
    raise HTTPException(status_code=501, detail="place_order not wired in this file yet")

@app.get("/get_orders")
def get_orders(userid: str = "", user_id: str = "", client_id: str = ""):
    raise HTTPException(status_code=501, detail="get_orders not wired in this file yet")

@app.get("/get_positions")
def get_positions(userid: str = "", user_id: str = "", client_id: str = ""):
    raise HTTPException(status_code=501, detail="get_positions not wired in this file yet")

@app.get("/get_holdings")
def get_holdings(userid: str = "", user_id: str = "", client_id: str = ""):
    raise HTTPException(status_code=501, detail="get_holdings not wired in this file yet")

@app.get("/get_summary")
def get_summary(userid: str = "", user_id: str = "", client_id: str = ""):
    raise HTTPException(status_code=501, detail="get_summary not wired in this file yet")
