# motilal_trader.py
"""
Motilal Trader (Minimal Clean) — Symbols DB + Symbol Search + Auth Router only

Applied corrections WITHOUT removing anything from your attached file:
- Keeps all your imports and helpers (including _safe_int_token)
- Keeps Auth router mount at /auth
- Keeps Symbols DB build on startup from GitHub CSV to SQLite
- Fixes /search_symbols to be frontend-compatible by returning BOTH:
    1) Select2 format:  {"results":[{"id","text"}]}
    2) React-Select:    {"options":[{"value","label"}]}
- Adds DB-ready guard (returns 503 if DB not built/available)

Nothing else removed.
"""

from __future__ import annotations

import csv
import os
import sqlite3
import threading
from typing import Any, Dict, List

import requests
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Request, Body, Query, Form, HTTPException, BackgroundTasks,Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import pandas as pd
import requests  # (kept as-is from your attached file)
import base64
import json
import re


# Optional auth router (Auth0 integration expected to live here)
try:
    from auth.auth_router import router as auth_router  # type: ignore
except Exception:
    auth_router = None  # type: ignore


###############################################################################
# App + CORS
###############################################################################

app = FastAPI(title="Motilal Trader (Minimal)", version="0.1")

# IMPORTANT: os.getenv takes (key, default) only.
# Support both env var names:
# - ALLOWED_ORIGINS (Render UI earlier)
# - FRONTEND_ORIGINS (code default)
_frontend_origins = os.getenv(
    "ALLOWED_ORIGINS",
    os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,https://multibroker-trader-multiuser.vercel.app",
    ),
)

allow_origins = [o.strip() for o in _frontend_origins.split(",") if o.strip()]
if len(allow_origins) == 1 and allow_origins[0] == "*":
    allow_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount auth router if present
if auth_router is not None:
    app.include_router(auth_router, prefix="/auth")


###############################################################################
# Symbol DB config
###############################################################################

GITHUB_CSV_URL = os.getenv(
    "SYMBOLS_CSV_URL",
    "https://raw.githubusercontent.com/Pramod541988/Stock_List/main/security_id.csv",
)

SQLITE_DB = os.getenv("SYMBOLS_DB_PATH", "symbols.db")
TABLE_NAME = os.getenv("SYMBOLS_TABLE", "symbols")
symbol_db_lock = threading.Lock()


###############################################################################
# Symbol DB build + validation
###############################################################################

def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            Exchange TEXT,
            "Stock Symbol" TEXT,
            "Security ID" TEXT
        )
        """
    )
    conn.commit()


def recreate_sqlite_from_csv() -> Dict[str, Any]:
    """
    Recreate symbols.db from the GitHub CSV (or configured URL).
    Expects columns at least: Exchange, Stock Symbol, Security ID
    """
    try:
        r = requests.get(GITHUB_CSV_URL, timeout=45)
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Failed to download symbols CSV: {e}")

    csv_lines = r.text.splitlines()
    if not csv_lines:
        raise RuntimeError("Symbols CSV is empty.")

    reader = csv.DictReader(csv_lines)
    required = {"Exchange", "Stock Symbol", "Security ID"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise RuntimeError(f"CSV missing required columns. Found: {reader.fieldnames}")

    tmp_db = SQLITE_DB + ".tmp"

    if os.path.exists(tmp_db):
        try:
            os.remove(tmp_db)
        except Exception:
            pass

    conn = sqlite3.connect(tmp_db)
    try:
        conn.execute(f"DROP TABLE IF EXISTS {TABLE_NAME}")
        conn.execute(
            f"""
            CREATE TABLE {TABLE_NAME} (
                Exchange TEXT,
                "Stock Symbol" TEXT,
                "Security ID" TEXT
            )
            """
        )

        rows = []
        for row in reader:
            rows.append(
                (
                    (row.get("Exchange") or "").strip(),
                    (row.get("Stock Symbol") or "").strip(),
                    (row.get("Security ID") or "").strip(),
                )
            )

        conn.executemany(
            f'INSERT INTO {TABLE_NAME} (Exchange, "Stock Symbol", "Security ID") VALUES (?, ?, ?)',
            rows,
        )
        conn.execute(f'CREATE INDEX IF NOT EXISTS idx_sym ON {TABLE_NAME}("Stock Symbol")')
        conn.execute(f'CREATE INDEX IF NOT EXISTS idx_exch ON {TABLE_NAME}(Exchange)')
        conn.commit()
    finally:
        conn.close()

    # Swap
    if os.path.exists(SQLITE_DB):
        try:
            os.remove(SQLITE_DB)
        except Exception:
            pass
    os.replace(tmp_db, SQLITE_DB)

    return {"ok": True, "rows": len(rows), "db_path": SQLITE_DB, "source": GITHUB_CSV_URL}


def _db_ready() -> bool:
    try:
        if not os.path.exists(SQLITE_DB):
            return False
        conn = sqlite3.connect(SQLITE_DB)
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (TABLE_NAME,),
        )
        ok = cur.fetchone() is not None
        conn.close()
        return ok
    except Exception:
        return False


@app.on_event("startup")
def _startup() -> None:
    try:
        with symbol_db_lock:
            recreate_sqlite_from_csv()
    except Exception as e:
        # Don't crash boot; /search_symbols will show 503 until rebuild works.
        print(f"[startup] symbols db init failed: {e}")


def _safe_int_token(x):
    """
    Accepts '10666', '10666.0', 10666.0, etc.
    Returns int or raises HTTPException(400) with a clear message.
    """
    try:
        if x is None:
            raise ValueError("symboltoken is None")
        s = str(x).strip()
        if s == "":
            raise ValueError("symboltoken is empty")
        return int(float(s))
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid symboltoken: {x}")


###############################################################################
# Basic endpoints
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

@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "symbols_db_ready": _db_ready(), "auth_router": bool(auth_router is not None)}


@app.post("/symbols/rebuild")
def rebuild_symbols() -> Dict[str, Any]:
    try:
        with symbol_db_lock:
            return recreate_sqlite_from_csv()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


###############################################################################
# Symbols search
###############################################################################

@app.get("/search_symbols")
def search_symbols(q: str = Query("", alias="q"), exchange: str = Query("", alias="exchange")):
    query = (q or "").strip()
    exchange_filter = (exchange or "").strip().upper()

    if not query:
        # Provide both keys so frontend never breaks on empty input
        return JSONResponse(content={"results": [], "options": [], "count": 0})

    # Guard: if DB didn't build (startup download failed) return 503 with clear message
    if not _db_ready():
        raise HTTPException(
            status_code=503,
            detail="Symbols DB not ready. Check /health and/or call POST /symbols/rebuild.",
        )

    words = [w for w in query.lower().split() if w]
    if not words:
        return JSONResponse(content={"results": [], "options": [], "count": 0})

    where_clauses = []
    params = []
    for w in words:
        # Use bracket quoting for sqlite compatibility (kept style from your file)
        where_clauses.append("LOWER([Stock Symbol]) LIKE ?")
        params.append(f"%{w}%")

    where_sql = " AND ".join(where_clauses)
    if exchange_filter:
        where_sql += " AND UPPER(Exchange) = ?"
        params.append(exchange_filter)

    sql = f"""
        SELECT Exchange, [Stock Symbol], [Security ID]
        FROM {TABLE_NAME}
        WHERE {where_sql}
        ORDER BY [Stock Symbol]
        LIMIT 20
    """

    with symbol_db_lock:
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        conn.close()

    results = [
        {"id": f"{row[0]}|{row[1]}|{row[2]}", "text": f"{row[0]} | {row[1]}"}
        for row in rows
    ]

    # React-Select compatible too (some UIs expect options/value/label)
    options = [{"value": r["id"], "label": r["text"]} for r in results]

    return JSONResponse(content={"results": results, "options": options, "count": len(results)})

def _env_first(*keys: str, default: str = "") -> str:
    """Return first non-empty env var among keys (stripped)."""
    for k in keys:
        v = os.getenv(k, "")
        if v is None:
            continue
        v = str(v).strip()
        if v:
            return v
    return str(default).strip()

# --- GitHub storage configuration (accept legacy key names too) ---
GITHUB_OWNER = _env_first("GITHUB_OWNER", "GITHUB_REPO_OWNER")
GITHUB_REPO = _env_first("GITHUB_REPO", "GITHUB_REPO_NAME")
GITHUB_BRANCH = _env_first("GITHUB_BRANCH", default="main") or "main"
GITHUB_TOKEN = _env_first("GITHUB_TOKEN", "GITHUB_PAT", "GITHUB_ACCESS_TOKEN")

# Root folder in repo that contains "users/...". Typical: "data"
GITHUB_DATA_ROOT = (_env_first("GITHUB_DATA_ROOT", "GITHUB_ROOT", "DATA_ROOT", default="data").strip().strip("/") or "data")

def _github_missing() -> List[str]:
    missing = []
    if not GITHUB_OWNER:
        missing.append("GITHUB_OWNER")
    if not GITHUB_REPO:
        missing.append("GITHUB_REPO")
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    return missing

def _github_enabled() -> bool:
    return len(_github_missing()) == 0

def _gh_headers() -> Dict[str, str]:
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "motilal-trader",
    }

def _gh_api_url(path: str) -> str:
    path = path.lstrip("/")
    return f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"

def _github_get(path: str) -> Dict[str, Any]:
    """
    GET a GitHub 'contents' API object.
    Returns dict or {"__not_found__": True} if missing.
    """
    if not _github_enabled():
        raise HTTPException(status_code=500, detail=f"GitHub storage not configured. Missing: {', '.join(_github_missing())}. Set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN in Render Environment.")
    url = _gh_api_url(path)
    try:
        r = requests.get(url, headers=_gh_headers(), params={"ref": GITHUB_BRANCH}, timeout=30)
        if r.status_code == 404:
            return {"__not_found__": True}
        r.raise_for_status()
        j = r.json()
        return j if isinstance(j, dict) else {"__list__": j}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub GET failed: {e}")

def _github_put(path: str, content_bytes: bytes, message: str) -> Dict[str, Any]:
    """
    Create/update a file in GitHub at 'path' (repo-relative).
    """
    if not _github_enabled():
        raise HTTPException(status_code=500, detail=f"GitHub storage not configured. Missing: {', '.join(_github_missing())}. Set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN in Render Environment.")

    # check existing to obtain sha (required for updates)
    existing = _github_get(path)
    sha = None
    if isinstance(existing, dict) and existing.get("__not_found__"):
        sha = None
    elif isinstance(existing, dict) and existing.get("sha"):
        sha = existing.get("sha")

    payload: Dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("utf-8"),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    url = _gh_api_url(path)
    try:
        r = requests.put(url, headers=_gh_headers(), json=payload, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub PUT failed: {e}")

def _github_list_dir(path: str) -> List[Dict[str, Any]]:
    """
    List a directory using GitHub contents API. Returns [] if not found.
    """
    obj = _github_get(path)
    if isinstance(obj, dict) and obj.get("__not_found__"):
        return []
    if isinstance(obj, dict) and "__list__" in obj and isinstance(obj["__list__"], list):
        return obj["__list__"]
    return []

def _github_read_json(path: str) -> Dict[str, Any]:
    obj = _github_get(path)
    if isinstance(obj, dict) and obj.get("__not_found__"):
        return {}
    if not isinstance(obj, dict) or "content" not in obj:
        return {}
    try:
        raw = base64.b64decode((obj.get("content") or "").encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

def _github_write_json(path: str, data: Dict[str, Any], message: str) -> None:
    b = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _github_put(path, b, message=message)

def _safe(s: Any) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", str(s or "").strip())

def _pick(*vals: Any) -> str:
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""

def require_user(user_id: str) -> str:
    uid = (user_id or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing X-User-Id header (logged in user).")
    return uid

def _client_rel_path(user_id: str, client_id: str) -> str:
    # repo path: data/users/<user>/clients/motilal/<client>.json
    return f"{GITHUB_DATA_ROOT}/users/{_safe(user_id)}/clients/motilal/{_safe(client_id)}.json"

def _client_dir(user_id: str) -> str:
    return f"{GITHUB_DATA_ROOT}/users/{_safe(user_id)}/clients/motilal"

# ============================================================
# Motilal client login helpers (web multi-user)
# ============================================================
# We keep sessions in-memory (per instance). Persistent client creds stay in GitHub JSON.
# "session_active" reflects the last known login state.
try:
    from MotilalOswalApi import MOFSLOPENAPI  # type: ignore
except Exception:
    MOFSLOPENAPI = None  # fallback in case dependency missing in env

try:
    import pyotp
except Exception:
    pyotp = None  # fallback

MOFSL_BASE_URL = os.getenv("MOFSL_BASE_URL", "https://openapi.motilaloswal.com")
MOFSL_SOURCE_ID = os.getenv("MOFSL_SOURCE_ID", "WEBSCRAP")  # keep stable default

# in-memory sessions: key -> dict with api instance + timestamps
_mofsl_sessions: Dict[str, Dict[str, Any]] = {}

def _norm_userid(raw: Optional[str]) -> str:
    """Accept userid from header or query; also fixes accidental quotes like %22pra%22."""
    if not raw:
        return ""
    s = raw.strip()
    if (len(s) >= 2) and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        s = s[1:-1]
    return s.strip()

def _resolve_userid(request: Request, userid: Optional[str] = None, user_id: Optional[str] = None, x_user_id: Optional[str] = None) -> str:
    """Resolve userid from (1) explicit args, (2) query, (3) header, in that order."""
    for v in (userid, user_id, x_user_id):
        u = _norm_userid(v)
        if u:
            return u
    for k in ("userid", "user_id"):
        u = _norm_userid(request.query_params.get(k))
        if u:
            return u
    u = _norm_userid(request.headers.get("x-user-id"))
    if u:
        return u
    return ""

async def _login_motilal_client_doc(user: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt login for a single client doc; updates doc['session_active'] in GitHub."""
    if MOFSLOPENAPI is None:
        await github_write_user_client(user, doc.get("userid", ""), {**doc, "session_active": False, "session_error": "MOFSLOPENAPI not installed"})
        return {"ok": False, "error": "MOFSLOPENAPI not installed"}

    client_userid = doc.get("userid") or doc.get("client_id") or ""
    password = doc.get("password") or ""
    apikey = doc.get("apikey") or doc.get("api_key") or ""
    totpkey = doc.get("totpkey") or doc.get("totp_key") or ""

    if not client_userid or not password:
        await github_write_user_client(user, doc.get("userid", ""), {**doc, "session_active": False, "session_error": "Missing userid/password"})
        return {"ok": False, "error": "Missing userid/password"}

    twofa = ""
    if totpkey and pyotp is not None:
        try:
            twofa = pyotp.TOTP(totpkey).now()
        except Exception:
            twofa = ""

    try:
        api = MOFSLOPENAPI(
            base_url=MOFSL_BASE_URL,
            api_key=apikey,
            client_id=client_userid,
            password=password,
            totp=twofa,
            source_id=MOFSL_SOURCE_ID,
        )
        # Support common SDK method names
        if hasattr(api, "login"):
            resp = api.login()
        elif hasattr(api, "login_request"):
            resp = api.login_request()
        else:
            resp = {"message": "SDK missing login method"}

        ok = bool(resp) and ("token" in str(resp).lower() or "success" in str(resp).lower() or getattr(api, "auth_token", None))
        sess_key = f"{user}:{client_userid}"
        if ok:
            _mofsl_sessions[sess_key] = {"api": api, "ts": time.time()}
            updated = {**doc, "session_active": True, "session_error": "", "last_login_ts": time.time()}
        else:
            updated = {**doc, "session_active": False, "session_error": str(resp)[:500]}

        await github_write_user_client(user, doc.get("userid", ""), updated)
        return {"ok": ok, "response": resp}
    except Exception as e:
        updated = {**doc, "session_active": False, "session_error": str(e)[:500]}
        await github_write_user_client(user, doc.get("userid", ""), updated)
        return {"ok": False, "error": str(e)}

async def _login_all_clients_for_user(user: str) -> Dict[str, Any]:
    clients = await github_list_user_clients(user)
    results = []
    for doc in clients:
        results.append(await _login_motilal_client_doc(user, doc))
    ok = all(r.get("ok") for r in results) if results else True
    return {"ok": ok, "count": len(results), "results": results}
@app.post("/add_client")
async def add_client(
    payload: Dict[str, Any] = Body(...),
    user_id: str = Header("", alias="X-User-Id"),
) -> Dict[str, Any]:
    """
    Save a Motilal client for the logged-in user into GitHub.
    Reference fields from CT_FastAPI: name, userid, password, pan, apikey, totpkey, capital, session_active. fileciteturn4file4L1-L22
    """
    uid = require_user(user_id)

    client_id = _pick(payload.get("userid"), payload.get("client_id"))
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id/userid required")

    display_name = (payload.get("name") or payload.get("display_name") or client_id).strip()

    doc = dict(payload)
    doc["broker"] = "motilal"
    doc["userid"] = client_id
    doc["name"] = display_name
    doc.setdefault("session_active", False)
    doc.setdefault("created_at", datetime.utcnow().isoformat())
    doc["updated_at"] = datetime.utcnow().isoformat()

    rel = _client_rel_path(uid, client_id)
    _github_write_json(rel, doc, message=f"Add/Update client {client_id} for {uid}")

    return {"success": True, "message": "Client saved to GitHub.", "client_id": client_id}

@app.get("/get_clients")
@app.get("/clients")
async def get_clients(
    request: Request,
    userid: str = Query("", description="user id"),
    user_id: str = Query("", description="user id alt"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
) -> Dict[str, Any]:
    """Load clients for a user from GitHub.

    Supports:
      - ?userid=pra (frontend)
      - ?user_id=pra
      - X-User-Id header
    """
    uid = _resolve_userid(request, userid=userid, user_id=user_id, x_user_id=x_user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Missing userid")

    out: List[Dict[str, Any]] = []
    dir_path = _client_dir(uid)
    for it in _github_list_dir(dir_path):
        if it.get("type") != "file":
            continue
        fn = it.get("name") or ""
        if not fn.endswith(".json"):
            continue

        doc = _github_read_json(f"{dir_path}/{fn}") or {}
        if not isinstance(doc, dict):
            continue

        client_id = str(doc.get("userid") or doc.get("client_id") or "").strip()
        session_status = "Logged in" if bool(doc.get("session_active")) else "pending"

        out.append(
            {
                "name": doc.get("name", "") or doc.get("display_name", ""),
                "client_id": client_id,
                "capital": doc.get("capital", "") or "",
                "session": session_status,
                "broker": "motilal",
            }
        )

    out.sort(key=lambda x: (x.get("name") or "", x.get("client_id") or ""))
    return {"ok": True, "clients": out}


@app.post("/login_all_clients")
async def login_all_clients(
    request: Request,
    userid: str = Query("", description="user id"),
    user_id: str = Query("", description="user id alt"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    user = _resolve_userid(request, userid=userid, user_id=user_id, x_user_id=x_user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Missing userid")
    return await _login_all_clients_for_user(user)

@app.post("/login_client")
async def login_client(
    request: Request,
    client_userid: str = Body(..., embed=True),
    userid: str = Query("", description="user id"),
    user_id: str = Query("", description="user id alt"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    user = _resolve_userid(request, userid=userid, user_id=user_id, x_user_id=x_user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Missing userid")
    doc = await github_read_user_client(user, client_userid)
    if not doc:
        raise HTTPException(status_code=404, detail="Client not found")
    return await _login_motilal_client_doc(user, doc)
