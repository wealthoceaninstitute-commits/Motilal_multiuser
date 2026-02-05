from fastapi import APIRouter, Body, HTTPException
from datetime import datetime
from typing import Dict, Any, Optional
import hashlib
import os
import requests

from .github_store import github_write_json

"""Auth routes.

IMPORTANT:
The main FastAPI app mounts this router with `prefix="/auth"`.
So this router must NOT also define `prefix="/auth"`, otherwise paths become
`/auth/auth/login` and `/auth/auth/register` and the frontend will get 404.
"""

router = APIRouter(tags=["Auth"])

# ---- GitHub raw read config (login reads from GitHub) ----
GITHUB_OWNER = os.getenv("GITHUB_REPO_OWNER", "wealthoceaninstitute-commits")
GITHUB_REPO  = os.getenv("GITHUB_REPO_NAME", "Multiuser_clients")
BRANCH = os.getenv("GITHUB_BRANCH", "main")


# ---- small helpers ----
def _norm(s: Optional[str]) -> str:
    """Normalize user input to avoid invisible whitespace bugs."""
    return (s or "").strip()

def _safe(s: str) -> str:
    """Filesystem-safe key (also useful to store email-based profiles)."""
    s = _norm(s).replace(" ", "_")
    return "".join(ch for ch in s if ch.isalnum() or ch in ("_", "-"))

def hash_password(p: str) -> str:
    # IMPORTANT: always normalize before hashing
    return hashlib.sha256(_norm(p).encode("utf-8")).hexdigest()


@router.post("/register")
def register(payload: Dict[str, Any] = Body(...)):
    """
    Register a new user.

    Required fields: userid, email, password

    Storage:
      - Primary: data/users/<userid>/profile.json
      - Secondary (optional): data/users/<safe_email>/profile.json  (enables email login)
    """
    userid = _norm(payload.get("userid"))
    email = _norm(payload.get("email"))
    password = _norm(payload.get("password"))

    if not userid or not email or not password:
        raise HTTPException(status_code=400, detail="All fields required")

    profile = {
        "userid": userid,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.utcnow().isoformat(),
    }

    # Attempt to write to GitHub but do not crash on failure
    try:
        # Primary location (userid)
        github_write_json(f"data/users/{userid}/profile.json", profile)

        # Secondary location (safe email) so login can accept email as userid too
        safe_email = _safe(email)
        if safe_email and safe_email != userid:
            github_write_json(f"data/users/{safe_email}/profile.json", profile)

    except Exception as e:
        # Don't leak sensitive info
        print("[auth] GitHub write failed:", str(e)[:200])

    return {"success": True}


@router.post("/login")
def login(payload: Dict[str, Any] = Body(...)):
    """
    Login with either:
      - userid (preferred)
      - email (supported via safe-email storage + fallback lookups)

    Expects: { userid|username, password }
    """
    username = _norm(payload.get("userid") or payload.get("username"))
    password = _norm(payload.get("password"))

    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing credentials")

    # Never print passwords
    print("[auth] login attempt:", username)

    candidates = []
    # 1) as provided (legacy behavior)
    candidates.append(username)
    # 2) safe() version (helps when frontend sends email, or older code used safe keys)
    safe_u = _safe(username)
    if safe_u and safe_u not in candidates:
        candidates.append(safe_u)

    # Try each candidate path until we find a profile.json
    user = None
    tried = []
    for key in candidates:
        path = f"data/users/{key}/profile.json"
        tried.append(path)
        url = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{BRANCH}/{path}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                user = r.json()
                break
        except Exception:
            continue

    if not user:
        # Avoid revealing which usernames exist
        raise HTTPException(status_code=401, detail="Invalid login")

    if user.get("password") != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid login")

    # Return the canonical userid stored in profile (important if login used email)
    return {"success": True, "userid": user.get("userid") or username}
