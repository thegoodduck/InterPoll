#!/usr/bin/env python3
"""
Flask polling app with integrated Idena sign-in (full start→authenticate→callback flow),
atomic vote storage, transparency logging, optional Google OAuth.

Fixes:
- Adds /auth/v1/callback (idena_callback) so url_for('idena_callback') actually resolves.
- Supports BASE_URL to force absolute HTTPS URLs for web wallet (ngrok/cloudflared).
- Adds permissive CORS for /auth/v1/* so app.idena.io can POST across origins.
- Keeps desktop dna:// flow working with IDENA_USE_DESKTOP=1.
"""
import os
import secrets
import subprocess
import hashlib
import hmac
from datetime import datetime, timezone
import json
import logging
from collections import Counter
from urllib.parse import urlencode, quote_plus, urljoin

from flask import (
    Flask, render_template, request, redirect, url_for,
    make_response, session, Response, send_file, abort
)
# from authlib.integrations.flask_client import OAuth  # unused
# from dotenv import load_dotenv  # unused
import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import uuid
from eth_account.messages import encode_defunct
from eth_account import Account
import tempfile
import fcntl
import errno
from werkzeug.routing import BuildError

# --- Config & Constants ---
VOTE_DIR = os.environ.get("VOTE_DIR", "votes")
DB_FILE = os.environ.get("DB_FILE", "votes_db.json")
LOG_FILE = os.environ.get("LOG_FILE", "votes_log.jsonl")
LOG_STATE = os.environ.get("LOG_STATE", "log_state.json")
CHAIN_HEAD_FILE = os.environ.get("CHAIN_HEAD_FILE", "chain_head.txt")
PRIVATE_DIR = os.environ.get("PRIVATE_DIR", "private")

IDENA_VERIFY_URL = os.environ.get("IDENA_VERIFY_URL", "")
IDENA_VERIFY_METHOD = os.environ.get("IDENA_VERIFY_METHOD", "local").lower()

# If set to "1" use desktop dna:// scheme, otherwise use https://app.idena.io
IDENA_USE_DESKTOP = os.environ.get("IDENA_USE_DESKTOP", "0") == "1"

# If you’re using the web wallet, set this to your public HTTPS base (e.g., https://x.ngrok-free.app)
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

POLL_ID = os.environ.get("POLL_ID", "poll_001")
POLL_QUESTION = os.environ.get("POLL_QUESTION", "Do you support this proposal?")
POLL_OPTIONS = json.loads(os.environ.get("POLL_OPTIONS_JSON", '["Yes","No","Maybe"]'))
# Optional Receipter integration (defaults to local receipter)
RECEIPTER_POST_URL = os.getenv("RECEIPTER_POST_URL", "http://localhost:7001/ingest")
RECEIPTER_PAGE_URL = os.getenv("RECEIPTER_PAGE_URL", "http://localhost:7001/")

# Microsoft OAuth config
MS_CLIENT_ID = os.getenv("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET", "")
MS_TENANT = os.getenv("MS_TENANT", "common")  # common | organizations | consumers | <tenant_id>
MS_SCOPES = os.getenv("MS_SCOPES", "openid profile email")
release = "debug"
# Privacy salts (set via env; fallback to Flask secret key after app init)
EVIDENCE_SALT = os.getenv("EVIDENCE_SALT", "")
IDENTITY_SALT = os.getenv("IDENTITY_SALT", "")
print("[DEBUG] InterPoll release", release, "started.")
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-change-me")
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)

# Resolve salts after app is available
if not EVIDENCE_SALT:
    EVIDENCE_SALT = app.secret_key
if not IDENTITY_SALT:
    IDENTITY_SALT = app.secret_key
EVIDENCE_SALT_BYTES = EVIDENCE_SALT.encode()
IDENTITY_SALT_BYTES = IDENTITY_SALT.encode()

def _hmac_sha256_hex(key_bytes: bytes, data: str) -> str:
    return hmac.new(key_bytes, (data or "").encode(), hashlib.sha256).hexdigest()

def compute_id_tag(identity: str) -> str:
    if not identity:
        return ""
    return _hmac_sha256_hex(IDENTITY_SALT_BYTES, identity)

def compute_ev_tag(ip: str, ua: str) -> str:
    combo = f"{ip or ''}|{ua or ''}"
    return _hmac_sha256_hex(EVIDENCE_SALT_BYTES, combo)

def _client_ip() -> str:
    try:
        xf = request.headers.get("X-Forwarded-For", "") or request.headers.get("x-forwarded-for", "")
        if xf:
            return xf.split(",")[0].strip()
        return request.remote_addr or ""
    except Exception:
        return ""

# If you actually want Flask to generate external URLs using BASE_URL host, you can optionally set:
# - Prefer using BASE_URL inside helper _abs_url() below
# app.config["SERVER_NAME"] = (BASE_URL.replace("https://", "").replace("http://", "") if BASE_URL else None)
# app.config["PREFERRED_URL_SCHEME"] = "https"

## Google OAuth via google-auth-oauthlib will be handled in /login/google route
## Guys this is a debug preview so please do not use it to decide where to send 2 bn dollars

idena_sessions = {}
used_nonces = set()
logger = logging.getLogger("poll_app")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# --- Auth helpers for per-poll login requirements ---
def _current_provider() -> str:
    u = session.get("user") or {}
    p = (u.get("_provider") or "").lower()
    return p

def _login_ok_for_poll(poll: dict) -> bool:
    req = (poll.get("login_required") or "none").lower()
    prov = _current_provider()
    if req in ("", "none"):
        return True
    if req == "google":
        return prov == "google"
    if req == "idena":
        return prov == "idena"
    if req == "any":
        return prov in ("google", "idena")
    return True
# ID For commits should be universal
# --- Helpers for absolute URLs ---
def _abs_url(path_endpoint_name: str, **values) -> str:
    """
    Build an absolute URL for a Flask endpoint.

    Parameters:
        path_endpoint_name (str): The name of the Flask endpoint.
        **values: Additional keyword arguments for url_for.

    Returns:
        str: An absolute URL as a string. If BASE_URL is set, the URL is joined to BASE_URL;
             otherwise, Flask's url_for with _external=True is used.
    """
    if BASE_URL:
        # Make a relative path via url_for without _external, then join
        rel = url_for(path_endpoint_name, _external=False, **values)
        return urljoin(BASE_URL + "/", rel.lstrip("/"))
    return url_for(path_endpoint_name, _external=True, **values)

# --- File utilities: atomic writes & locks ---
class FileLock:
    def __init__(self, path):
        self.path = path
        self.f = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.f = open(self.path, "a+")
        while True:
            try:
                fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
                break
            except IOError as e:
                if e.errno != errno.EINTR:
                    raise
        return self.f

    def __exit__(self, exc_type, exc, tb):
        try:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        finally:
            self.f.close()

def atomic_write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(path) or ".") as tf:
        json.dump(obj, tf, indent=2)
        tf.flush()
        os.fsync(tf.fileno())
        tmp = tf.name
    os.replace(tmp, path)

def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(path) or ".") as tf:
        tf.write(text)
        tf.flush()
        os.fsync(tf.fileno())
        tmp = tf.name
    os.replace(tmp, path)

# --- Vote DB and Logging ---
if os.path.exists(DB_FILE):
    try:
        with open(DB_FILE, "r") as f:
            votes_db = json.load(f)
    except Exception:
        logger.exception("Cannot load DB; starting fresh.")
        votes_db = {"votes": {}, "counts": {opt: 0 for opt in POLL_OPTIONS}}
else:
    votes_db = {"votes": {}, "counts": {opt: 0 for opt in POLL_OPTIONS}}

# Define save_db before first use
def save_db():
    with FileLock(DB_FILE + ".lock"):
        atomic_write_json(DB_FILE, votes_db)

# On load, scrub legacy fingerprinting fields from global DB and migrate identity->identity_tag
try:
    changed = False
    for k, v in list(votes_db.get("votes", {}).items()):
        if isinstance(v, dict):
            if "ip" in v:
                v.pop("ip", None)
                changed = True
            if "ua" in v:
                v.pop("ua", None)
                changed = True
            # Migrate legacy raw identity to salted tag
            if "identity" in v and "identity_tag" not in v:
                try:
                    tag = compute_id_tag(v.get("identity") or "")
                    v["identity_tag"] = tag
                    v.pop("identity", None)
                    changed = True
                except Exception:
                    logger.exception("Failed to migrate legacy identity to identity_tag (global)")
    if changed:
        save_db()
except Exception:
    logger.exception("Failed to sanitize global DB")

def _canonical_json(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))
def _sha256_hex(b: bytes): return hashlib.sha256(b).hexdigest()

def _load_log_state():
    if os.path.exists(LOG_STATE):
        try:
            with open(LOG_STATE, "r") as f:
                return json.load(f)
        except Exception:
            logger.exception("Corrupt log state; resetting.")
    return {"count":0, "head":""}

def _save_log_state(state):
    with FileLock(LOG_STATE + ".lock"):
        atomic_write_json(LOG_STATE, state)

def append_transparency_log(entry: dict):
    state = _load_log_state()
    prev = bytes.fromhex(state.get("head","")) if state.get("head") else b""
    ej = _canonical_json(entry)
    eh = _sha256_hex(ej.encode())
    nh = _sha256_hex(prev + bytes.fromhex(eh))
    idx = state.get("count", 0)
    rec = {"index": idx, "entry": entry, "entry_hash": eh, "chain_head": nh}
    with FileLock(LOG_FILE + ".lock"):
        with open(LOG_FILE, "a") as f:
            f.write(_canonical_json(rec) + "\n")
        state["count"] = idx + 1
        state["head"] = nh
        _save_log_state(state)
        atomic_write_text(CHAIN_HEAD_FILE, f"poll={POLL_ID}\nindex={idx}\nhead={nh}\n")
    try:
        subprocess.run(["ots", "stamp", CHAIN_HEAD_FILE], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        logger.debug("ots not installed")
    except Exception as e:
        logger.warning("ots error: %s", e)
    return eh, nh, idx

# --- Private audit logging (no vote choice, for admin eyes only) ---
def _append_private_audit(poll_id: str, ts: str, provider: str, identity: str, vote_hash: str, extra: dict | None = None):
    if not provider or not identity:
        return
    try:
        os.makedirs(PRIVATE_DIR, exist_ok=True)
        try:
            os.chmod(PRIVATE_DIR, 0o700)
        except Exception:
            pass
        base_entry = {
            "poll": poll_id,
            "timestamp": ts,
            "provider": provider,
            "identity": identity,
            "vote_id": vote_hash,
        }
        if extra:
            base_entry.update(extra)
        # Global audit file
        glob_path = os.path.join(PRIVATE_DIR, "audit.jsonl")
        with FileLock(glob_path + ".lock"):
            with open(glob_path, "a") as f:
                f.write(_canonical_json(base_entry) + "\n")
        # Per-poll audit file
        pp_path = os.path.join(PRIVATE_DIR, f"audit_{poll_id}.jsonl")
        with FileLock(pp_path + ".lock"):
            with open(pp_path, "a") as f:
                f.write(_canonical_json(base_entry) + "\n")
    except Exception:
        logger.exception("Failed to append private audit entry for poll %s", poll_id)

def iter_log_entries():
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE) as f:
        for line in f:
            try:
                yield json.loads(line)
            except Exception:
                logger.exception("bad log entry")
                continue

def rebuild_counts_and_anomalies():
    counts = Counter({opt:0 for opt in POLL_OPTIONS})
    anomalies = []
    for rec in iter_log_entries() or []:
        e = rec.get("entry",{})
        c = e.get("choice")
        if c in counts:
            counts[c] += 1
        fn = e.get("filename") or f"{e.get('id','')}.txt"
        fh = e.get("file_hash") or e.get("id")
        p = os.path.join(VOTE_DIR, fn)
        if not os.path.exists(p):
            anomalies.append({"type": "missing_file", "filename": fn})
            continue
        try:
            with open(p, "rb") as vf:
                data_bytes = vf.read()
            a = hashlib.sha256(data_bytes).hexdigest()
            if fh and a != fh:
                anomalies.append({"type": "hash_mismatch", "filename": fn})
        except Exception as ex:
            anomalies.append({"type": "read_error", "filename": fn, "error": str(ex)})
    return counts, anomalies

# --- Idena verification ---
def verify_eth_signature_local(address: str, message: str, signature: str) -> bool:
    try:
        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == address.lower()
    except Exception:
        return False

def verify_idena_signature(address: str, message: str, signature: str) -> bool:
    if IDENA_VERIFY_METHOD == "remote" and IDENA_VERIFY_URL:
        try:
            r = requests.post(IDENA_VERIFY_URL, json={"address":address,"message":message,"signature":signature}, timeout=10)
            if not r.ok:
                return False
            d = r.json()
            return bool(d.get("result") or d.get("success") or d.get("ok"))
        except Exception:
            logger.exception("Remote verify failed")
            return False
    return verify_eth_signature_local(address, message, signature)

# --- Minimal CORS for /auth/v1/* ---
CORS_PATH_PREFIX = "/auth/v1/"

@app.after_request
def add_cors_headers(resp: Response):
    # Only add CORS headers for /auth/v1/* endpoints
    try:
        if request.path.startswith(CORS_PATH_PREFIX):
            origin = request.headers.get("Origin")
            # In dev, be generous. In prod, pin to https://app.idena.io if you want.
            resp.headers["Access-Control-Allow-Origin"] = origin or "*"
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    except Exception:
        pass
    return resp

@app.route(CORS_PATH_PREFIX + "<path:sub>", methods=["OPTIONS"])
def cors_preflight(sub):
    resp = make_response("", 204)
    return add_cors_headers(resp)

# --- Microsoft Sign-in (OAuth 2.0 Authorization Code Flow) ---
@app.route("/login/microsoft")
def login_microsoft():
    if not MS_CLIENT_ID or not MS_CLIENT_SECRET:
        return "Microsoft OAuth not configured. Set MS_CLIENT_ID and MS_CLIENT_SECRET.", 500
    # Preserve next if we were enforcing login for a poll
    nxt = request.args.get("next")
    if nxt:
        session["_next"] = nxt
    state = secrets.token_urlsafe(16)
    session["ms_state"] = state
    redirect_uri = _abs_url("login_microsoft_callback")
    logger.info("Microsoft auth start tenant=%s redirect_uri=%s scopes=%s", MS_TENANT, redirect_uri, MS_SCOPES)
    auth_url = f"https://login.microsoftonline.com/{MS_TENANT}/oauth2/v2.0/authorize"
    params = {
        "client_id": MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": MS_SCOPES,
        "state": state,
    }
    return redirect(f"{auth_url}?{urlencode(params)}")

def _b64url_decode_json(segment: str) -> dict:
    import base64
    import json as _json
    s = segment + ("=" * ((4 - len(segment) % 4) % 4))
    try:
        data = base64.urlsafe_b64decode(s.encode("utf-8"))
        return _json.loads(data.decode("utf-8"))
    except Exception:
        return {}

@app.route("/login/microsoft/callback")
def login_microsoft_callback():
    err = request.args.get("error")
    if err:
        return f"Microsoft login error: {err}", 400
    state = request.args.get("state")
    if not state or state != session.get("ms_state"):
        return "Invalid state.", 400
    code = request.args.get("code")
    if not code:
        return "Missing code.", 400
    redirect_uri = _abs_url("login_microsoft_callback")
    token_url = f"https://login.microsoftonline.com/{MS_TENANT}/oauth2/v2.0/token"
    data = {
        "client_id": MS_CLIENT_ID,
        "client_secret": MS_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": MS_SCOPES,
    }
    try:
        tr = requests.post(token_url, data=data, timeout=15)
    except Exception:
        logger.exception("Microsoft token request failed")
        return "Token request failed", 500
    if not tr.ok:
        # Surface Azure AD error details to simplify setup debugging
        detail = None
        try:
            dj = tr.json()
            detail = dj.get("error_description") or dj.get("error")
        except Exception:
            detail = tr.text
        logger.warning("Microsoft token exchange failed: %s %s", tr.status_code, detail)
        return f"Token exchange failed: {tr.status_code} {detail}", 400
    tok = tr.json()
    idt = tok.get("id_token", "")
    # Parse id_token claims without signature verification (trusted via token endpoint response)
    claims = {}
    try:
        parts = idt.split(".")
        if len(parts) >= 2:
            claims = _b64url_decode_json(parts[1])
    except Exception:
        claims = {}
    # Claims of interest: sub, name, preferred_username, email, oid
    sub = claims.get("sub") or claims.get("oid") or ""
    email = claims.get("email") or claims.get("preferred_username") or ""
    name = claims.get("name") or ""
    session['user'] = {
        '_provider': 'microsoft',
        'email': email,
        'name': name,
        'sub': sub,
        'picture': None
    }
    # Clean state
    session.pop("ms_state", None)
    # Redirect back if we were enforcing login for a poll
    nxt = session.pop('_next', None)
    if nxt:
        try:
            return redirect(nxt)
        except Exception:
            pass
    return redirect(url_for('index'))

# --- Idena sign-in endpoints ---
@app.route("/auth/v1/init", methods=["POST"])
def idena_init():
    token = secrets.token_urlsafe(16)
    try:
        callback = _abs_url("idena_callback")
    except BuildError:
        callback = _abs_url("idena_finalize")  # fallback (should not happen now)
    nonce_endpoint = _abs_url("idena_start_session")
    auth_endpoint = _abs_url("idena_authenticate")
    favicon = _abs_url("static", filename="favicon.ico")
    params = {
        "token": token,
        "callback_url": callback,
        "nonce_endpoint": nonce_endpoint,
        "authentication_endpoint": auth_endpoint,
        "auth_endpoint": auth_endpoint,
        "favicon_url": favicon
    }
    if token not in idena_sessions:
        idena_sessions[token] = {"nonce": None, "address": None, "authenticated": False}
    if IDENA_USE_DESKTOP:
        q = "&".join(f"{k}={quote_plus(v)}" for k, v in params.items())
        signin_uri = f"dna://signin/v1?{q}"
    else:
        signin_uri = "https://app.idena.io/dna/signin?" + urlencode(params)
    return {"success": True, "token": token, "signin_url": signin_uri}

@app.route("/auth/v1/status")
def idena_status():
    token = request.args.get("token")
    sess = idena_sessions.get(token)
    if not sess:
        return {"success": False, "error": "unknown_token"}, 404
    return {"success": True, "authenticated": bool(sess.get("authenticated")), "address": sess.get("address"), "has_nonce": bool(sess.get("nonce"))}

@app.route("/auth/v1/finalize", methods=["POST"])
def idena_finalize():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    sess = idena_sessions.get(token)
    if not sess or not sess.get("authenticated"):
        return {"success": False, "error": "not_authenticated"}, 400
    session["user"] = {"_provider": "idena", "address": sess.get("address"), "session_token": token}
    return {"success": True}

@app.route("/auth/v1/start-session", methods=["POST"])
def idena_start_session():
    raw_json = request.get_json(silent=True) or {}
    token = (raw_json.get("token") or request.form.get("token") or request.args.get("token"))
    address = (raw_json.get("address") or request.form.get("address") or request.args.get("address") or "").strip().lower()
    logger.debug("start-session inbound token=%s address=%s content_type=%s", token, address, request.content_type)
    if not token:
        logger.info("start-session missing token (addr=%s)", address)
        return {"success": False, "error": "missing_token"}, 400
    nonce = f"signin-{uuid.uuid4()}"
    idena_sessions[token] = {"nonce": nonce, "address": address or None, "authenticated": False}
    logger.info("start-session token=%s addr=%s nonce=%s", token, address or None, nonce)
    return {"nonce": nonce, "success": True, "data": {"nonce": nonce}}

@app.route("/auth/v1/authenticate", methods=["POST"])
def idena_authenticate():
    raw_json = request.get_json(silent=True) or {}
    token = (raw_json.get("token") or request.form.get("token") or request.args.get("token"))
    sig = (raw_json.get("signature") or request.form.get("signature") or request.args.get("signature"))
    logger.debug("authenticate inbound token=%s sig_len=%s content_type=%s", token, len(sig or ""), request.content_type)
    if not token or not sig:
        return {"success": False, "error": "missing_token_or_signature"}, 400
    sess = idena_sessions.get(token)
    if not sess:
        logger.info("authenticate unknown token=%s", token)
        return {"success": False, "error": "unknown_session"}, 400
    nonce = sess.get("nonce")
    addr = sess.get("address")
    if not nonce:
        logger.info("authenticate no nonce token=%s", token)
        return {"success": False, "error": "no_nonce"}, 400
    if nonce in used_nonces:
        logger.info("authenticate replay nonce=%s", nonce)
        return {"success": True, "data": {"authenticated": False, "replay": True}}
    if not addr:
        try:
            msg = encode_defunct(text=nonce)
            recovered = Account.recover_message(msg, signature=sig)
            sess["address"] = recovered
            sess["authenticated"] = True
            used_nonces.add(nonce)
            logger.info("authenticate recovered addr=%s token=%s", recovered, token)
            return {"success": True, "authenticated": True, "address": recovered, "data": {"authenticated": True}}
        except Exception as e:
            logger.warning("authenticate recover failed token=%s err=%s", token, e)
            return {"success": True, "authenticated": False, "error": "recover_failed"}
    ok = verify_idena_signature(addr, nonce, sig)
    if ok:
        sess["authenticated"] = True
        used_nonces.add(nonce)
        logger.info("authenticate ok addr=%s token=%s", addr, token)
        return {"success": True, "authenticated": True, "address": addr}
    else:
        logger.info("authenticate bad sig addr=%s token=%s", addr, token)
        return {"success": True, "authenticated": False, "error": "bad_signature"}

# Backward compatibility for legacy templates referencing 'auth_idena'
@app.route("/auth/idena", methods=["GET", "POST"])
def auth_idena_compat():
    token = request.values.get("token")
    if token:
        return redirect(url_for("idena_finalize", token=token))
    return ("Provide ?token=... or update client to use /auth/v1/callback", 400)

# --- Explicit login_idena endpoint for templates calling url_for('login_idena') ---
@app.route("/login/idena")
def login_idena():
    token = secrets.token_urlsafe(16)
    callback = _abs_url("idena_callback")
    nonce_endpoint = _abs_url("idena_start_session")
    auth_endpoint = _abs_url("idena_authenticate")
    favicon = _abs_url("static", filename="favicon.ico")

    params = {
        "token": token,
        "callback_url": callback,
        "nonce_endpoint": nonce_endpoint,
        "authentication_endpoint": auth_endpoint,
        "auth_endpoint": auth_endpoint,
        "favicon_url": favicon
    }

    if token not in idena_sessions:
        idena_sessions[token] = {"nonce": None, "address": None, "authenticated": False}
    logger.info("Initiating Idena login token=%s callback=%s", token, callback)

    if IDENA_USE_DESKTOP:
        q = "&".join(f"{k}={quote_plus(v)}" for k, v in params.items())
        signin_uri = f"dna://signin/v1?{q}"
    else:
        signin_uri = "https://app.idena.io/dna/signin?" + urlencode(params)

    return redirect(signin_uri)

# --- NEW: Idena callback route (required) ---
@app.route("/auth/v1/callback")
def idena_callback():
    """
    The wallet redirects here with ?token=...
    We finalize the session (POST /auth/v1/finalize) from the browser via fetch
    and then send the user back to index.
    """
    token = request.args.get("token", "")
    # Minimal HTML/JS to finalize then redirect:
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Idena Callback</title></head>
<body>
<script>
(async () => {{
  const token = {json.dumps(token)};
  if (!token) {{
    window.location = {json.dumps(url_for('index'))};
    return;
  }}
  try {{
    const r = await fetch({json.dumps(url_for('idena_finalize'))}, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      credentials: 'include',
      body: JSON.stringify({{ token }})
    }});
  }} catch (e) {{
    // ignore
  }}
  window.location = {json.dumps(url_for('index'))};
}})();
</script>
</body></html>"""
    return Response(html, mimetype="text/html")
## Migrate to django somedays for better liability.
@app.route("/login/google")
def login_google():
    # Desktop OAuth flow using google-auth-oauthlib
    SCOPES = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secrets.json',
        scopes=SCOPES
    )
    creds = flow.run_local_server(port=8080)
    service = build('oauth2', 'v2', credentials=creds)
    user_info = service.userinfo().get().execute()
    # Store user info in session
    session['user'] = {
        '_provider': 'google',
        'email': user_info.get('email'),
        'name': user_info.get('name'),
        'sub': user_info.get('id'),
        'picture': user_info.get('picture')
    }
    # Redirect back if we were enforcing login for a poll
    nxt = session.pop('_next', None)
    if nxt:
        return redirect(nxt)
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# --- Poll storage ---
POLL_LIST_FILE = os.environ.get("POLL_LIST_FILE", "polls.json")
def load_polls():
    if os.path.exists(POLL_LIST_FILE):
        try:
            with open(POLL_LIST_FILE, "r") as f:
                return json.load(f)
        except Exception:
            logger.exception("Cannot load poll list; starting fresh.")
    return []
def save_polls(polls):
    atomic_write_json(POLL_LIST_FILE, polls)

# --- Per-poll helpers (shareable poll pages) ---
def get_poll(poll_id: str):
    for p in load_polls():
        if p.get("id") == poll_id:
            return p
    return None

def _paths_for_poll(poll_id: str):
    base_votes_dir = os.path.join(VOTE_DIR, poll_id)
    os.makedirs(base_votes_dir, exist_ok=True)
    db = f"votes_db_{poll_id}.json"
    log = f"votes_log_{poll_id}.jsonl"
    state = f"log_state_{poll_id}.json"
    head = f"chain_head_{poll_id}.txt"
    return {
        "VOTE_DIR": base_votes_dir,
        "DB_FILE": os.path.join(base_votes_dir, db),
        "LOG_FILE": os.path.join(base_votes_dir, log),
        "LOG_STATE": os.path.join(base_votes_dir, state),
        "CHAIN_HEAD_FILE": os.path.join(base_votes_dir, head),
    }

def _load_db_for_poll(poll_id: str, options: list[str]):
    paths = _paths_for_poll(poll_id)
    if os.path.exists(paths["DB_FILE"]):
        try:
            with open(paths["DB_FILE"], "r") as f:
                db = json.load(f)
            # Scrub legacy fingerprinting fields from per-poll DB and migrate identity->identity_tag
            changed = False
            for _k, v in list((db.get("votes") or {}).items()):
                if isinstance(v, dict):
                    if "ip" in v:
                        v.pop("ip", None)
                        changed = True
                    if "ua" in v:
                        v.pop("ua", None)
                        changed = True
                    if "identity" in v and "identity_tag" not in v:
                        try:
                            tag = compute_id_tag(v.get("identity") or "")
                            v["identity_tag"] = tag
                            v.pop("identity", None)
                            changed = True
                        except Exception:
                            logger.exception("Failed to migrate legacy identity to identity_tag for %s", poll_id)
            if changed:
                try:
                    _save_db_for_poll(poll_id, db)
                except Exception:
                    logger.exception("Failed to sanitize DB for %s", poll_id)
            return db
        except Exception:
            logger.exception("Cannot load DB for %s; starting fresh.", poll_id)
    return {"votes": {}, "counts": {opt: 0 for opt in options}}

def _save_db_for_poll(poll_id: str, db_obj: dict):
    paths = _paths_for_poll(poll_id)
    with FileLock(paths["DB_FILE"] + ".lock"):
        atomic_write_json(paths["DB_FILE"], db_obj)

def _append_log_for_poll(poll_id: str, entry: dict):
    paths = _paths_for_poll(poll_id)
    # Per-poll transparency log
    if os.path.exists(paths["LOG_STATE"]):
        try:
            with open(paths["LOG_STATE"], "r") as f:
                state = json.load(f)
        except Exception:
            state = {"count":0, "head":""}
    else:
        state = {"count":0, "head":""}
    prev = bytes.fromhex(state.get("head","")) if state.get("head") else b""
    ej = _canonical_json(entry)
    eh = _sha256_hex(ej.encode())
    nh = _sha256_hex(prev + bytes.fromhex(eh))
    idx = state.get("count", 0)
    rec = {"index": idx, "entry": entry, "entry_hash": eh, "chain_head": nh}
    with FileLock(paths["LOG_FILE"] + ".lock"):
        with open(paths["LOG_FILE"], "a") as f:
            f.write(_canonical_json(rec) + "\n")
        state["count"] = idx + 1
        state["head"] = nh
        with FileLock(paths["LOG_STATE"] + ".lock"):
            atomic_write_json(paths["LOG_STATE"], state)
        atomic_write_text(paths["CHAIN_HEAD_FILE"], f"poll={poll_id}\nindex={idx}\nhead={nh}\n")
    try:
        subprocess.run(["ots", "stamp", paths["CHAIN_HEAD_FILE"]], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        logger.debug("ots not installed")
    except Exception as e:
        logger.warning("ots error: %s", e)
    return eh, nh, idx

def _iter_log_entries_for_poll(poll_id: str):
    paths = _paths_for_poll(poll_id)
    lf = paths["LOG_FILE"]
    if not os.path.exists(lf):
        return
    with open(lf) as f:
        for line in f:
            try:
                yield json.loads(line)
            except Exception:
                logger.exception("bad log entry (%s)", poll_id)
                continue

def _rebuild_counts_for_poll(poll_id: str, options: list[str]):
    paths = _paths_for_poll(poll_id)
    counts = Counter({opt:0 for opt in options})
    anomalies = []
    for rec in _iter_log_entries_for_poll(poll_id) or []:
        e = rec.get("entry",{})
        c = e.get("choice")
        if c in counts:
            counts[c] += 1
        fn = e.get("filename") or f"{e.get('id','')}.txt"
        fh = e.get("file_hash") or e.get("id")
        p = os.path.join(paths["VOTE_DIR"], fn)
        if not os.path.exists(p):
            anomalies.append({"type": "missing_file", "filename": fn})
            continue
        try:
            with open(p, "rb") as vf:
                data_bytes = vf.read()
            a = hashlib.sha256(data_bytes).hexdigest()
            if fh and a != fh:
                anomalies.append({"type": "hash_mismatch", "filename": fn})
        except Exception as ex:
            anomalies.append({"type": "read_error", "filename": fn, "error": str(ex)})
    # load state
    head = ""
    st_path = _paths_for_poll(poll_id)["LOG_STATE"]
    if os.path.exists(st_path):
        try:
            with open(st_path, "r") as f:
                head = (json.load(f) or {}).get("head", "")
        except Exception:
            head = ""
    return counts, anomalies, head

# --- Poll creation route ---
@app.route("/create_poll", methods=["GET", "POST"])
def create_poll():
    if request.method == "GET":
        return render_template("create_poll.html")
    # POST: handle form
    question = request.form.get("question", "").strip()
    options = [opt.strip() for opt in request.form.getlist("options") if opt.strip()]
    login_required = request.form.get("login_required", "none")
    cookie_mode = request.form.get("cookie_mode", "yes")
    if not question or len(options) < 2:
        return "Poll must have a question and at least two non-empty options.", 400
    poll_id = f"poll_{uuid.uuid4().hex[:8]}"
    poll = {
        "id": poll_id,
        "question": question,
        "options": options,
        "login_required": login_required,
        "cookie_mode": cookie_mode,
        "created": datetime.now(timezone.utc).isoformat()
    }
    polls = load_polls()
    polls.append(poll)
    save_polls(polls)
    return redirect(url_for("index"))

# --- Per-poll pages ---
@app.route("/poll/<poll_id>")
def poll_detail(poll_id):
    user = session.get("user")
    p = get_poll(poll_id)
    if not p:
        abort(404)
    voted = request.cookies.get(f"voted_{poll_id}")
    can_vote = _login_ok_for_poll(p)
    return render_template(
        "poll_detail.html",
        poll=p,
        user=user,
        voted=voted,
        can_vote=can_vote,
    )

@app.route("/poll/<poll_id>/vote", methods=["POST"])
def poll_vote(poll_id):
    p = get_poll(poll_id)
    if not p:
        abort(404)
    # Enforce per-poll login requirement
    if not _login_ok_for_poll(p):
        req = (p.get("login_required") or "none").lower()
        if req == "google":
            # best-effort next handling via session
            session["_next"] = url_for("poll_detail", poll_id=poll_id)
            return redirect(url_for("login_google"))
        if req == "idena":
            session["_next"] = url_for("poll_detail", poll_id=poll_id)
            return redirect(url_for("login_idena"))
        abort(403)
    choice = request.form.get("vote")
    options = p.get("options") or []
    if choice not in options:
        return "Invalid vote option!", 400
    cookie_key = f"voted_{poll_id}"
    user = session.get("user") or {}
    provider = user.get("_provider")
    identity = (f"idena:{user['address']}" if provider=="idena"
                else f"{provider}:{user.get('sub') or user.get('id') or ''}") if provider else ""
    id_tag = compute_id_tag(identity)
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    ev_tag = compute_ev_tag(ip, ua)
    db = _load_db_for_poll(poll_id, options)
    if id_tag:
        if any(v.get("identity_tag")==id_tag for v in db["votes"].values()):
            return redirect(url_for("poll_results", poll_id=poll_id, error="account"))
    else:
        # Anonymous dedup: block if same evidence_tag has already voted this poll
        if ev_tag and any(v.get("evidence_tag")==ev_tag for v in db["votes"].values()):
            return redirect(url_for("poll_results", poll_id=poll_id, error="device"))
    if request.cookies.get(cookie_key):
        return redirect(url_for("poll_results", poll_id=poll_id, error="device"))
    ts = datetime.now(timezone.utc).isoformat()
    # Privacy: do not collect/store raw IP/UA; store only HMAC tags in DB
    vote_data = f"{choice}|{ts}|{id_tag}"
    file_hash = hashlib.sha256(vote_data.encode()).hexdigest()
    vote_dir = _paths_for_poll(poll_id)["VOTE_DIR"]
    os.makedirs(vote_dir, exist_ok=True)
    fn = os.path.join(vote_dir, f"{file_hash}.txt")
    try:
        atomic_write_text(fn, vote_data)
    except Exception:
        logger.exception("Vote file error")
        return "Error saving vote", 500
    try:
        subprocess.run(["ots", "stamp", fn], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    db["votes"][file_hash] = {"choice":choice, "timestamp":ts, "identity_tag":id_tag, "evidence_tag": ev_tag}
    db["counts"].setdefault(choice, 0)
    db["counts"][choice] += 1
    try:
        _save_db_for_poll(poll_id, db)
    except Exception:
        logger.exception("save_db error")
    # Private audit log: who (provider+identity) voted on which poll (no choice)
    try:
        _append_private_audit(
            poll_id=poll_id,
            ts=ts,
            provider=(provider or ""),
            identity=(identity or ""),
            vote_hash=file_hash,
            extra={"ip": ip, "ua": ua, "evidence_tag": ev_tag},
        )
    except Exception:
        logger.exception("audit log error")
    entry = {"poll":poll_id,"choice":choice,"timestamp":ts,"id":file_hash,
             "identity_tag":id_tag,"file_hash":file_hash,"filename":f"{file_hash}.txt"}
    try:
        eh, _chain_head, idx = _append_log_for_poll(poll_id, entry)
    except Exception:
        logger.exception("log append error")
        eh, idx = None, 0
    resp = make_response(redirect(url_for("poll_receipt", poll_id=poll_id, h=(eh or ""), i=idx)))
    secure = os.getenv("PRODUCTION","").lower() in ("1","true")
    resp.set_cookie(cookie_key, "1", max_age=30*24*3600, samesite="Lax", secure=secure, httponly=True)
    return resp

@app.route("/poll/<poll_id>/results")
def poll_results(poll_id):
    p = get_poll(poll_id)
    if not p:
        abort(404)
    try:
        counts, anomalies, head = _rebuild_counts_for_poll(poll_id, p.get("options") or [])
        total = sum(counts.values()) or 0
        results_list = []
        for opt in p.get("options") or []:
            c = counts.get(opt, 0)
            pct = round((c / total * 100.0), 2) if total else 0.0
            results_list.append({"option": opt, "count": c, "percent": pct})
        # Map error code from query to friendly message
        err_code = request.args.get("error")
        err_msg = None
        if err_code == "device":
            err_msg = "This device has already voted."
        elif err_code == "account":
            err_msg = "This account has already voted."
        return render_template(
            "result.html",
            question=p.get("question"),
            results=results_list,
            total_votes=total,
            anomalies=anomalies,
            head_hash=head,
            error=err_msg,
        )
    except Exception as e:
        logger.exception("poll results error")
        return render_template(
            "result.html",
            question=p.get("question"),
            results=[],
            total_votes=0,
            anomalies=[],
            head_hash="",
            error=str(e),
        ), 500

@app.route("/poll/<poll_id>/receipt")
def poll_receipt(poll_id):
    entry_hash = request.args.get("h","")
    idx = int(request.args.get("i",0))
    ts = ""
    file_id = ""
    try:
        for rec in _iter_log_entries_for_poll(poll_id) or []:
            if rec.get("index") == idx:
                e = rec.get("entry", {})
                if entry_hash and rec.get("entry_hash") != entry_hash:
                    continue
                ts = e.get("timestamp", "")
                file_id = e.get("id") or e.get("file_hash") or ""
                break
    except Exception:
        logger.exception("poll receipt lookup failure")
    # head
    head = ""
    st_path = _paths_for_poll(poll_id)["LOG_STATE"]
    if os.path.exists(st_path):
        try:
            with open(st_path, "r") as f:
                head = (json.load(f) or {}).get("head", "")
        except Exception:
            pass
    return render_template(
        "receipt.html",
        entry_hash=entry_hash,
        index=idx,
        head=head,
        poll_id=poll_id,
        ts=ts,
        file_id=file_id,
        receipter_url=RECEIPTER_POST_URL,
        receipter_page_url=RECEIPTER_PAGE_URL,
        back_url=url_for('poll_detail', poll_id=poll_id),
        results_url=url_for('poll_results', poll_id=poll_id),
        download_log_url=url_for('poll_download_log', poll_id=poll_id),
        download_head_url=url_for('poll_download_chain_head', poll_id=poll_id),
    )

@app.route("/poll/<poll_id>/download_log")
def poll_download_log(poll_id):
    lf = _paths_for_poll(poll_id)["LOG_FILE"]
    if not os.path.exists(lf):
        abort(404)
    return send_file(lf, as_attachment=True, download_name=os.path.basename(lf))

@app.route("/poll/<poll_id>/download_chain_head")
def poll_download_chain_head(poll_id):
    hf = _paths_for_poll(poll_id)["CHAIN_HEAD_FILE"]
    if not os.path.exists(hf):
        abort(404)
    return send_file(hf, as_attachment=True, download_name=os.path.basename(hf))

@app.route("/poll/<poll_id>/chain-head")
def poll_chain_head_txt(poll_id):
    hf = _paths_for_poll(poll_id)["CHAIN_HEAD_FILE"]
    if not os.path.exists(hf):
        abort(404)
    with open(hf, "r") as f:
        data = f.read()
    return Response(data, mimetype="text/plain")

@app.route("/poll/<poll_id>/log")
def poll_log_jsonl(poll_id):
    lf = _paths_for_poll(poll_id)["LOG_FILE"]
    if not os.path.exists(lf):
        abort(404)
    with open(lf, "r") as f:
        data = f.read()
    return Response(data, mimetype="application/x-ndjson")

@app.route("/")
def index():
    user = session.get("user")
    polls = load_polls()
    voted = request.cookies.get(f"voted_{POLL_ID}")
    return render_template("index.html", 
                          polls=polls, 
                          user=user, 
                          question=POLL_QUESTION, 
                          options=POLL_OPTIONS,
                          voted=voted)

@app.route("/vote", methods=["POST"])
def vote():
    choice = request.form.get("vote")
    if choice not in POLL_OPTIONS:
        return "Invalid vote option!", 400
    cookie_key = f"voted_{POLL_ID}"
    user = session.get("user") or {}
    provider = user.get("_provider")
    identity = (f"idena:{user['address']}" if provider=="idena"
                else f"{provider}:{user.get('sub') or user.get('id') or ''}") if provider else ""
    id_tag = compute_id_tag(identity)
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    ev_tag = compute_ev_tag(ip, ua)
    if id_tag:
        if any(v.get("identity_tag")==id_tag for v in votes_db["votes"].values()):
            return redirect(url_for("results", error="account"))
    else:
        if ev_tag and any(v.get("evidence_tag")==ev_tag for v in votes_db["votes"].values()):
            return redirect(url_for("results", error="device"))
    if request.cookies.get(cookie_key):
        return redirect(url_for("results", error="device"))
    ts = datetime.now(timezone.utc).isoformat()
    # Privacy: do not collect/store raw IP/UA; store only HMAC tags in DB
    vote_data = f"{choice}|{ts}|{id_tag}"
    file_hash = hashlib.sha256(vote_data.encode()).hexdigest()
    os.makedirs(VOTE_DIR, exist_ok=True)
    fn = os.path.join(VOTE_DIR, f"{file_hash}.txt")
    try:
        atomic_write_text(fn, vote_data)
    except Exception:
        logger.exception("Vote file error")
        return "Error saving vote", 500
    try:
        subprocess.run(["ots", "stamp", fn], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    votes_db["votes"][file_hash] = {"choice":choice, "timestamp":ts, "identity_tag":id_tag, "evidence_tag": ev_tag}
    votes_db["counts"].setdefault(choice, 0)
    votes_db["counts"][choice] += 1
    try:
        save_db()
    except Exception:
        logger.exception("save_db error")
    # Private audit log: who (provider+identity) voted on which poll (no choice)
    try:
        _append_private_audit(
            poll_id=POLL_ID,
            ts=ts,
            provider=(provider or ""),
            identity=(identity or ""),
            vote_hash=file_hash,
            extra={"ip": ip, "ua": ua, "evidence_tag": ev_tag},
        )
    except Exception:
        logger.exception("audit log error")
    entry = {"poll":POLL_ID,"choice":choice,"timestamp":ts,"id":file_hash,
             "identity_tag":id_tag,"file_hash":file_hash,"filename":f"{file_hash}.txt"}
    try:
        eh, _chain_head, idx = append_transparency_log(entry)
    except Exception:
        logger.exception("log append error")
        eh, idx = None, 0
    resp = make_response(redirect(url_for("receipt", h=eh or "", i=idx)))
    secure = os.getenv("PRODUCTION","").lower() in ("1","true")
    resp.set_cookie(cookie_key, "1", max_age=30*24*3600, samesite="Lax", secure=secure, httponly=True)
    return resp

@app.route("/results")
def results():
    try:
        counts, anomalies = rebuild_counts_and_anomalies()
        total = sum(counts.values()) or 0
        results_list = []
        for opt in POLL_OPTIONS:
            c = counts.get(opt, 0)
            pct = round((c / total * 100.0), 2) if total else 0.0
            results_list.append({"option": opt, "count": c, "percent": pct})
        state = _load_log_state()
        # Map error code from query to friendly message
        err_code = request.args.get("error")
        err_msg = None
        if err_code == "device":
            err_msg = "This device has already voted."
        elif err_code == "account":
            err_msg = "This account has already voted."
        return render_template(
            "result.html",
            question=POLL_QUESTION,
            results=results_list,
            total_votes=total,
            anomalies=anomalies,
            head_hash=state.get("head", ""),
            error=err_msg,
        )
    except Exception as e:
        logger.exception("results page error")
        return render_template(
            "result.html",
            question=POLL_QUESTION,
            results=[],
            total_votes=0,
            anomalies=[],
            head_hash="",
            error=str(e),
        ), 500

@app.route("/receipt")
def receipt():
    entry_hash = request.args.get("h","")
    idx = int(request.args.get("i",0))
    # Try to enrich with timestamp and file id
    ts = ""
    file_id = ""
    try:
        if entry_hash:
            for rec in iter_log_entries() or []:
                if rec.get("entry_hash") == entry_hash:
                    e = rec.get("entry", {})
                    ts = e.get("timestamp", "")
                    file_id = e.get("id") or e.get("file_hash") or ""
                    break
    except Exception:
        logger.exception("receipt lookup failure")
    state = _load_log_state()
    return render_template(
        "receipt.html",
        entry_hash=entry_hash,
        index=idx,
        head=state.get("head"),
        poll_id=POLL_ID,
        ts=ts,
        file_id=file_id,
        receipter_url=RECEIPTER_POST_URL,
        receipter_page_url=RECEIPTER_PAGE_URL,
        back_url=url_for('index'),
        results_url=url_for('results'),
        download_log_url=url_for('download_log'),
        download_head_url=url_for('download_chain_head'),
    )

@app.route("/download_log")
def download_log():
    if not os.path.exists(LOG_FILE):
        abort(404)
    return send_file(LOG_FILE, as_attachment=True, download_name=os.path.basename(LOG_FILE))

@app.route("/download_chain_head")
def download_chain_head():
    if not os.path.exists(CHAIN_HEAD_FILE):
        abort(404)
    return send_file(CHAIN_HEAD_FILE, as_attachment=True, download_name=os.path.basename(CHAIN_HEAD_FILE))

# --- Receipter support endpoints (global) ---
@app.route("/chain-head")
def chain_head_txt():
    if not os.path.exists(CHAIN_HEAD_FILE):
        abort(404)
    with open(CHAIN_HEAD_FILE, "r") as f:
        data = f.read()
    return Response(data, mimetype="text/plain")

@app.route("/log")
def log_jsonl():
    if not os.path.exists(LOG_FILE):
        abort(404)
    with open(LOG_FILE, "r") as f:
        data = f.read()
    # Newline-delimited JSON
    return Response(data, mimetype="application/x-ndjson")

def _recompute_chain_head_until(target_index: int):
    state_head = b""
    found = None
    if not os.path.exists(LOG_FILE):
        return None, None
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            idx = rec.get("index")
            eh = rec.get("entry_hash")
            if not isinstance(idx, int) or not isinstance(eh, str):
                continue
            try:
                ehb = bytes.fromhex(eh)
            except Exception:
                continue
            nh = hashlib.sha256(state_head + ehb).hexdigest()
            state_head = bytes.fromhex(nh)
            if idx == target_index:
                found = eh
                break
    return (state_head.hex() if state_head else None), found

@app.route("/verify", methods=["POST"])
def verify_receipt():
    r = request.get_json(silent=True) or {}
    entry_hash = (r.get("entry_hash") or r.get("entry") or "").strip()
    index = r.get("index")
    chain_head = (r.get("chain_head") or r.get("head") or "").strip()
    file_id = (r.get("file_id") or r.get("id") or r.get("file_hash") or "").strip()
    poll_id = (r.get("poll_id") or r.get("poll") or "").strip()
    if poll_id and poll_id != POLL_ID:
        return {"valid": False, "reason": "poll_id_mismatch"}, 400
    if not entry_hash or not isinstance(index, int):
        return {"valid": False, "reason": "missing_entry_or_index"}, 400
    rec_ok = False
    rec_chain = None
    try:
        for rec in iter_log_entries() or []:
            if rec.get("index") == index:
                if rec.get("entry_hash") != entry_hash:
                    return {"valid": False, "reason": "index_entry_mismatch"}, 400
                rec_ok = True
                rec_chain = rec.get("chain_head")
                break
    except Exception:
        logger.exception("verify: iter_log failure")
        return {"valid": False, "reason": "log_read_error"}, 500
    if not rec_ok:
        return {"valid": False, "reason": "not_found"}, 404
    recomputed_head, eh_at_idx = _recompute_chain_head_until(index)
    if not recomputed_head or eh_at_idx != entry_hash:
        return {"valid": False, "reason": "chain_recompute_failed"}, 400
    if chain_head and chain_head != recomputed_head:
        return {"valid": False, "reason": "head_mismatch"}, 400
    if rec_chain and rec_chain != recomputed_head:
        return {"valid": False, "reason": "record_head_mismatch"}, 400
    file_ok = None
    if file_id:
        vote_path = os.path.join(VOTE_DIR, f"{file_id}.txt")
        if os.path.exists(vote_path):
            try:
                with open(vote_path, "rb") as vf:
                    data = vf.read()
                calc = hashlib.sha256(data).hexdigest()
                file_ok = (calc == file_id)
            except Exception:
                file_ok = False
        else:
            file_ok = False
    return {
        "valid": True,
        "head": recomputed_head,
        "file_ok": file_ok,
        "index": index,
        "entry_hash": entry_hash,
    }

@app.route("/api/results")
def api_results():
    counts, anomalies = rebuild_counts_and_anomalies()
    total = sum(counts.values())
    return {
        "poll_id": POLL_ID,
        "question": POLL_QUESTION,
        "options": POLL_OPTIONS,
        "counts": counts,
        "total": total,
        "anomalies": anomalies,
        "head": _load_log_state().get("head"),
    }

@app.route("/_internal/status")
def status():
    return {"ok":True, "poll":POLL_ID, "votes":len(votes_db["votes"]), "counts":votes_db["counts"]}

# --- Server run ---
if __name__ == "__main__":
    os.makedirs(VOTE_DIR, exist_ok=True)
    try:
        with FileLock(DB_FILE + ".lock"):
            if not os.path.exists(DB_FILE):
                atomic_write_json(DB_FILE, votes_db)
    except Exception:
        logger.exception("DB init error")
    if app.secret_key == "dev-change-me":
        logger.warning("Running with dev secret key. Change FLASK_SECRET_KEY for production.")
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=int(os.getenv("PORT",5000)))
