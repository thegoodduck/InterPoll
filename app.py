#!/usr/bin/env python3
"""
Flask polling app with integrated Idena sign-in (full start→authenticate→callback flow),
atomic vote storage, transparency logging, optional Google OAuth.

This version includes a `login_idena` route to avoid BuildError when templates call
url_for('login_idena').
"""
import os
import secrets
import subprocess
import hashlib
from datetime import datetime, timezone
import json
import logging
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, make_response, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
import uuid
from eth_account.messages import encode_defunct
from eth_account import Account
import tempfile
import fcntl
import errno
from urllib.parse import urlencode, quote_plus
from werkzeug.routing import BuildError

# --- Config & Constants ---
load_dotenv()
VOTE_DIR = os.getenv("VOTE_DIR", "votes")
DB_FILE = os.getenv("DB_FILE", "votes_db.json")
LOG_FILE = os.getenv("LOG_FILE", "votes_log.jsonl")
LOG_STATE = os.getenv("LOG_STATE", "log_state.json")
CHAIN_HEAD_FILE = os.getenv("CHAIN_HEAD_FILE", "chain_head.txt")
IDENA_VERIFY_URL = os.getenv("IDENA_VERIFY_URL", "")
IDENA_VERIFY_METHOD = os.getenv("IDENA_VERIFY_METHOD", "local").lower()
# If set to "1" use desktop dna:// scheme, otherwise use https://app.idena.io
IDENA_USE_DESKTOP = os.getenv("IDENA_USE_DESKTOP", "0") == "1"
POLL_ID = os.getenv("POLL_ID", "poll_001")
POLL_QUESTION = os.getenv("POLL_QUESTION", "Do you support this proposal?")
POLL_OPTIONS = json.loads(os.getenv("POLL_OPTIONS_JSON", '["Yes","No","Maybe"]'))
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-change-me")
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)
oauth = OAuth(app)
if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    oauth.register(name='google',
                   client_id=os.getenv("GOOGLE_CLIENT_ID"),
                   client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                   server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                   client_kwargs={'scope': 'openid email profile'})
else:
    logging.getLogger().warning("Google OAuth not configured")
idena_sessions = {}
used_nonces = set()
logger = logging.getLogger("poll_app")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

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

def save_db():
    with FileLock(DB_FILE + ".lock"):
        atomic_write_json(DB_FILE, votes_db)

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

# --- Idena sign-in endpoints ---
@app.route("/auth/v1/init", methods=["POST"])
def idena_init():
    """Initialize an Idena login attempt and return sign-in URL + token.
    Front-end will open the sign-in URL (which triggers the wallet) and then poll /auth/v1/status.
    Once authenticated, it will POST /auth/v1/finalize to bind session in the current browser.
    """
    token = secrets.token_urlsafe(16)
    try:
        callback = url_for("idena_callback", _external=True)
    except BuildError:
        # Fallback to finalize if callback route not registered yet
        callback = url_for("idena_finalize", _external=True)
    nonce_endpoint = url_for("idena_start_session", _external=True)
    auth_endpoint = url_for("idena_authenticate", _external=True)
    favicon = url_for("static", filename="favicon.ico", _external=True)
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
    # Accept JSON, form, or query params
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
    # Return both new simple shape and legacy shape for compatibility
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
        # Try recover address directly
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
    # Have address, verify signature
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
        return redirect(url_for("idena_callback", token=token))
    return ("Provide ?token=... or update client to use /auth/v1/callback", 400)

# --- New route: explicit login_idena endpoint (used by templates that call url_for('login_idena')) ---
@app.route("/login/idena")
def login_idena():
    """
    Redirect user to Idena sign-in URL.
    Uses https://app.idena.io/dna/signin by default; set IDENA_USE_DESKTOP=1 to use dna:// scheme.
    """
    token = secrets.token_urlsafe(16)
    callback = url_for("idena_callback", _external=True)
    nonce_endpoint = url_for("idena_start_session", _external=True)
    auth_endpoint = url_for("idena_authenticate", _external=True)
    favicon = url_for("static", filename="favicon.ico", _external=True)

    params = {
        "token": token,
        "callback_url": callback,
        "nonce_endpoint": nonce_endpoint,
        # Provide both keys some clients use authentication_endpoint others auth_endpoint
        "authentication_endpoint": auth_endpoint,
        "auth_endpoint": auth_endpoint,
        "favicon_url": favicon
    }

    # Pre-create empty session so callback can still succeed if wallet calls authenticate slightly later
    if token not in idena_sessions:
        idena_sessions[token] = {"nonce": None, "address": None, "authenticated": False}
    logger.info("Initiating Idena login token=%s callback=%s", token, callback)

    if IDENA_USE_DESKTOP:
        # dna:// scheme needs percent-encoding for callback_url etc.
        # build dna URI manually
        q = "&".join(f"{k}={quote_plus(v)}" for k, v in params.items())
        signin_uri = f"dna://signin/v1?{q}"
    else:
        signin_uri = "https://app.idena.io/dna/signin?" + urlencode(params)

    return redirect(signin_uri)

# --- Optional JWT-based Idena login omitted for brevity ---

# --- Google OAuth login and logout endpoints ---
@app.route("/login/google")
def login_google():
    redirect_uri = url_for("auth_google", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google")
def auth_google():
    oauth.google.authorize_access_token()
    u = oauth.google.userinfo()
    if u:
        u["_provider"] = "google"
        session["user"] = u
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# --- Main web routes ---
@app.route("/")
def index():
    voted = request.cookies.get(f"voted_{POLL_ID}") is not None
    user = session.get("user")
    signin_link = None
    if not user:
        # for templates that expect signin_link
        token = secrets.token_urlsafe(16)
        app_callback = url_for("idena_callback", _external=True)
        start = url_for("idena_start_session", _external=True)
        auth = url_for("idena_authenticate", _external=True)
        favicon = url_for("static", filename="favicon.ico", _external=True)
        params = {
            "token": token,
            "callback_url": app_callback,
            "nonce_endpoint": start,
            "authentication_endpoint": auth,
            "favicon_url": favicon
        }
        if IDENA_USE_DESKTOP:
            q = "&".join(f"{k}={quote_plus(v)}" for k, v in params.items())
            signin_link = f"dna://signin/v1?{q}"
        else:
            signin_link = "https://app.idena.io/dna/signin?" + urlencode(params)

    return render_template("index.html", question=POLL_QUESTION, options=POLL_OPTIONS,
                           voted=voted, user=user, signin_link=signin_link)

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
    if identity:
        if any(v.get("identity")==identity for v in votes_db["votes"].values()):
            return redirect(url_for("results"))
    if request.cookies.get(cookie_key):
        return redirect(url_for("results"))
    ts = datetime.now(timezone.utc).isoformat()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = (request.headers.get("User-Agent","") or "")[:400]
    vote_data = f"{choice}|{ts}|{ip}|{ua}|{identity}"
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
        # stamping is best-effort
        pass
    votes_db["votes"][file_hash] = {"choice":choice, "timestamp":ts, "ip":ip, "ua":ua, "identity":identity}
    votes_db["counts"].setdefault(choice, 0)
    votes_db["counts"][choice] += 1
    try:
        save_db()
    except Exception:
        logger.exception("save_db error")
    entry = {"poll":POLL_ID,"choice":choice,"timestamp":ts,"id":file_hash,
             "identity":identity,"file_hash":file_hash,"filename":f"{file_hash}.txt"}
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
    counts, anomalies = rebuild_counts_and_anomalies()
    total = sum(counts.values())
    return render_template("result.html", votes=dict(counts), anomalies=anomalies, total=total)

@app.route("/receipt")
def receipt():
    entry_hash = request.args.get("h","")
    idx = int(request.args.get("i",0))
    state = _load_log_state()
    return render_template("receipt.html", entry_hash=entry_hash, index=idx, head=state.get("head"), poll_id=POLL_ID)

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
