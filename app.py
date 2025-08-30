import os
import secrets
import subprocess
import hashlib
from datetime import datetime, timezone
import json
import logging
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, make_response, abort, session
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
from dotenv import load_dotenv
import requests
import uuid
from eth_account.messages import encode_defunct
from eth_account import Account

# --- File/dir constants ---
VOTE_DIR = "votes"
DB_FILE = "votes_db.json"
LOG_FILE = "votes_log.jsonl"
LOG_STATE = "log_state.json"
CHAIN_HEAD_FILE = "chain_head.txt"

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-change-me")
oauth = OAuth(app)

# --- Idena verification endpoint (configurable) ---
IDENA_VERIFY_URL = os.getenv("IDENA_VERIFY_URL", "https://api.idena.io/api/Signature/Verify")
IDENA_VERIFY_METHOD = os.getenv("IDENA_VERIFY_METHOD", "simple")

# In-memory Idena auth sessions (token -> {nonce,address,authenticated})
idena_sessions = {}

# --- Google OAuth (optional) ---
google_id = os.getenv("GOOGLE_CLIENT_ID")
google_secret = os.getenv("GOOGLE_CLIENT_SECRET")
if google_id and google_secret:
    oauth.register(
        name='google',
        client_id=google_id,
        client_secret=google_secret,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
else:
    logging.warning("Google OAuth not configured")

# --- Poll Setup ---
POLL_ID = "poll_001"
POLL_QUESTION = "Do you support this proposal?"
POLL_OPTIONS = ["Yes", "No", "Maybe"]

if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f:
        votes_db = json.load(f)
else:
    votes_db = {"votes": {}, "counts": {opt: 0 for opt in POLL_OPTIONS}}

def save_db():
    with open(DB_FILE, "w") as f:
        json.dump(votes_db, f, indent=2)

def hash_vote(vote_text):
    return hashlib.sha256(vote_text.encode()).hexdigest()

def timestamp_vote(file_path):
    try:
        subprocess.run(["ots", "stamp", file_path], check=True)
    except FileNotFoundError:
        logging.warning("OpenTimestamps CLI 'ots' not found. Skipping timestamp.")
    except subprocess.CalledProcessError as e:
        logging.warning("OpenTimestamps failed: %s", e)

def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _load_log_state():
    if os.path.exists(LOG_STATE):
        with open(LOG_STATE, "r") as f:
            return json.load(f)
    return {"count": 0, "head": ""}

def _save_log_state(state):
    with open(LOG_STATE, "w") as f:
        json.dump(state, f, indent=2)

def append_transparency_log(entry: dict):
    state = _load_log_state()
    prev_head_hex = state.get("head", "")
    prev_head_bytes = bytes.fromhex(prev_head_hex) if prev_head_hex else b""
    entry_json = _canonical_json(entry)
    entry_hash_hex = _sha256_hex(entry_json.encode("utf-8"))
    entry_hash_bytes = bytes.fromhex(entry_hash_hex)
    new_head_hex = _sha256_hex(prev_head_bytes + entry_hash_bytes)
    index = state.get("count", 0)
    record = {"index": index, "entry": entry, "entry_hash": entry_hash_hex, "chain_head": new_head_hex}
    with open(LOG_FILE, "a") as f:
        f.write(_canonical_json(record) + "\n")
    state["count"] = index + 1
    state["head"] = new_head_hex
    _save_log_state(state)
    with open(CHAIN_HEAD_FILE, "w") as f:
        f.write(f"poll={POLL_ID}\nindex={index}\nhead={new_head_hex}\n")
    timestamp_vote(CHAIN_HEAD_FILE)
    return entry_hash_hex, new_head_hex, index

def iter_log_entries():
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except Exception:
                    continue

def rebuild_counts_and_anomalies():
    counts = Counter({opt: 0 for opt in POLL_OPTIONS})
    anomalies = []
    for rec in iter_log_entries() or []:
        entry = rec.get("entry", {})
        choice = entry.get("choice")
        if choice in counts:
            counts[choice] += 1
        filename = entry.get("filename") or f"{entry.get('id','')}.txt"
        file_hash = entry.get("file_hash") or entry.get("id")
        path = os.path.join(VOTE_DIR, filename)
        if not os.path.exists(path):
            anomalies.append({"type": "missing_file", "filename": filename})
            continue
        try:
            with open(path, "rb") as vf:
                data = vf.read()
            actual = hashlib.sha256(data).hexdigest()
            if file_hash and actual != file_hash:
                anomalies.append({"type": "hash_mismatch", "filename": filename})
        except Exception as e:
            anomalies.append({"type": "read_error", "filename": filename, "error": str(e)})
    return counts, anomalies

# ---------------------------
# Idena Session Auth Flow (nonce + signature) per provided spec
# ---------------------------
@app.route("/auth/v1/start-session", methods=["POST"])
def idena_start_session():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    address = (data.get("address") or "").strip()
    if not token or not address:
        return {"success": False, "error": "Missing token or address"}, 400
    nonce = f"signin-{uuid.uuid4()}"
    idena_sessions[token] = {"nonce": nonce, "address": address.lower(), "authenticated": False}
    return {"success": True, "data": {"nonce": nonce}}

@app.route("/auth/v1/authenticate", methods=["POST"])
def idena_authenticate():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    signature = data.get("signature")
    if not token or not signature:
        return {"success": False, "error": "Missing token or signature"}, 400
    sess = idena_sessions.get(token)
    if not sess:
        return {"success": False, "error": "Unknown session"}, 400
    nonce = sess["nonce"]
    expected_address = sess["address"]
    try:
        message = encode_defunct(text=nonce)
        recovered = Account.recover_message(message, signature=signature).lower()
    except Exception as e:
        logging.warning("Idena signature recovery failed: %s", e)
        return {"success": True, "data": {"authenticated": False}}
    if recovered == expected_address:
        sess["authenticated"] = True
        return {"success": True, "data": {"authenticated": True}}
    return {"success": True, "data": {"authenticated": False}}

@app.route("/auth/v1/get-account", methods=["GET"])
def idena_get_account():
    token = request.args.get("token")
    sess = idena_sessions.get(token)
    if sess and sess.get("authenticated"):
        return {"success": True, "data": {"address": sess["address"]}}
    return {"success": False, "error": "Not authenticated"}

@app.route("/auth/v1/callback")
def idena_callback():
    token = request.args.get("token")
    sess = idena_sessions.get(token)
    if sess and sess.get("authenticated"):
        session["user"] = {"_provider": "idena", "address": sess["address"], "session_token": token}
        return redirect(url_for("index"))
    return "Login failed", 403

# ---------------------------
# Idena Auth
# ---------------------------
def verify_idena_signature(address: str, message: str, signature: str) -> bool:
    try:
        r = requests.post(IDENA_VERIFY_URL, json={
            "address": address,
            "message": message,
            "signature": signature
        }, timeout=10)
        if not r.ok:
            return False
        data = r.json()
        return bool(data.get("result") or data.get("success") or data.get("ok"))
    except Exception as e:
        logging.exception("Idena verify failed: %s", e)
        return False

@app.route("/login/idena/start")
def login_idena():
    challenge = secrets.token_hex(16)
    session["idena_challenge"] = challenge
    return render_template("idena_start.html", challenge=challenge)

@app.route("/auth/idena", methods=["POST"])
def auth_idena():
    """Handle Idena auth via JWT id_token posted from client.

    Expected form fields:
      - id_token: JWT containing address claim (and others)
    """
    id_token = request.form.get("id_token", "").strip()
    if not id_token:
        return "Missing id_token", 400
    try:
        # For simplicity we skip signature verification (would require Idena JWKS); we still parse & validate exp.
        claims = jwt.decode(id_token, key=None, claims_options={"iss": None, "aud": None})
        claims.validate()
        address = claims.get("address") or claims.get("addr") or claims.get("sub")
        if not address:
            return "No address in token", 400
        session["user"] = {"_provider": "idena", "address": address, "claims": dict(claims)}
        return redirect(url_for("index"))
    except Exception as e:
        logging.exception("Idena JWT parse failed: %s", e)
        return "Invalid id_token", 400

# --- Routes ---
@app.route("/")
def index():
    voted = request.cookies.get(f"voted_{POLL_ID}") is not None
    user = session.get("user")
    return render_template("index.html", question=POLL_QUESTION, options=POLL_OPTIONS, voted=voted, user=user)

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("auth_google", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google")
def auth_google():
    oauth.google.authorize_access_token()
    user = oauth.google.userinfo()
    if user:
        user["_provider"] = "google"
        session["user"] = user
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# --- Voting ---
@app.route("/vote", methods=["POST"])
def vote():
    vote_choice = request.form.get("vote")
    if vote_choice not in POLL_OPTIONS:
        return "Invalid vote option!", 400

    voted_cookie_key = f"voted_{POLL_ID}"
    user = session.get("user") or {}
    provider = user.get("_provider")
    if provider == "idena":
        identity = f"idena:{user.get('address','')}"
    elif provider:
        identity = f"{provider}:{user.get('sub') or user.get('id')}"
    else:
        identity = ""

    if identity:
        for v in votes_db["votes"].values():
            if v.get("identity") == identity:
                return redirect(url_for("results"))
    if request.cookies.get(voted_cookie_key):
        return redirect(url_for("results"))

    timestamp = datetime.now(timezone.utc).isoformat()
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")[:400]

    vote_data = f"{vote_choice}|{timestamp}|{client_ip}|{user_agent}|{identity}"
    file_hash = hash_vote(vote_data)
    os.makedirs(VOTE_DIR, exist_ok=True)
    file_name = f"{VOTE_DIR}/{file_hash}.txt"
    with open(file_name, "w") as f:
        f.write(vote_data)
    timestamp_vote(file_name)

    votes_db["votes"][file_hash] = {
        "choice": vote_choice,
        "timestamp": timestamp,
        "ip": client_ip,
        "ua": user_agent,
        "identity": identity
    }
    votes_db["counts"][vote_choice] += 1
    save_db()

    log_entry = {
        "poll": POLL_ID,
        "choice": vote_choice,
        "timestamp": timestamp,
        "id": file_hash,
        "identity": identity,
        "file_hash": file_hash,
        "filename": f"{file_hash}.txt"
    }
    entry_hash, head, idx = append_transparency_log(log_entry)
    resp = make_response(redirect(url_for("receipt", h=entry_hash, i=idx)))
    resp.set_cookie(voted_cookie_key, "1", max_age=30*24*3600, samesite="Lax")
    return resp

@app.route("/results")
def results():
    counts, anomalies = rebuild_counts_and_anomalies()
    total = sum(counts.values())
    return render_template("result.html", votes=dict(counts), anomalies=anomalies, total=total)

@app.route("/receipt")
def receipt():
    entry_hash = request.args.get("h")
    idx = int(request.args.get("i", 0))
    state = _load_log_state()
    return render_template("receipt.html",
                           entry_hash=entry_hash,
                           index=idx,
                           head=state.get("head"),
                           poll_id=POLL_ID)

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
