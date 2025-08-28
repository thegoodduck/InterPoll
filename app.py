import os
import subprocess
import hashlib
from datetime import datetime, timezone
import json
import logging
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, abort, session
from authlib.integrations.flask_client import OAuth

# --- File/dir constants ---
VOTE_DIR = "votes"
DB_FILE = "votes_db.json"
LOG_FILE = "votes_log.jsonl"
LOG_STATE = "log_state.json"
CHAIN_HEAD_FILE = "chain_head.txt"

app = Flask(__name__)
app.secret_key = "supersecret"
oauth = OAuth(app)

# --- Google OAuth (proper OIDC) ---
oauth.register(
    name='google',
    client_id='478090540512-rtc3help4la8vj941ucrsodn4e5h0fm8.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- GitHub OAuth ---
oauth.register(
    name='github',
    client_id='Iv1.1234567890abcdef',  # replace with your GitHub client ID
    client_secret='abcdef1234567890abcdef1234567890abcdef12',  # replace with your GitHub secret
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'read:user user:email'}
)

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
                except:
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
            anomalies.append({"type": "missing_file", "filename": filename, "entry_hash": rec.get("entry_hash")})
            continue
        try:
            with open(path, "rb") as vf:
                data = vf.read()
            actual = hashlib.sha256(data).hexdigest()
            if file_hash and actual != file_hash:
                anomalies.append({"type": "hash_mismatch", "filename": filename, "expected": file_hash, "actual": actual, "entry_hash": rec.get("entry_hash")})
        except Exception as e:
            anomalies.append({"type": "read_error", "filename": filename, "error": str(e), "entry_hash": rec.get("entry_hash")})
    return counts, anomalies

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
    user = oauth.google.userinfo()  # Fetch from Google's OpenID UserInfo endpoint
    if user:
        user["_provider"] = "google"
        session["user"] = user
    return redirect(url_for("index"))

@app.route("/login/github")
def login_github():
    redirect_uri = url_for("auth_github", _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route("/auth/github")
def auth_github():
    oauth.github.authorize_access_token()
    resp = oauth.github.get("user")
    user = resp.json() if resp.ok else {}
    user["_provider"] = "github"
    session["user"] = user
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# --- Voting route ---
@app.route("/vote", methods=["POST"])
def vote():
    vote_choice = request.form.get("vote")
    if vote_choice not in POLL_OPTIONS:
        return "Invalid vote option!", 400

    voted_cookie_key = f"voted_{POLL_ID}"
    user = session.get("user") or {}
    user_id = user.get("sub") or user.get("id")
    provider = user.get("_provider")
    identity = f"{provider}:{user_id}" if provider and user_id else ""

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

    votes_db["votes"][file_hash] = {"choice": vote_choice, "timestamp": timestamp, "ip": client_ip, "ua": user_agent, "identity": identity}
    votes_db["counts"][vote_choice] += 1
    save_db()

    log_entry = {
        "poll": POLL_ID,
        "choice": vote_choice,
        "timestamp": timestamp,
        "id": file_hash,
        "ip": client_ip,
        "ua": user_agent,
        "identity": identity,
        "file_hash": file_hash,
        "filename": f"{file_hash}.txt"
    }
    entry_hash, head, idx = append_transparency_log(log_entry)
    resp = make_response(redirect(url_for("receipt", h=entry_hash, i=idx, ts=timestamp, fi=file_hash)))
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
    try:
        idx = int(request.args.get("i"))
    except Exception:
        return abort(400)
    state = _load_log_state()
    return render_template("receipt.html", entry_hash=entry_hash, index=idx, head=state.get("head"), poll_id=POLL_ID)

if __name__ == "__main__":
    app.run(debug=True)
