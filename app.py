from flask import Flask, render_template, request, redirect, url_for, make_response, send_file, abort
import os
import subprocess
import hashlib
from datetime import datetime, timezone
import json
import logging

app = Flask(__name__)
VOTE_DIR = "votes"
DB_FILE = "votes_db.json"
os.makedirs(VOTE_DIR, exist_ok=True)

# Secret key for sessions/cookies (override in env for production)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["RECEIPTER_URL"] = os.environ.get("RECEIPTER_URL", "http://localhost:7001/ingest")
app.config["RECEIPTER_PAGE_URL"] = os.environ.get("RECEIPTER_PAGE_URL", "http://localhost:7001/")

# Transparency log files (tamper-evident via hash chaining)
LOG_FILE = "votes_log.jsonl"  # append-only JSON Lines
LOG_STATE = "log_state.json"  # stores chain head and count
CHAIN_HEAD_FILE = "chain_head.txt"  # contains latest chain head info for OTS

# Define your poll
POLL_ID = "poll_001"
POLL_QUESTION = "Do you support this proposal?"
POLL_OPTIONS = ["Yes", "No", "Maybe"]

# Load vote database
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
    """
    Attempt to timestamp the file using OpenTimestamps CLI if available.
    Fails gracefully if CLI is missing or command fails.
    """
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
    """
    Append an entry to the transparency log implementing a simple hash chain.
    new_head = sha256(prev_head_bytes || entry_hash_bytes)
    Returns (entry_hash_hex, new_head_hex, index)
    """
    state = _load_log_state()
    prev_head_hex = state.get("head", "")
    prev_head_bytes = bytes.fromhex(prev_head_hex) if prev_head_hex else b""

    entry_json = _canonical_json(entry)
    entry_hash_hex = _sha256_hex(entry_json.encode("utf-8"))
    entry_hash_bytes = bytes.fromhex(entry_hash_hex)

    new_head_hex = _sha256_hex(prev_head_bytes + entry_hash_bytes)
    index = state.get("count", 0)

    # Append to JSONL with metadata
    record = {
        "index": index,
        "entry": entry,
        "entry_hash": entry_hash_hex,
        "chain_head": new_head_hex,
    }
    with open(LOG_FILE, "a") as f:
        f.write(_canonical_json(record) + "\n")

    # Update state
    state["count"] = index + 1
    state["head"] = new_head_hex
    _save_log_state(state)

    # Write chain head file for external timestamping
    with open(CHAIN_HEAD_FILE, "w") as f:
        f.write(f"poll={POLL_ID}\nindex={index}\nhead={new_head_hex}\n")
    timestamp_vote(CHAIN_HEAD_FILE)

    return entry_hash_hex, new_head_hex, index


def _git_anchor(index: int, head_hex: str):
    """Optionally commit and push log updates if this directory is a git repo.
    Safe no-op if git is not available or repo/remote not configured.
    """
    try:
        # Ensure we're in a git repo
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "add", LOG_FILE, LOG_STATE, CHAIN_HEAD_FILE], check=True)
        subprocess.run(["git", "commit", "-m", f"log: index {index} head {head_hex}"], check=True)
        # Push if a default remote exists; ignore failures
        subprocess.run(["git", "push"], check=True)
    except Exception as e:
        logging.debug("git anchor skipped: %s", e)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        vote = (request.form.get("vote") or "").strip()

        if vote not in POLL_OPTIONS:
            return "Invalid vote option!", 400

        # Prevent double voting (MVP): simple cookie-based check
        voted_cookie_key = f"voted_{POLL_ID}"
        if request.cookies.get(voted_cookie_key):
            return redirect(url_for("results"))

        # Save vote with timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        vote_data = f"{vote}|{timestamp}|{client_ip}"
        file_hash = hash_vote(vote_data)
        file_name = f"{VOTE_DIR}/{file_hash}.txt"

        with open(file_name, "w") as f:
            f.write(vote_data)

        timestamp_vote(file_name)

        # Record in DB
        votes_db["votes"][file_hash] = {"choice": vote, "timestamp": timestamp, "ip": client_ip}
        votes_db["counts"][vote] += 1
        save_db()

        # Append to transparency log (tamper-evident)
        log_entry = {"poll": POLL_ID, "choice": vote, "timestamp": timestamp, "id": file_hash, "ip": client_ip}
        entry_hash_hex, head_hex, index = append_transparency_log(log_entry)
        _git_anchor(index, head_hex)

        # Set cookie to block repeat voting from the same browser and redirect to receipt
        resp = make_response(redirect(url_for("receipt", h=entry_hash_hex, i=index, ts=timestamp, fi=file_hash)))
        # 30 days expiry
        resp.set_cookie(voted_cookie_key, "1", max_age=30 * 24 * 3600, samesite="Lax")
        return resp

    # GET
    voted = request.cookies.get(f"voted_{POLL_ID}") is not None
    return render_template("index.html", question=POLL_QUESTION, options=POLL_OPTIONS, voted=voted)

@app.route("/results")
def results():
    # Derive results from the append-only log to avoid tamper-prone DB states
    counts = {opt: 0 for opt in POLL_OPTIONS}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    entry = rec.get("entry", {})
                    choice = entry.get("choice")
                    if choice in counts:
                        counts[choice] += 1
                except Exception:
                    # Skip malformed lines
                    continue
    else:
        # Fallback to in-memory counts if log missing
        counts = dict(votes_db.get("counts", {}))
        for opt in POLL_OPTIONS:
            counts.setdefault(opt, 0)
    return render_template("result.html", votes=counts)


@app.route("/receipt")
def receipt():
    entry_hash = request.args.get("h")
    try:
        index = int(request.args.get("i"))
    except (TypeError, ValueError):
        return abort(400)
    state = _load_log_state()
    head = state.get("head", "")
    ts = request.args.get("ts") or ""
    fi = request.args.get("fi") or ""
    receipter_url = app.config.get("RECEIPTER_URL")
    receipter_page_url = app.config.get("RECEIPTER_PAGE_URL")
    return render_template("receipt.html", entry_hash=entry_hash, index=index, head=head, poll_id=POLL_ID, ts=ts, file_id=fi, receipter_url=receipter_url, receipter_page_url=receipter_page_url)


@app.route("/log")
def download_log():
    if not os.path.exists(LOG_FILE):
        return abort(404)
    return send_file(LOG_FILE, mimetype="text/plain", as_attachment=True, download_name="votes_log.jsonl")


@app.route("/chain-head")
def download_chain_head():
    if not os.path.exists(CHAIN_HEAD_FILE):
        return abort(404)
    return send_file(CHAIN_HEAD_FILE, mimetype="text/plain", as_attachment=True, download_name="chain_head.txt")

if __name__ == "__main__":
    app.run(debug=True)
