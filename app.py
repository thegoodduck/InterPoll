from flask import Flask, render_template, request, redirect, url_for, make_response
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

        # Set cookie to block repeat voting from the same browser
        resp = make_response(redirect(url_for("results")))
        # 30 days expiry
        resp.set_cookie(voted_cookie_key, "1", max_age=30 * 24 * 3600, samesite="Lax")
        return resp

    # GET
    voted = request.cookies.get(f"voted_{POLL_ID}") is not None
    return render_template("index.html", question=POLL_QUESTION, options=POLL_OPTIONS, voted=voted)

@app.route("/results")
def results():
    return render_template("result.html", votes=votes_db["counts"])

if __name__ == "__main__":
    app.run(debug=True)
