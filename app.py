from flask import Flask, render_template, request, redirect, url_for
import os
import subprocess
import hashlib
from datetime import datetime, timezone
import json
from bitcoinlib.keys import Address

app = Flask(__name__)
VOTE_DIR = "votes"
DB_FILE = "votes_db.json"
os.makedirs(VOTE_DIR, exist_ok=True)

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
    subprocess.run(["ots", "stamp", file_path], check=True)

def verify_signature(address, message, signature):
    """
    Verify Bitcoin message signature.
    """
    try:
        addr = Address.import_address(address)
        return addr.verify(message, signature)
    except Exception:
        return False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        address = request.form.get("address").strip()
        signature = request.form.get("signature").strip()
        vote = request.form.get("vote").strip()

        if vote not in POLL_OPTIONS:
            return "Invalid vote option!", 400

        # Prevent double voting
        if address in votes_db["votes"]:
            return "This Bitcoin address has already voted!", 403

        # Build message
        message = f"{POLL_ID}|{vote}"
        if not verify_signature(address, message, signature):
            return "Invalid signature!", 400

        # Save vote with timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        vote_data = f"{vote}|{address}|{timestamp}"
        file_name = f"{VOTE_DIR}/{hash_vote(vote_data)}.txt"

        with open(file_name, "w") as f:
            f.write(vote_data)

        timestamp_vote(file_name)

        # Record in DB
        votes_db["votes"][address] = {"choice": vote, "timestamp": timestamp}
        votes_db["counts"][vote] += 1
        save_db()

        return redirect(url_for("results"))

    return render_template("index.html", question=POLL_QUESTION, options=POLL_OPTIONS)

@app.route("/results")
def results():
    return render_template("result.html", votes=votes_db["counts"])

if __name__ == "__main__":
    app.run(debug=True)
