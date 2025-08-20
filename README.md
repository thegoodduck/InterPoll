# InterPoll (MVP)

A super-simple Flask poll app. Users can vote in one click—no Bitcoin wallet or signatures needed. Votes are stored as hashed files and (optionally) timestamped via OpenTimestamps.

## Run locally

1) Create and activate a Python venv (recommended)
2) Install deps
3) Start the server

```sh
# from the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt
export FLASK_APP=app.py
export SECRET_KEY="change-me"
flask run --port 5000
```

Open http://127.0.0.1:5000

## Notes
- MVP enforces one vote per browser using a cookie for 30 days.
- Each vote is written to `votes/<sha256>.txt` with the choice, timestamp, and client IP.
- If the `ots` CLI is available, the file is timestamped (failure is non-fatal).

Optional: Install OpenTimestamps CLI
```sh
pip install opentimestamps-client
# or OS package if available
```

## Future hardening ideas
- Stronger uniqueness: email/OTP, OAuth, or allow privacy-preserving proofs.
- Rate limits and basic bot protection.
- Admin page to reset poll / export results CSV.
- Server-side session store or signed tokens for integrity.
