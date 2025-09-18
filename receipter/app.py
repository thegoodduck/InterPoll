from flask import Flask, request, jsonify, render_template, make_response
import os
import json
from datetime import datetime, timezone
import tempfile
import urllib.request
import logging

app = Flask(__name__)
STORAGE = os.environ.get("RECEIPTER_STORE", "receipts.json")
AUTH_BASE = os.environ.get("AUTH_BASE", "http://localhost:5000")  # base URL of main poll server
AUTH_CHAIN_HEAD = f"{AUTH_BASE.rstrip('/')}/chain-head"
AUTH_LOG = f"{AUTH_BASE.rstrip('/')}/log"
MAX_PAYLOAD = int(os.environ.get("MAX_RECEIPT_BYTES", "4096"))

def _load_existing():
    if os.path.exists(STORAGE):
        try:
            with open(STORAGE, 'r') as f:
                return json.load(f)
        except Exception:
            logging.warning("Could not parse existing receipts file; starting fresh")
            return []
    return []

receipts = _load_existing()

def _atomic_save(path: str, obj):
    fd, tmp = tempfile.mkstemp(prefix="receipts_", suffix=".tmp")
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def save():
    _atomic_save(STORAGE, receipts)

def _fetch_chain_head():
    try:
        with urllib.request.urlopen(AUTH_CHAIN_HEAD, timeout=3) as r:
            data = r.read().decode('utf-8', errors='ignore')
        # Expect a simple text file with lines like head=...
        head_line = next((ln for ln in data.splitlines() if ln.startswith('head=')), '')
        return head_line.split('=',1)[1].strip() if '=' in head_line else ''
    except Exception:
        return ''

def _basic_validate(receipt: dict) -> tuple[bool, str]:
    required = {"poll_id", "entry_hash", "index", "chain_head"}
    if not required.issubset(receipt.keys()):
        return False, "missing fields"
    eh = receipt.get("entry_hash", "")
    if not isinstance(eh, str) or len(eh) != 64 or any(c not in '0123456789abcdef' for c in eh.lower()):
        return False, "bad entry_hash"
    try:
        int(receipt.get("index"))
    except Exception:
        return False, "bad index"
    return True, ""

def _verify_against_chain(receipt: dict) -> bool:
    # Lightweight check: compare provided chain_head with current authoritative chain head.
    # Stronger verification would fetch /log and recompute head across entries.
    authoritative = _fetch_chain_head()
    if not authoritative:
        return False  # cannot verify now
    return authoritative == receipt.get("chain_head")

@app.route('/')
def home():
    return render_template('home.html', count=len(receipts), receipts=receipts[-50:][::-1])

def _corsify(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    resp.headers['Access-Control-Max-Age'] = '3600'
    return resp

@app.route('/ingest', methods=['POST', 'OPTIONS'])
def ingest():
    # Preflight
    if request.method == 'OPTIONS':
        return _corsify(make_response('', 204))

    if request.content_length and request.content_length > MAX_PAYLOAD:
        return _corsify(jsonify({"ok": False, "error": "payload too large"})), 413
    try:
        data = request.get_json(force=True)
    except Exception:
        return _corsify(jsonify({"ok": False, "error": "invalid json"})), 400

    ok, err = _basic_validate(data)
    if not ok:
        return _corsify(jsonify({"ok": False, "error": err})), 400

    eh = data["entry_hash"]
    # Duplicate check
    if any(r.get('entry_hash') == eh for r in receipts):
        return _corsify(jsonify({"ok": True, "status": "duplicate"}))

    # Optional user scoping
    uid = data.get("user_id")
    if uid is not None and not isinstance(uid, str):
        return _corsify(jsonify({"ok": False, "error": "bad user_id"})), 400
    data["received_at"] = datetime.now(timezone.utc).isoformat()
    data["verified"] = _verify_against_chain(data)
    receipts.append(data)
    save()
    return _corsify(jsonify({"ok": True, "verified": data["verified"]}))

@app.route('/mine')
def mine():
    uid = (request.args.get('uid') or '').strip()
    if not uid:
        # no uid -> show empty
        return render_template('home.html', count=0, receipts=[])
    mine = [r for r in receipts if (r.get('user_id') or '') == uid]
    return render_template('home.html', count=len(mine), receipts=mine[-50:][::-1])

if __name__ == '__main__':
    app.run(port=7001, debug=True)
