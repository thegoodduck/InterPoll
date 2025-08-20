from flask import Flask, request, jsonify, render_template
import os
import json
from datetime import datetime, timezone

app = Flask(__name__)
STORAGE = os.environ.get("RECEIPTER_STORE", "receipts.json")

if os.path.exists(STORAGE):
    with open(STORAGE, 'r') as f:
        try:
            receipts = json.load(f)
        except Exception:
            receipts = []
else:
    receipts = []

def save():
    with open(STORAGE, 'w') as f:
        json.dump(receipts, f, indent=2)

@app.route('/')
def home():
    return render_template('home.html', count=len(receipts), receipts=receipts[-50:][::-1])

@app.route('/ingest', methods=['POST'])
def ingest():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "invalid json"}), 400
    required = {"poll_id", "entry_hash", "index", "chain_head"}
    if not required.issubset(data.keys()):
        return jsonify({"ok": False, "error": "missing fields"}), 400
    data["received_at"] = datetime.now(timezone.utc).isoformat()
    # dedupe on entry_hash
    if any(r.get('entry_hash') == data['entry_hash'] for r in receipts):
        return jsonify({"ok": True, "status": "duplicate"})
    receipts.append(data)
    save()
    return jsonify({"ok": True})

if __name__ == '__main__':
    app.run(port=7001, debug=True)
