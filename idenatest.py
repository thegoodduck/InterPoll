from flask import Flask, request, redirect, session, url_for, jsonify
import uuid
import secrets
import requests
from eth_account.messages import encode_defunct
from eth_account import Account

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

# In-memory stores for demo (use Redis or DB in production)
idena_sessions = {}
used_nonces = set()

# Configuration
IDENA_VERIFY_METHOD = "local"  # "local" or "remote"
IDENA_VERIFY_URL = None  # Optional remote verification endpoint

def verify_eth_signature_local(address, message, signature):
    try:
        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == address.lower()
    except Exception:
        return False

def verify_idena_signature(address, message, signature):
    if IDENA_VERIFY_METHOD == "remote" and IDENA_VERIFY_URL:
        try:
            r = requests.post(IDENA_VERIFY_URL, json={"address": address, "message": message, "signature": signature}, timeout=10)
            if not r.ok:
                return False
            data = r.json()
            return any(data.get(k) for k in ("result","success","ok"))
        except Exception:
            return False
    else:
        return verify_eth_signature_local(address, message, signature)

@app.route('/auth/v1/start-session', methods=['POST'])
def start_session():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    address = (data.get("address") or "").strip().lower()
    if not token or not address:
        return jsonify(success=False, error="Missing token or address"), 400

    nonce = f"signin-{uuid.uuid4()}"
    idena_sessions[token] = {"nonce": nonce, "address": address, "authenticated": False}
    return jsonify(success=True, data={"nonce": nonce})

@app.route('/auth/v1/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    signature = data.get("signature")
    if not token or not signature:
        return jsonify(success=False, error="Missing token or signature"), 400

    sess = idena_sessions.get(token)
    if not sess:
        return jsonify(success=False, error="Unknown session"), 400

    nonce = sess["nonce"]
    address = sess["address"]
    if nonce in used_nonces:
        return jsonify(success=True, data={"authenticated": False})

    auth_ok = verify_idena_signature(address, nonce, signature)
    if auth_ok:
        sess["authenticated"] = True
        used_nonces.add(nonce)
        return jsonify(success=True, data={"authenticated": True})
    else:
        return jsonify(success=True, data={"authenticated": False})

@app.route('/auth/v1/callback')
def callback():
    token = request.args.get("token")
    sess = idena_sessions.get(token)
    if sess and sess.get("authenticated"):
        session["user"] = {"_provider": "idena", "address": sess["address"]}
        return redirect(url_for("index"))
    return "Login failed", 403

@app.route('/')
def index():
    user = session.get("user")
    if user:
        return f"Hello, Idena user {user.get('address')}!"
    # Build the sign-in URL per docs:contentReference[oaicite:1]{index=1}
    token = secrets.token_urlsafe(16)
    app_url = url_for("callback", _external=True)
    signin_url = (
        "https://app.idena.io/dna/signin?"
        f"token={token}&"
        f"callback_url={app_url}&"
        f"nonce_endpoint={url_for('start_session', _external=True)}&"
        f"authentication_endpoint={url_for('authenticate', _external=True)}&"
        f"favicon_url={url_for('static', filename='favicon.ico', _external=True)}"
    )
    return f'<a href="{signin_url}">Sign in with Idena</a>'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
