# whatsapp_backend.py
import os
import json
import hmac
import hashlib
import asyncio
import base64
from datetime import datetime
from quart import Quart, request, jsonify, Response
import requests
import firebase_admin
from firebase_admin import credentials, db

# load env
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
APP_SECRET = os.getenv("WHATSAPP_APP_SECRET")
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "verify_token")
FIREBASE_CRED_B64 = os.getenv("FIREBASE_CRED_B64")
FIREBASE_RDB_URL = "https://legendry1-79529-default-rtdb.asia-southeast1.firebasedatabase.app/"
GRAPH_API_VERSION = os.getenv("GRAPH_API_VERSION", "v23.0")

if not (WHATSAPP_TOKEN and PHONE_NUMBER_ID and FIREBASE_CRED_B64 and FIREBASE_RDB_URL):
    raise RuntimeError("Set WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID, FIREBASE_CRED_B64, FIREBASE_RDB_URL")

# ----- Decode Firebase JSON from base64 -----
cred_json = base64.b64decode(FIREBASE_CRED_B64).decode("utf-8")
cred_dict = json.loads(cred_json)
cred = credentials.Certificate(cred_dict)

# Initialize Firebase Admin
firebase_admin.initialize_app(cred, {
    "databaseURL": FIREBASE_RDB_URL
})
rdb_root = db.reference("/")  # root

app = Quart(__name__)

GRAPH_BASE = f"https://graph.facebook.com/{GRAPH_API_VERSION}/{PHONE_NUMBER_ID}"

# ----- Helper: send message via WhatsApp Cloud API -----
def send_whatsapp_text(recipient_number: str, text: str):
    url = f"{GRAPH_BASE}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": recipient_number,
        "type": "text",
        "text": {"body": text}
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()

# ----- Endpoint: Send message (called by frontend) -----
@app.route("/send_message", methods=["POST"])
async def send_message():
    data = await request.get_json()
    to = data.get("to")
    text = data.get("text")
    if not to or not text:
        return jsonify({"error": "missing to or text"}), 400

    try:
        api_resp = send_whatsapp_text(to, text)
    except Exception as e:
        return jsonify({"error": "failed to send", "detail": str(e)}), 500

    msg_ref = rdb_root.child("messages").child("outgoing").push()
    msg_ref.set({
        "to": to,
        "text": text,
        "status": "sent_to_api",
        "api_response": api_resp,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    return jsonify({"ok": True, "api": api_resp})

# ----- Endpoint: WhatsApp Webhook -----
@app.route("/webhook", methods=["GET", "POST"])
async def webhook():
    if request.method == "GET":
        args = request.args
        mode = args.get("hub.mode")
        challenge = args.get("hub.challenge")
        token = args.get("hub.verify_token")
        if mode == "subscribe" and token == VERIFY_TOKEN:
            return Response(challenge, status=200)
        return jsonify({"status": "failed", "message": "verification failed"}), 403

    body_bytes = await request.data
    sig_header = request.headers.get("X-Hub-Signature-256") or request.headers.get("x-hub-signature-256")

    if APP_SECRET and sig_header:
        try:
            _, signature = sig_header.split("=", 1)
        except Exception:
            return jsonify({"error": "invalid signature header"}), 400
        digest = hmac.new(APP_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, digest):
            return jsonify({"error": "signature mismatch"}), 403

    payload = json.loads(body_bytes.decode("utf-8"))

    try:
        raw_ref = rdb_root.child("messages").child("incoming").push()
        raw_ref.set({
            "raw": payload,
            "received_at": datetime.utcnow().isoformat() + "Z"
        })

        entries = payload.get("entry", [])
        for entry in entries:
            changes = entry.get("changes", [])
            for ch in changes:
                value = ch.get("value", {})
                messages = value.get("messages", [])
                for m in messages:
                    from_num = m.get("from")
                    msg_id = m.get("id")
                    text_obj = m.get("text", {})
                    body = text_obj.get("body")
                    simple_ref = rdb_root.child("messages").child("incoming_simple").push()
                    simple_ref.set({
                        "from": from_num,
                        "id": msg_id,
                        "text": body,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    })
    except Exception as e:
        rdb_root.child("logs").push().set({"error": str(e), "payload": payload})
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True})

# ----- SSE: stream new messages -----
@app.route("/events")
async def events():
    async def event_stream():
        last_seen = set()
        try:
            existing = rdb_root.child("messages").child("incoming_simple").get() or {}
            last_seen.update(existing.keys() if isinstance(existing, dict) else [])
        except Exception:
            pass

        while True:
            try:
                snapshot = rdb_root.child("messages").child("incoming_simple").get() or {}
                if isinstance(snapshot, dict):
                    for key, val in snapshot.items():
                        if key not in last_seen:
                            last_seen.add(key)
                            d = json.dumps({"key": key, "data": val})
                            yield f"data: {d}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            await asyncio.sleep(2.0)
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
