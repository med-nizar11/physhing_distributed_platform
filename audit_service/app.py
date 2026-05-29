from flask import Flask, request, jsonify
from datetime import datetime
import json
import os

app = Flask(__name__)

LOG_FILE = "audit.log"


def mask_token(value):
    """
    Masque les tokens pour éviter de les écrire entièrement dans les logs.
    """
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def write_audit_log(event_type, username, status, details=None):
    """
    Écrit un événement sous format JSON dans audit.log.
    """

    if details is None:
        details = {}

    # Sécurité : ne pas journaliser les tokens complets
    if "token" in details:
        details["token"] = mask_token(details["token"])

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "username": username,
        "status": status,
        "details": details
    }

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "AuditService",
        "status": "running"
    }), 200


@app.route("/audit", methods=["POST"])
def audit():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    event_type = str(data.get("event_type", "UNKNOWN_EVENT")).strip()
    username = str(data.get("username", "anonymous")).strip()
    status = str(data.get("status", "unknown")).strip()
    details = data.get("details", {})

    if not isinstance(details, dict):
        details = {"message": "Invalid details format"}

    if len(event_type) > 100:
        event_type = "INVALID_EVENT_TYPE"

    if len(username) > 50:
        username = "invalid_username"

    write_audit_log(event_type, username, status, details)

    return jsonify({
        "message": "Audit event saved"
    }), 201


@app.route("/logs", methods=["GET"])
def get_logs():
    """
    Route utile pour la démonstration.
    Elle retourne les derniers logs.
    Normalement, dans un vrai système, cette route serait réservée à l'admin.
    """

    if not os.path.exists(LOG_FILE):
        return jsonify({
            "logs": []
        }), 200

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        lines = file.readlines()

    last_logs = lines[-20:]

    logs = []
    for line in last_logs:
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return jsonify({
        "logs": logs
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=True)