from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
import json
import requests
import Pyro5.api

app = Flask(__name__)

DB_NAME = "reports.db"

AUTH_SERVICE_URL = "http://127.0.0.1:5001"
AUDIT_SERVICE_URL = "http://127.0.0.1:5003"

MAX_SENDER_LENGTH = 120
MAX_SUBJECT_LENGTH = 200
MAX_CONTENT_LENGTH = 5000


# -----------------------------
# DATABASE
# -----------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            content TEXT NOT NULL,
            has_attachment INTEGER NOT NULL,
            urls_detected TEXT,
            submitted_at TEXT NOT NULL,
            submitted_by TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            reasons TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# SECURITY AND VALIDATION
# -----------------------------

def clean_text(value):
    if value is None:
        return ""
    value = str(value)
    value = value.replace("<", "").replace(">", "")
    return value.strip()


def validate_email_data(data):
    sender = clean_text(data.get("sender"))
    subject = clean_text(data.get("subject"))
    content = clean_text(data.get("content"))
    has_attachment = bool(data.get("has_attachment", False))

    if not sender or not subject or not content:
        return None, "Missing required fields"

    if len(sender) > MAX_SENDER_LENGTH:
        return None, "Invalid input"

    if len(subject) > MAX_SUBJECT_LENGTH:
        return None, "Invalid input"

    if len(content) > MAX_CONTENT_LENGTH:
        return None, "Invalid input"

    email_data = {
        "sender": sender,
        "subject": subject,
        "content": content,
        "has_attachment": has_attachment
    }

    return email_data, None


def get_token_from_request():
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "").strip()

    return None


def verify_token(token):
    try:
        response = requests.post(
            AUTH_SERVICE_URL + "/verify-token",
            json={"token": token},
            timeout=3
        )

        if response.status_code != 200:
            return None

        data = response.json()

        if not data.get("valid"):
            return None

        return {
            "username": data.get("username"),
            "role": data.get("role")
        }

    except requests.exceptions.RequestException:
        return None


def require_auth():
    token = get_token_from_request()

    if not token:
        return None

    user_info = verify_token(token)
    return user_info


def is_admin_or_analyst(role):
    return role in ["admin", "analyst"]


# -----------------------------
# AUDIT
# -----------------------------

def send_audit(event_type, username, status, details=None):
    if details is None:
        details = {}

    try:
        requests.post(
            AUDIT_SERVICE_URL + "/audit",
            json={
                "event_type": event_type,
                "username": username,
                "status": status,
                "details": details
            },
            timeout=3
        )
    except requests.exceptions.RequestException:
        # On ne bloque pas l'application si AuditService est indisponible
        pass


# -----------------------------
# ANALYSIS RPC
# -----------------------------

def call_analysis_service(email_data):
    try:
        ns = Pyro5.api.locate_ns(host="127.0.0.1", port=9090)
        uri = ns.lookup("phishing.analysis")

        service = Pyro5.api.Proxy(uri)
        service._pyroTimeout = 5

        result = service.analyze_email(email_data)
        return result, None

    except Exception:
        return None, "Analysis service unavailable"


# -----------------------------
# ROUTES
# -----------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "GatewayService",
        "status": "running"
    }), 200


@app.route("/submit", methods=["POST"])
def submit_report():
    user_info = require_auth()

    if user_info is None:
        send_audit(
            "UNAUTHORIZED_ACCESS",
            "anonymous",
            "failed",
            {"endpoint": "/submit"}
        )
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    if not data:
        send_audit(
            "INVALID_SUBMISSION",
            user_info["username"],
            "failed",
            {"reason": "empty request"}
        )
        return jsonify({"error": "Invalid request"}), 400

    email_data, validation_error = validate_email_data(data)

    if validation_error:
        send_audit(
            "INVALID_SUBMISSION",
            user_info["username"],
            "failed",
            {"reason": validation_error}
        )
        return jsonify({"error": "Invalid input"}), 400

    analysis_result, analysis_error = call_analysis_service(email_data)

    if analysis_error:
        send_audit(
            "ANALYSIS_SERVICE_ERROR",
            user_info["username"],
            "failed",
            {"message": analysis_error}
        )
        return jsonify({"error": "Service temporarily unavailable"}), 503

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO reports (
            sender,
            subject,
            content,
            has_attachment,
            urls_detected,
            submitted_at,
            submitted_by,
            risk_score,
            risk_level,
            reasons
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_data["sender"],
        email_data["subject"],
        email_data["content"],
        1 if email_data["has_attachment"] else 0,
        json.dumps(analysis_result.get("urls_detected", []), ensure_ascii=False),
        datetime.now().isoformat(),
        user_info["username"],
        int(analysis_result.get("score", 0)),
        analysis_result.get("level", "faible"),
        json.dumps(analysis_result.get("reasons", []), ensure_ascii=False)
    ))

    report_id = cursor.lastrowid

    conn.commit()
    conn.close()

    send_audit(
        "SUBMISSION_CREATED",
        user_info["username"],
        "success",
        {
            "report_id": report_id,
            "risk_level": analysis_result.get("level", "unknown")
        }
    )

    return jsonify({
        "message": "Report submitted successfully",
        "report_id": report_id,
        "analysis": analysis_result
    }), 201


@app.route("/reports", methods=["GET"])
def list_reports():
    user_info = require_auth()

    if user_info is None:
        send_audit(
            "UNAUTHORIZED_ACCESS",
            "anonymous",
            "failed",
            {"endpoint": "/reports"}
        )
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    if is_admin_or_analyst(user_info["role"]):
        cursor.execute("""
            SELECT id, sender, subject, submitted_at, submitted_by, risk_score, risk_level
            FROM reports
            ORDER BY id DESC
        """)
    else:
        cursor.execute("""
            SELECT id, sender, subject, submitted_at, submitted_by, risk_score, risk_level
            FROM reports
            WHERE submitted_by = ?
            ORDER BY id DESC
        """, (user_info["username"],))

    reports = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "reports": reports
    }), 200


@app.route("/reports/<int:report_id>", methods=["GET"])
def get_report(report_id):
    user_info = require_auth()

    if user_info is None:
        send_audit(
            "UNAUTHORIZED_ACCESS",
            "anonymous",
            "failed",
            {"endpoint": f"/reports/{report_id}"}
        )
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    conn.close()

    if report is None:
        return jsonify({"error": "Report not found"}), 404

    report = dict(report)

    if not is_admin_or_analyst(user_info["role"]) and report["submitted_by"] != user_info["username"]:
        send_audit(
            "FORBIDDEN_ACCESS",
            user_info["username"],
            "failed",
            {"report_id": report_id}
        )
        return jsonify({"error": "Forbidden"}), 403

    report["urls_detected"] = json.loads(report["urls_detected"])
    report["reasons"] = json.loads(report["reasons"])

    return jsonify({
        "report": report
    }), 200


@app.route("/search", methods=["GET"])
def search_reports():
    user_info = require_auth()

    if user_info is None:
        send_audit(
            "UNAUTHORIZED_ACCESS",
            "anonymous",
            "failed",
            {"endpoint": "/search"}
        )
        return jsonify({"error": "Unauthorized"}), 401

    sender = clean_text(request.args.get("sender"))
    risk_level = clean_text(request.args.get("risk_level"))
    keyword = clean_text(request.args.get("keyword"))

    query = """
        SELECT id, sender, subject, submitted_at, submitted_by, risk_score, risk_level
        FROM reports
        WHERE 1=1
    """

    params = []

    if sender:
        query += " AND sender LIKE ?"
        params.append(f"%{sender}%")

    if risk_level:
        query += " AND risk_level = ?"
        params.append(risk_level)

    if keyword:
        query += " AND (subject LIKE ? OR content LIKE ?)"
        params.append(f"%{keyword}%")
        params.append(f"%{keyword}%")

    if not is_admin_or_analyst(user_info["role"]):
        query += " AND submitted_by = ?"
        params.append(user_info["username"])

    query += " ORDER BY id DESC"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    reports = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "reports": reports
    }), 200


if __name__ == "__main__":
    init_db()
    print("GATEWAY SERVICE STARTED")
    print(app.url_map)

app.run(host="127.0.0.1", port=5010, debug=True)