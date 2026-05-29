from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import hashlib
from datetime import datetime

app = Flask(__name__)

DB_NAME = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()

    default_users = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("user", "user123", "user")
    ]

    for username, password, role in default_users:
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user is None:
            password_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )

    conn.commit()
    conn.close()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "AuthService",
        "status": "running"
    }), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    if len(username) > 50 or len(password) > 100:
        return jsonify({"error": "Invalid credentials"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is None:
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    token = secrets.token_urlsafe(32)
    token_hash = hash_token(token)

    cursor.execute(
        "INSERT INTO tokens (username, token_hash, created_at) VALUES (?, ?, ?)",
        (username, token_hash, datetime.now().isoformat())
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Login successful",
        "token": token,
        "username": username,
        "role": user["role"]
    }), 200


@app.route("/verify-token", methods=["POST"])
def verify_token():
    data = request.get_json()

    if not data:
        return jsonify({"valid": False, "error": "Invalid request"}), 400

    token = str(data.get("token", "")).strip()

    if not token:
        return jsonify({"valid": False, "error": "Unauthorized"}), 401

    token_hash = hash_token(token)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT tokens.username, users.role
        FROM tokens
        JOIN users ON tokens.username = users.username
        WHERE tokens.token_hash = ?
    """, (token_hash,))

    result = cursor.fetchone()
    conn.close()

    if result is None:
        return jsonify({"valid": False, "error": "Unauthorized"}), 401

    return jsonify({
        "valid": True,
        "username": result["username"],
        "role": result["role"]
    }), 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)