"""PATCHED variant — same API, flaws fixed. Used by regression tests.

FINDING-001: ownership check (403 unless row.owner == current user).
FINDING-002: parameterized LIKE query (no string interpolation).
FINDING-003: realpath containment — resolved path must stay inside files/.
FINDING-004: HMAC-signed session token with constant-time verification.
FINDING-005: server-side amount validation (positive, bounded, integer).
"""
import base64
import hashlib
import hmac
import os
import sqlite3
from flask import Flask, request, jsonify, send_file, abort

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "notes.db")
FILES = os.path.join(BASE, "files")

# Lab fixture key. Real deployments load this from a secret manager, never source.
SESSION_KEY = os.environ.get("LAB_SESSION_KEY", "lab-fixture-key-not-a-secret").encode()

MAX_TRANSFER = 1_000_000


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("DROP TABLE IF EXISTS notes")
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
    conn.execute("INSERT INTO notes (owner, title, body) VALUES ('alice', 'shopping', 'buy milk')")
    conn.execute("INSERT INTO notes (owner, title, body) VALUES ('alice', 'todo', 'call dentist')")
    conn.execute("INSERT INTO notes (owner, title, body) VALUES ('bob', 'secret', 'bob private note')")
    conn.execute("DROP TABLE IF EXISTS accounts")
    conn.execute("CREATE TABLE accounts (owner TEXT PRIMARY KEY, balance INTEGER)")
    conn.execute("INSERT INTO accounts (owner, balance) VALUES ('alice', 100)")
    conn.execute("INSERT INTO accounts (owner, balance) VALUES ('bob', 100)")
    conn.commit()
    conn.close()
    os.makedirs(FILES, exist_ok=True)
    with open(os.path.join(FILES, "public.txt"), "w") as f:
        f.write("public file\n")


@app.get("/")
def index():
    return jsonify({"app": "CSA-LAB demo (patched)", "user": current_user()})


def current_user():
    return request.args.get("as", "alice")


def _sign(user: str) -> str:
    """FIX 004: token = base64(user).base64(hmac_sha256(key, user))."""
    mac = hmac.new(SESSION_KEY, user.encode(), hashlib.sha256).digest()
    return (base64.urlsafe_b64encode(user.encode()).decode().rstrip("=")
            + "."
            + base64.urlsafe_b64encode(mac).decode().rstrip("="))


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _verify(token: str):
    """FIX 004: reject any token whose HMAC does not match. Constant-time compare."""
    if not token or token.count(".") != 1:
        return None
    body, sig = token.split(".", 1)
    try:
        user = _b64d(body).decode()
        given = _b64d(sig)
    except Exception:
        return None
    expected = hmac.new(SESSION_KEY, user.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(given, expected):
        return None
    return user


@app.get("/note/<int:note_id>")
def get_note(note_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if row is None:
        abort(404)
    if row["owner"] != current_user():  # FIX 001
        abort(403)
    return jsonify({"id": row["id"], "owner": row["owner"], "title": row["title"], "body": row["body"]})


@app.get("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    rows = conn.execute("SELECT id, owner, title FROM notes WHERE title LIKE ?", (f"%{q}%",)).fetchall()  # FIX 002
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.get("/download")
def download():
    name = request.args.get("f", "public.txt")
    try:
        real = os.path.realpath(os.path.join(FILES, name))
        ok = os.path.commonpath([real, os.path.realpath(FILES)]) == os.path.realpath(FILES)
    except ValueError:
        ok = False
    if not ok:  # FIX 003
        abort(403)
    if not os.path.isfile(real):
        abort(404)
    return send_file(real)


@app.get("/login")
def login():
    user = request.args.get("as", "alice")
    conn = get_db()
    row = conn.execute("SELECT owner FROM accounts WHERE owner = ?", (user,)).fetchone()
    conn.close()
    if row is None:
        abort(401)
    return jsonify({"token": _sign(user)})  # FIX 004


@app.get("/me")
def me():
    user = _verify(request.headers.get("X-Session-Token", ""))  # FIX 004
    if user is None:
        abort(401)
    conn = get_db()
    row = conn.execute("SELECT owner, balance FROM accounts WHERE owner = ?", (user,)).fetchone()
    conn.close()
    if row is None:
        abort(401)
    return jsonify({"user": row["owner"], "balance": row["balance"]})


@app.get("/balances")
def balances():
    """Read-only view of the demo ledger, used by regression tests."""
    conn = get_db()
    out = {r["owner"]: r["balance"] for r in conn.execute("SELECT owner, balance FROM accounts")}
    conn.close()
    return jsonify(out)


@app.post("/transfer")
def transfer():
    data = request.get_json(silent=True) or {}
    src = data.get("from", "alice")
    dst = data.get("to", "bob")
    raw = data.get("amount", 0)

    # FIX 005: validate type, sign and bounds BEFORE touching balances.
    if isinstance(raw, bool) or not isinstance(raw, int):
        return jsonify({"error": "amount must be an integer"}), 400
    if raw <= 0:
        return jsonify({"error": "amount must be positive"}), 400
    if raw > MAX_TRANSFER:
        return jsonify({"error": "amount exceeds limit"}), 400
    if src == dst:
        return jsonify({"error": "source and destination must differ"}), 400

    amount = raw
    conn = get_db()
    srow = conn.execute("SELECT balance FROM accounts WHERE owner = ?", (src,)).fetchone()
    drow = conn.execute("SELECT balance FROM accounts WHERE owner = ?", (dst,)).fetchone()
    if srow is None or drow is None:
        conn.close()
        abort(404)
    if srow["balance"] < amount:
        conn.close()
        return jsonify({"error": "insufficient funds"}), 400
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE owner = ?", (amount, src))
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE owner = ?", (amount, dst))
    conn.commit()
    out = {r["owner"]: r["balance"] for r in conn.execute("SELECT owner, balance FROM accounts")}
    conn.close()
    return jsonify(out)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
