"""Intentionally vulnerable demo app — LOCALHOST ONLY.

Do NOT deploy. Do NOT expose to any network. Binds 127.0.0.1 by design.
Planted flaws (see writeups/):
  FINDING-001 IDOR on GET /note/<id>
  FINDING-002 SQL injection on GET /search
  FINDING-003 path traversal on GET /download
  FINDING-004 forgeable session token on GET /me (predictable, unsigned)
  FINDING-005 business-logic flaw on POST /transfer (negative amount)
  FINDING-006 SSRF on GET /preview (unrestricted server-side fetch)
"""
import base64
import os
import sqlite3
import sys
import urllib.parse
import urllib.request
from flask import Flask, request, jsonify, send_file, abort, Response

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BASE))
import lab_telemetry  # noqa: E402  (opt-in audit log, off unless LAB_AUDIT_LOG is set)

lab_telemetry.install(app)
DB = os.path.join(BASE, "notes.db")
FILES = os.path.join(BASE, "files")


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
    return jsonify({"app": "CSA-LAB demo (vulnerable by design)", "user": current_user(),
                    "endpoints": ["GET /note/<id>", "GET /search?q=", "GET /download?f=",
                                  "GET /login?as=", "GET /me", "POST /transfer", "GET /preview?url="]})


def current_user():
    # Demo auth: ?as=alice|bob. No passwords — localhost fixture only.
    return request.args.get("as", "alice")


@app.get("/note/<int:note_id>")
def get_note(note_id):
    # FINDING-001: no ownership check (IDOR). alice can read bob's note id=3.
    conn = get_db()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if row is None:
        abort(404)
    lab_telemetry.note(actor=current_user(), resource_owner=row["owner"])
    return jsonify({"id": row["id"], "owner": row["owner"], "title": row["title"], "body": row["body"]})


@app.get("/search")
def search():
    # FINDING-002: string-interpolated SQL (injection).
    q = request.args.get("q", "")
    conn = get_db()
    rows = conn.execute(f"SELECT id, owner, title FROM notes WHERE title LIKE '%{q}%'").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.get("/download")
def download():
    # FINDING-003: unsanitized path join (traversal). ?f=../app.py leaks source.
    name = request.args.get("f", "public.txt")
    path = os.path.join(FILES, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.get("/login")
def login():
    # FINDING-004: token is just base64(username) — unsigned and predictable.
    user = request.args.get("as", "alice")
    token = base64.b64encode(user.encode()).decode()
    lab_telemetry.note(issued_subject=user)
    return jsonify({"token": token})


@app.get("/me")
def me():
    # FINDING-004: server trusts a token any client can forge for any user.
    token = request.headers.get("X-Session-Token", "")
    try:
        user = base64.b64decode(token.encode()).decode()
    except Exception:
        abort(401)
    if not user:
        abort(401)
    lab_telemetry.note(token_subject=user)
    conn = get_db()
    row = conn.execute("SELECT owner, balance FROM accounts WHERE owner = ?", (user,)).fetchone()
    conn.close()
    if row is None:
        abort(401)
    return jsonify({"user": row["owner"], "balance": row["balance"]})


@app.post("/transfer")
def transfer():
    # FINDING-005: amount is never validated as positive, so a negative
    # transfer pulls funds FROM the destination account (reverse transfer).
    data = request.get_json(silent=True) or {}
    src = data.get("from", "alice")
    dst = data.get("to", "bob")
    amount = int(data.get("amount", 0))
    lab_telemetry.note(transfer_from=src, transfer_to=dst, amount=amount)
    conn = get_db()
    row = conn.execute("SELECT balance FROM accounts WHERE owner = ?", (src,)).fetchone()
    if row is None:
        conn.close()
        abort(404)
    if row["balance"] < amount:
        conn.close()
        return jsonify({"error": "insufficient funds"}), 400
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE owner = ?", (amount, src))
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE owner = ?", (amount, dst))
    conn.commit()
    out = {r["owner"]: r["balance"] for r in conn.execute("SELECT owner, balance FROM accounts")}
    conn.close()
    return jsonify(out)


@app.get("/internal/config")
def internal_config():
    # Fixture standing in for link-local-only data (cloud-metadata style).
    # Synthetic values. Reachable over HTTP only because this demo binds
    # 127.0.0.1; real metadata endpoints are never touched.
    return jsonify({"role": "demo-instance-role", "secret": "SSRF-FIXTURE-SECRET"})


@app.get("/preview")
def preview():
    # FINDING-006: unrestricted server-side fetch. Any URL the lab process
    # can reach is fetched and returned, including link-local-only routes.
    target = request.args.get("url", "")
    try:
        with urllib.request.urlopen(target, timeout=3) as resp:
            return Response(resp.read(), content_type="application/json")
    except Exception as e:
        abort(400, str(e)[:200])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
