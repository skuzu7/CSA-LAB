"""Intentionally vulnerable demo app — LOCALHOST ONLY.

Do NOT deploy. Do NOT expose to any network. Binds 127.0.0.1 by design.
Planted flaws (see writeups/): FINDING-001 IDOR, FINDING-002 SQLi, FINDING-003 path traversal.
"""
import os
import sqlite3
from flask import Flask, request, jsonify, send_file, abort

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
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
    conn.commit()
    conn.close()
    os.makedirs(FILES, exist_ok=True)
    with open(os.path.join(FILES, "public.txt"), "w") as f:
        f.write("public file\n")


@app.get("/")
def index():
    return jsonify({"app": "defensive-security-lab demo (vulnerable by design)", "user": current_user(),
                    "endpoints": ["GET /note/<id>", "GET /search?q=", "GET /download?f="]})


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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
