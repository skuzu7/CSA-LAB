"""PATCHED variant — same API, flaws fixed. Used by regression tests.

FINDING-001: ownership check (403 unless row.owner == current user).
FINDING-002: parameterized LIKE query (no string interpolation).
FINDING-003: basename allowlist — realpath must stay inside files/.
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
    return jsonify({"app": "defensive-security-lab demo (patched)", "user": current_user()})


def current_user():
    return request.args.get("as", "alice")


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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
