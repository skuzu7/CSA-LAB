"""A deliberately vulnerable invoicing API to practise access-control testing on.

It binds to 127.0.0.1 only and has no option to change that: do not expose it.
Which routes are broken is listed at the bottom of the README; try to find them first.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {
    1: {"id": 1, "name": "Alice Souza", "email": "alice@lab.test", "role": "user", "tax_id": "LAB-0001"},
    2: {"id": 2, "name": "Bob Lima", "email": "bob@lab.test", "role": "user", "tax_id": "LAB-0002"},
    3: {"id": 3, "name": "Carol Admin", "email": "carol@lab.test", "role": "admin", "tax_id": "LAB-0003"},
}
PASSWORDS = {"alice": (1, "alice-pass"), "bob": (2, "bob-pass"), "carol": (3, "carol-pass")}
TOKENS = {"lab-token-alice": 1, "lab-token-bob": 2, "lab-token-carol": 3}

DOCUMENT_ALICE = "0b9d2c0e-6f1a-4c53-9a7e-2f4d8c1b7a10"
DOCUMENT_BOB = "5e1f7a92-3b6d-4e08-8c2f-9a0b1d3c4e21"


def fresh_state() -> dict:
    return {
        "invoices": {
            101: {"id": 101, "owner_id": 1, "customer_email": "alice@lab.test", "amount": 1250.00, "memo": "Consulting, March"},
            102: {"id": 102, "owner_id": 1, "customer_email": "alice@lab.test", "amount": 310.50, "memo": "Hosting"},
            201: {"id": 201, "owner_id": 2, "customer_email": "bob@lab.test", "amount": 89.90, "memo": "Domain renewal"},
        },
        "notes": {
            1: {"id": 1, "owner_id": 1, "text": "Alice Souza: bank details go out on Friday"},
            2: {"id": 2, "owner_id": 2, "text": "Bob Lima: renew the certificate"},
        },
        "documents": {
            DOCUMENT_ALICE: {"id": DOCUMENT_ALICE, "owner_id": 1, "title": "Contract (Alice Souza)"},
            DOCUMENT_BOB: {"id": DOCUMENT_BOB, "owner_id": 2, "title": "Contract (Bob Lima)"},
        },
        "redirect_target_hits": 0,
    }


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- route handlers: (handler, user, match) -> (status, payload[, headers]) ---


def health(h, user, m):
    return 200, {"status": "ok", "server_time": now()}


def login(h, user, m):
    data = h.read_json()
    user_id, password = PASSWORDS.get(str(data.get("username")), (None, None))
    if user_id is None or data.get("password") != password:
        return 401, {"error": "invalid credentials"}
    token = next(t for t, uid in TOKENS.items() if uid == user_id)
    return 200, {"token": token}


def me(h, user, m):
    return 200, user


def plans(h, user, m):
    return 200, {"plans": [{"name": "Starter", "price": 0}, {"name": "Pro", "price": 49}], "generated_at": now()}


def list_invoices(h, user, m):
    return 200, [i for i in h.state["invoices"].values() if i["owner_id"] == user["id"]]


def get_invoice(h, user, m):
    invoice = h.state["invoices"].get(int(m[1]))
    return (200, invoice) if invoice else (404, {"error": "not found"})


def update_invoice(h, user, m):
    invoice = h.state["invoices"].get(int(m[1]))
    if not invoice:
        return 404, {"error": "not found"}
    memo = h.read_json().get("memo")
    if isinstance(memo, str):
        invoice["memo"] = memo
    return 200, invoice


def get_receipt(h, user, m):
    invoice = h.state["invoices"].get(int(m[1]))
    if not invoice or invoice["owner_id"] != user["id"]:
        return 404, {"error": "not found"}
    return 200, {"invoice_id": invoice["id"], "paid_by": invoice["customer_email"], "amount": invoice["amount"]}


def get_user(h, user, m):
    found = USERS.get(int(m[1]))
    return (200, found) if found else (404, {"error": "not found"})


def admin_users(h, user, m):
    return 200, {"users": list(USERS.values())}


def get_note(h, user, m):
    note = h.state["notes"].get(int(m[1]))
    return (200, note) if note else (404, {"error": "not found"})


def get_document(h, user, m):
    document = h.state["documents"].get(m[1])
    if not document:
        return 404, {"error": "not found"}
    if document["owner_id"] != user["id"]:
        return 403, {"error": "forbidden"}
    return 200, document


def old_dashboard(h, user, m):
    return 302, {"moved": True}, {"Location": "/api/redirect-target"}


def redirect_target(h, user, m):
    h.state["redirect_target_hits"] += 1
    return 200, {"landed": True}


def static_js(h, user, m):
    return 200, "console.log('lab');", {"Content-Type": "application/javascript"}


# (method, path pattern, handler, requires a valid token)
ROUTES = [
    ("GET", r"/api/health", health, False),
    ("POST", r"/api/login", login, False),
    ("GET", r"/api/me", me, True),
    ("GET", r"/api/plans", plans, True),
    ("GET", r"/api/invoices", list_invoices, True),
    ("GET", r"/api/invoices/(\d+)", get_invoice, True),
    ("PUT", r"/api/invoices/(\d+)", update_invoice, True),
    ("GET", r"/api/invoices/(\d+)/receipt", get_receipt, True),
    ("GET", r"/api/users/(\d+)", get_user, True),
    ("GET", r"/api/admin/users", admin_users, True),
    ("GET", r"/api/notes/(\d+)", get_note, False),
    ("GET", r"/api/documents/([0-9a-f-]{36})", get_document, True),
    ("GET", r"/api/old-dashboard", old_dashboard, True),
    ("GET", r"/api/redirect-target", redirect_target, False),
    ("GET", r"/static/app\.js", static_js, False),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "authz-lab/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> dict:
        return self.server.state

    def log_message(self, fmt, *args):
        if self.server.verbose:
            super().log_message(fmt, *args)

    def read_json(self) -> dict:
        try:
            data = json.loads(self.body or b"{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def current_user(self):
        scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
        return USERS.get(TOKENS.get(token.strip())) if scheme.lower() == "bearer" else None

    def reply(self, status: int, payload, headers: dict | None = None) -> None:
        headers = dict(headers or {})
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        headers.setdefault("Content-Type", "application/json")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def dispatch(self) -> None:
        # Always consume the body first so the connection stays usable whatever the answer is.
        self.body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        path = self.path.split("?", 1)[0]
        path_known = False
        for method, pattern, handler, needs_auth in ROUTES:
            match = re.fullmatch(pattern, path)
            if not match:
                continue
            path_known = True
            if method != self.command:
                continue
            user = self.current_user()
            if needs_auth and user is None:
                self.reply(401, {"error": "authentication required"})
                return
            self.reply(*handler(self, user, match))
            return
        if path_known:
            self.reply(405, {"error": "method not allowed"})
        else:
            self.reply(404, {"error": "not found"})

    do_GET = do_POST = do_PUT = do_DELETE = dispatch


def make_server(port: int = 8099, verbose: bool = False) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.state = fresh_state()
    server.verbose = verbose
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliberately vulnerable lab API (localhost only)")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--quiet", action="store_true", help="do not log requests")
    args = parser.parse_args()
    server = make_server(args.port, verbose=not args.quiet)
    print(f"lab API listening on http://127.0.0.1:{server.server_address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
