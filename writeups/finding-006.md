# FINDING-006 — Server-Side Request Forgery (SSRF) in `GET /preview`

- Severity (lab): High (the server fetches any attacker-chosen URL, including link-local-only routes).
- Classification: CWE-918; CVSS v3.1 **8.6 (High)** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`, scored as if internet-facing — see [classification](../docs/classification.md).
- Target: local Flask demo, `vulnerable-app/app.py::preview`, commit in this repo. Bind 127.0.0.1:5000. The internal route holds synthetic fixture values, never real credentials.
- Status: PATCHED (`remediation/patched_app.py::preview`), regression-covered.

## 1. Context

A URL-preview feature fetches a user-supplied address server-side and returns the body, so clients can render link previews without fetching directly. The vulnerable version passes the raw `?url=` parameter to `urllib.request.urlopen` with no validation at all.

## 2. Threat model

Actor: any local client (no authentication on this endpoint). Asset: data reachable only from the server's network position — here represented by `GET /internal/config`, a fixture in the style of a cloud link-local metadata endpoint holding a synthetic secret. The trust boundary is the fetcher: it must distinguish user-chosen public targets from server-reachable-only ones. No external network is involved — the whole attack plays out on loopback.

## 3. Cause

```python
target = request.args.get("url", "")
with urllib.request.urlopen(target, timeout=3) as resp:
    return Response(resp.read(), content_type="application/json")
```

No scheme check, no host check, no path restriction, no deny-list. The server is a fully open HTTP proxy for whoever can reach it.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/test_findings_vulnerable.py::test_006_ssrf_preview_reaches_internal_config -v
# GET /preview?url=http://127.0.0.1:5000/internal/config -> 200 {"secret": "SSRF-FIXTURE-SECRET", ...}
```

Minimum PoC: `curl "http://127.0.0.1:5000/preview?url=http://127.0.0.1:5000/internal/config"`.

## 5. Impact

The synthetic secret leaks through the fetcher, proving the server's network position is fully exploitable. Against real infrastructure the same flaw class reaches cloud metadata endpoints, internal admin panels, and intranet services — the standard SSRF blast radius. Here it is contained to fixture values on localhost.

## 6. Remediation (the point of this finding)

```python
parts = urllib.parse.urlparse(target)
if parts.scheme != "http":
    return 400
if (parts.hostname or "") not in {"127.0.0.1", "localhost"}:
    return 400
if not (parts.path or "").startswith("/note/"):
    return 400
if any(bad in target.lower() for bad in ("169.254.169.254", "metadata", "internal/")):
    return 400
```

Parse-then-validate: scheme, host allowlist, path-prefix allowlist, plus an explicit deny-list for metadata patterns as defense in depth. Fail-closed on unparseable input and on fetch errors. The allowlist is deliberately narrow (own `/note/` reads only) — a preview feature that can only preview one path shape is honest about what it is a demo of.

### What this fix deliberately does *not* claim

URL parsing has known edge cases (redirect following, DNS rebinding, alternative IP encodings like `0x7f.0.0.1`, userinfo tricks). Production SSRF defense adds: no-redirect fetching, resolve-then-validate with re-resolution races handled, egress proxying, and response-size limits. Those are out of scope for a loopback fixture and are called out so this write-up is not read as a complete SSRF design.

## 7. Regression test

`tests/regression/test_fixes.py::test_006_fixed_preview_allowlist` — internal route refused (400, secret absent), metadata-IP refused (400), allowlisted `/note/1` still previewed (200). PASS (verified 2026-09-10).

## 8. Lessons

SSRF is a server-perspective flaw: the question is never "can the client reach this URL" but "can the *server* reach it on the client's behalf." Every server-side fetch of user input needs an allowlist defined from the server's network position, not the client's. Deny-lists alone lose — this fix layers both, with the allowlist doing the real work.
