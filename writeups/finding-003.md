# FINDING-003 — Path Traversal in `GET /download?f=`

- Severity (lab): High (arbitrary local file read as the app user).
- Classification: CWE-22; CVSS v3.1 **7.5 (High)** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`, scored as if internet-facing — see [classification](../docs/classification.md).
- Target: local Flask demo, `vulnerable-app/app.py::download`. Serves `files/`.
- Status: PATCHED (`remediation/patched_app.py::download`), regression-covered.

## 1. Context

Download endpoint serves files from `vulnerable-app/files/` by name.

## 2. Threat model

Actor: any demo user. Asset: any file readable by the app process (here: `../app.py` source; in production: configs, keys, `/etc/passwd`). Root cause: unsanitized join of user input to a base directory.

## 3. Cause

```python
path = os.path.join(FILES, name)   # ?f=../app.py escapes files/
return send_file(path)
```

No normalization, no containment check.

## 4. Authorized reproduction

```bash
LAB_APP_VARIANT=vulnerable pytest tests/security/test_findings_vulnerable.py::test_003_download_traversal_leaks_source -v
# GET /download?f=../app.py -> 200 with app source
```

## 5. Impact

Full source disclosure in the demo; in production this class yields secret theft and RCE recon. Contained here to the repo directory on localhost.

## 6. Remediation

```python
try:
    real = os.path.realpath(os.path.join(FILES, name))
    ok = os.path.commonpath([real, os.path.realpath(FILES)]) == os.path.realpath(FILES)
except ValueError:
    ok = False
if not ok:
    abort(403)
```

Canonicalize (`realpath`) then verify containment; fail closed on any abnormal input (the `ValueError` branch caught the `....//` case during testing — regression suite covers `../`, encoded, double-dot, and absolute-path payloads). Stronger alternative: allowlist of known filenames; recommended where the file set is enumerable.

## 7. Regression test

`tests/regression/test_fixes.py::test_003_fixed_traversal_blocked` — 4 malicious payloads blocked (400/403/404), `public.txt` still served. PASS (verified 2026-09-10).

## 8. Lessons

Every filesystem access with user input needs canonicalization + containment (or an allowlist). Blocklists of `..` fail against encoding and edge cases — the test run caught one (`....//` → 500 via `commonpath` ValueError) before the fix hardened it. That is why the regression list includes payloads, not just one.
