# authzdiff

Finds broken access control (IDOR / BOLA, missing authentication) by replaying
requests you captured as one user in two other ways: as a second user, and with
no credentials. If the second user or the anonymous client receives the first
user's private data, that is a finding.

It comes with a deliberately vulnerable API to practise on, has no dependencies
outside the Python standard library (3.11+), and writes a Markdown report you
can adapt for a bug bounty submission or a pentest deliverable.

## Rules of use

Use it only on systems you own or are explicitly authorized to test (a bug
bounty program's scope, a signed pentest agreement), and only with accounts you
created yourself. Read the program's rules first: some forbid automation, set
a request rate, or require an identifying header.

## Try it on the lab

Run every command in this README from the `authz-diff/` directory.

Terminal 1:

```bash
python lab/server.py
```

Terminal 2:

```bash
python -m authzdiff -c examples/lab.toml --har examples/lab.har --report report.md
```

You should see four `VULNERABLE` rows, one `SUSPECT`, one `PUBLIC`, and the
rest passing. The exit code is 2 when there is at least one `VULNERABLE`, so
the same command works as a regression check in CI for an API you maintain.

Before reading the answer key at the bottom, try to find the broken routes by
hand with `curl` and the tokens in `examples/lab.toml`.

## Use it on a real target

1. Create two accounts on the target, A (owner) and B (other), with the same
   role. Put some data in both.
2. Log in as A in a browser, open the developer tools' Network tab (or run your
   traffic through Burp, ZAP or mitmproxy), use every feature you can, and
   export the session as a HAR file.
3. Copy `examples/lab.toml` to `target.local.toml` and fill in:
   - `[scope] hosts`: exactly what the program lists as in scope.
   - `[identities.owner]` and `[identities.other]`: each account's session
     headers (`Authorization`, `Cookie`, a CSRF header if the app uses one).
     Write `"Bearer ${TOKEN_A}"` and export `TOKEN_A` in your shell rather than
     pasting tokens into the file.
   - `markers`: strings that appear only in that account's private data, such
     as its email, full name, or account number.
4. Check what would be sent, then run it:

```bash
python -m authzdiff -c target.local.toml --har session.har --dry-run
```

```bash
python -m authzdiff -c target.local.toml --har session.har --report out/report.md --save-bodies out/bodies
```

To test vertical access (a normal user reaching admin functions), capture the
HAR as the admin and set the admin as `owner` and a normal user as `other`.

HAR files contain your session tokens and often your password. The bundled
`.gitignore` excludes them; do not commit or share them.

## Verdicts

| Verdict | Meaning | What to do |
|---|---|---|
| `VULNERABLE` | The other user, or an anonymous client, got a 2xx whose body contains the owner's markers. | Reproduce by hand, then report. |
| `SUSPECT` | Both users got the same content from an endpoint that requires login, and no marker settled it. | Open the bodies. Shared data (a price list) is fine; one user's object is not. |
| `PUBLIC` | The same content comes back with no credentials and holds no owner marker. | Confirm it is meant to be public. |
| `DIFFERS` | The other user got a 2xx with different content: their own data, or an error inside a 200. | Usually fine. |
| `ENFORCED` | The other user was refused (401, 403, 404, or a redirect). | Nothing. |
| `SKIPPED` | The owner's own replay did not return 2xx, so there is no baseline. | Refresh the owner's session and capture again. |

Each request is sent as the owner first. If that fails, the other two are not
sent. JSON bodies are compared value by value after dropping keys that change
on every call (`timestamp`, `request_id` and similar; add your own with
`ignore_keys`), so two users' records with the same shape but different values
score low. Other bodies are compared as text.

Markers are what turn a guess into a finding. Without them nothing is reported
as `VULNERABLE`: the same leaks show up as `SUSPECT` or `PUBLIC`.

## What it will not do

- Send anything to a host that is not in `[scope] hosts`. A hostname without a
  port covers only the default port.
- Follow redirects. A 3xx is recorded as the answer.
- Replay `POST`, `PUT`, `PATCH` or `DELETE` unless you list them in `methods`
  and also pass `--allow-state-changing`. Replaying those as another user can
  change or delete the owner's data, which is the point of the test but should
  be a decision.
- Write credentials to the terminal, the JSON output or the report. The
  reproduction commands use placeholders such as `<BOB_AUTHORIZATION>`.

`--save-bodies` does write raw responses to disk, and on a real target those
can contain other people's data if a leak is real. Keep that directory private
and delete it when the report is filed.

## Limits

- It tests the requests you captured. Coverage is as good as your click-through.
- It does not change identifiers. It asks whether B can read the objects A
  touched, not whether A can guess B's. Capture as each account in turn for
  both directions.
- For state-changing methods the order is owner, anonymous, other. If the
  request is not idempotent (a `DELETE`, a counter), check the result by hand.
- If both accounts are empty, their responses are identical and show up as
  `SUSPECT`. Put data in the accounts first.
- Markers are matched against decoded JSON values and raw text. HTML-escaped
  or otherwise encoded values will not match.
- Requests signed per call (HMAC, AWS SigV4) or bound to a one-time CSRF token
  cannot be replayed this way.

## Options

```
-c, --config FILE          scope, identities and settings (required)
--har FILE                 HAR capture of the owner's session (repeatable)
--methods GET,PUT          override the methods in the config
--allow-state-changing     required for anything except GET, HEAD, OPTIONS
--dry-run                  list what would be sent and exit
--report FILE              Markdown report
--json FILE                machine-readable results
--save-bodies DIR          raw response bodies, for reviewing SUSPECT rows
--proxy URL                route traffic through a proxy such as Burp
--cafile PEM               trust an extra CA, such as the proxy's
```

Requests can also be listed in the config instead of a HAR:

```toml
[[requests]]
url = "https://api.example.com/v1/orders/1234"
```

## Tests

```bash
python -m unittest
```

The suite starts the lab on a free port and checks the verdict for every route.

## Lab answer key

<details>
<summary>Spoilers</summary>

| Route | Problem |
|---|---|
| `GET /api/invoices/{id}` | Returns any invoice to any logged-in user (BOLA). |
| `PUT /api/invoices/{id}` | Lets any logged-in user edit any invoice (BOLA, write). |
| `GET /api/users/{id}` | Returns any user's profile, including `tax_id` (BOLA). |
| `GET /api/admin/users` | Admin function with no role check (BFLA). |
| `GET /api/notes/{id}` | No authentication at all. |

`GET /api/invoices/{id}/receipt` and `GET /api/documents/{uuid}` check
ownership correctly. `GET /api/plans` is the same for everyone by design, which
is why it shows as `SUSPECT`: the tool cannot know that, and you have to look.

</details>
