# Threat model (lab)

Assets: demo note bodies (synthetic), demo DB contents (synthetic), files served (synthetic), demo ledger balances (synthetic), link-local-only fixture values (synthetic), app source (public by design).

Actors: (a) demo user alice/bob — authenticated, mutually untrusted; (b) unauthenticated local client (session forgery, FINDING-004); (c) local process snooper — out of scope (localhost trust); (d) external attacker — no route (binds 127.0.0.1, no deploy).

Trust boundaries: HTTP handlers (authz per object, 001), SQL layer (parameterization, 002), filesystem layer (containment, 003), session-token layer (HMAC integrity, 004), business-logic layer (amount validation, 005), server-side fetch layer (URL allowlist, 006). Each finding maps to exactly one boundary. STRIDE-lite: spoofing (004 forgeable token; demo `?as=` accepted as fixture limitation, documented), tampering (005 negative transfer; 002 SQLi), info-disclosure (001 IDOR, 002 SQLi, 003 traversal, 006 SSRF), DoS/elevation: not applicable to fixture scope.
