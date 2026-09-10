# Threat model (lab)

Assets: demo note bodies (synthetic), demo DB contents (synthetic), files served (synthetic), app source (public by design).

Actors: (a) demo user alice/bob — authenticated, mutually untrusted; (b) local process snooper — out of scope (localhost trust); (c) external attacker — no route (binds 127.0.0.1, no deploy).

Trust boundaries: HTTP handlers (authz per object), SQL layer (parameterization), filesystem layer (containment). Each finding maps to exactly one boundary. STRIDE-lite: spoofing (demo `?as=` accepted as fixture limitation, documented), tampering/info-disclosure (the three findings), DoS/elevation: not applicable to fixture scope.
