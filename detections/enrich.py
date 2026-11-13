"""Stateful enrichment applied to the audit stream before rule evaluation.

Sigma rules are stateless per event. Detecting a forged token in the vulnerable
fixture needs memory of which subjects were actually issued a token, so this step
adds ``token_issued`` to every ``/me`` event that carries a ``token_subject``. In a
SIEM this is a lookup table fed by the ``/login`` events.
"""
from __future__ import annotations

from typing import Iterable


def enrich(events: Iterable[dict]) -> list[dict]:
    issued: set[str] = set()
    out = []
    for event in events:
        event = dict(event)
        subject = event.get("issued_subject")
        if event.get("cs-uri-stem") == "/login" and subject and event.get("sc-status") == 200:
            issued.add(str(subject))
        claimed = event.get("token_subject")
        if event.get("cs-uri-stem") == "/me" and claimed:
            event["token_issued"] = str(claimed) in issued
        out.append(event)
    return out
