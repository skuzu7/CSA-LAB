"""Minimal Sigma evaluator used to prove the rules in ``detections/rules`` fire.

This is a deliberately small subset of the Sigma specification, sufficient to run
this repository's rules against JSON events in CI. It is NOT a SIEM and NOT a
replacement for pySigma; convert the rules with a real backend for production.

Supported: field equality (case-insensitive, ``*``/``?`` wildcards), value lists
(OR), map lists (OR), the modifiers ``contains``, ``startswith``, ``endswith``,
``all``, ``re`` (with the ``i`` flag), ``lt``/``lte``/``gt``/``gte``, ``exists`` and
``fieldref``; and conditions built from ``and``/``or``/``not``, parentheses and
``1 of`` / ``all of`` with a ``*`` suffix pattern or ``them``.
Anything else raises ``UnsupportedRule`` so a rule can never silently half-match.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

REQUIRED_KEYS = ("title", "id", "status", "description", "logsource", "detection", "level")
_NUMERIC = {"lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
            "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b}
_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class UnsupportedRule(ValueError):
    """Raised when a rule uses a Sigma feature this evaluator does not implement."""


@dataclass(frozen=True)
class Rule:
    path: Path
    doc: dict

    @property
    def rule_id(self) -> str:
        return str(self.doc["id"])

    @property
    def title(self) -> str:
        return str(self.doc["title"])

    @property
    def finding(self) -> str:
        """Lab finding number this rule covers, e.g. ``003`` (custom field)."""
        return str(self.doc.get("csa_lab_finding", ""))

    def matches(self, event: dict) -> bool:
        detection = self.doc["detection"]
        names = {k: v for k, v in detection.items() if k != "condition"}
        results = {name: _search(body, event) for name, body in names.items()}
        return _Condition(str(detection["condition"]), results).evaluate()


def load_rules(directory: Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(directory).glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = [key for key in REQUIRED_KEYS if key not in doc]
        if missing:
            raise UnsupportedRule(f"{path.name}: missing required keys {missing}")
        if "condition" not in doc["detection"]:
            raise UnsupportedRule(f"{path.name}: detection has no condition")
        rules.append(Rule(path=path, doc=doc))
    ids = [rule.rule_id for rule in rules]
    if len(ids) != len(set(ids)):
        raise UnsupportedRule("duplicate rule ids")
    return rules


def evaluate(rules: Iterable[Rule], event: dict) -> list[str]:
    """Return the ids of every rule that matches ``event``."""
    return [rule.rule_id for rule in rules if rule.matches(event)]


# --------------------------------------------------------------------------- search

def _search(body: Any, event: dict) -> bool:
    if isinstance(body, dict):
        return all(_field(spec, expected, event) for spec, expected in body.items())
    if isinstance(body, list) and all(isinstance(item, dict) for item in body):
        return any(_search(item, event) for item in body)
    raise UnsupportedRule("keyword (unfielded) searches are not supported")


def _field(spec: str, expected: Any, event: dict) -> bool:
    name, *modifiers = spec.split("|")
    present = name in event and event[name] is not None
    actual = event.get(name)

    if modifiers == ["exists"]:
        return present is bool(expected)
    if modifiers == ["fieldref"]:
        other = event.get(str(expected))
        return present and other is not None and _fold(actual) == _fold(other)

    require_all = "all" in modifiers
    modifiers = [m for m in modifiers if m != "all"]
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise UnsupportedRule(f"{spec}: empty value list")
    hits = [_value(modifiers, actual, present, value, spec) for value in values]
    return all(hits) if require_all else any(hits)


def _value(modifiers: list[str], actual: Any, present: bool, expected: Any, spec: str) -> bool:
    if expected is None:
        if modifiers:
            raise UnsupportedRule(f"{spec}: null cannot take modifiers")
        return not present
    if not present:
        return False

    if not modifiers:
        if isinstance(expected, bool) or isinstance(actual, bool):
            return actual is expected
        if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
            return actual == expected
        pattern = _fold(expected)
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatchcase(_fold(actual), pattern)
        return _fold(actual) == pattern

    head, *rest = modifiers
    if head in _NUMERIC and not rest:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return _NUMERIC[head](actual, expected)
    if head == "re" and rest in ([], ["i"]):
        return re.search(str(expected), str(actual), re.IGNORECASE if rest else 0) is not None
    if head in ("contains", "startswith", "endswith") and not rest:
        text, needle = _fold(actual), _fold(expected)
        if head == "contains":
            return needle in text
        return text.startswith(needle) if head == "startswith" else text.endswith(needle)
    raise UnsupportedRule(f"{spec}: unsupported modifier chain {modifiers}")


def _fold(value: Any) -> str:
    return str(value).casefold()


# ------------------------------------------------------------------------ condition

class _Condition:
    """Recursive-descent parser: or_expr -> and_expr -> not_expr -> atom."""

    def __init__(self, text: str, results: dict[str, bool]):
        if "|" in text:
            raise UnsupportedRule("aggregation pipes are not supported")
        self.tokens = _TOKEN.findall(text)
        if "".join(self.tokens) != re.sub(r"\s+", "", text):
            raise UnsupportedRule(f"unparseable condition: {text!r}")
        self.results = results
        self.pos = 0

    def evaluate(self) -> bool:
        value = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedRule("trailing tokens in condition")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise UnsupportedRule("unexpected end of condition")
        self.pos += 1
        return token

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._take()
            value = self._and() or value
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._take()
            value = self._not() and value
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._take()
        if token == "(":
            value = self._or()
            if self._take() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            return value
        if token in ("1", "all") and self._peek() == "of":
            self._take()
            selected = self._select(self._take())
            return any(selected) if token == "1" else all(selected)
        if token not in self.results:
            raise UnsupportedRule(f"unknown search identifier {token!r}")
        return self.results[token]

    def _select(self, pattern: str) -> list[bool]:
        if pattern == "them":
            names = list(self.results)
        else:
            names = [name for name in self.results if fnmatch.fnmatchcase(name, pattern)]
        if not names:
            raise UnsupportedRule(f"pattern {pattern!r} matches no search identifier")
        return [self.results[name] for name in names]
