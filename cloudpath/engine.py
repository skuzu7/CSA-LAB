"""CLOUD-PATH: bounded offline privilege graph and permission-removal simulation.

Synthetic permissions only. No cloud SDK, credentials, remote calls or execution.
This is a research abstraction, not a full AWS IAM or Kubernetes RBAC evaluator.
"""
from __future__ import annotations

from collections import deque
from typing import Any


def key(edge: dict) -> tuple[str, str, str]:
    return (edge["from"], edge["action"], edge["to"])


class PrivilegeGraph:
    def __init__(self, data: dict):
        if not isinstance(data, dict):
            raise ValueError("Graph must be an object")
        nodes = data.get("nodes")
        edges = data.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError("Graph must contain nodes and edges")
        if len(nodes) > 2048 or len(edges) > 4096:
            raise ValueError("Graph exceeds bounded research limits")
        self.nodes: set[str] = set()
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
                raise ValueError("Invalid graph node")
            if node["id"] in self.nodes:
                raise ValueError("Duplicate node")
            self.nodes.add(node["id"])

        deny: set[tuple[str, str, str]] = set()
        allowed: list[dict] = []
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValueError("Invalid graph edge")
            if not all(isinstance(edge.get(field), str) and edge[field] for field in ("from", "to", "action")):
                raise ValueError("Edge has invalid identifiers")
            if edge["from"] not in self.nodes or edge["to"] not in self.nodes:
                raise ValueError("Edge references unknown node")
            if edge.get("effect", "Allow") not in ("Allow", "Deny"):
                raise ValueError("Unsupported permission effect")
            if not isinstance(edge.get("condition_met", True), bool):
                raise ValueError("Condition status must be boolean")
            if not isinstance(edge.get("revocable", True), bool):
                raise ValueError("Revocability must be boolean")
            if edge.get("effect") == "Deny":
                deny.add(key(edge))
            elif edge.get("condition_met", True):
                allowed.append({
                    "from": edge["from"],
                    "to": edge["to"],
                    "action": edge["action"],
                    "revocable": edge.get("revocable", True),
                })

        self.edges = sorted(
            [edge for edge in allowed if key(edge) not in deny],
            key=lambda e: (e["from"], e["to"], e["action"]),
        )
        seen = set()
        for edge in self.edges:
            if key(edge) in seen:
                raise ValueError("Duplicate allow edge")
            seen.add(key(edge))

    def _check(self, source: str, target: str) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise ValueError("Source and target must be known nodes")

    def paths(
        self, source: str, target: str, *,
        max_hops: int = 8,
        max_paths: int = 100,
        removed: list[dict] | None = None,
    ) -> list[list[dict]]:
        self._check(source, target)
        if not 1 <= max_hops <= 16 or not 1 <= max_paths <= 1000:
            raise ValueError("Requested enumeration bounds exceeded")
        banned = {key(edge) for edge in (removed or [])}
        adjacency: dict[str, list[dict]] = {node: [] for node in self.nodes}
        for edge in self.edges:
            if key(edge) not in banned:
                adjacency[edge["from"]].append(edge)
        results: list[list[dict]] = []
        stack: list[tuple[str, list[dict], frozenset[str]]] = [
            (source, [], frozenset((source,)))
        ]
        while stack and len(results) < max_paths:
            node, chosen, visited = stack.pop()
            if node == target and chosen:
                results.append(chosen)
                continue
            if len(chosen) >= max_hops:
                continue
            for edge in reversed(adjacency[node]):
                if edge["to"] not in visited:
                    stack.append((edge["to"], chosen + [edge], visited | {edge["to"]}))
        return results

    def min_cut(self, source: str, target: str) -> list[dict]:
        """Find a minimum set of independently revocable edges breaking all paths.

        An edge-split residual network assigns unit capacity to revocable grants
        and infinite synthetic capacity to grants marked non-revocable.
        """
        self._check(source, target)
        if source == target or not self.edges:
            return []
        ids = {name: i for i, name in enumerate(sorted(self.nodes))}
        n = len(ids)
        inf = len(self.edges) + 1
        residual: dict[int, dict[int, int]] = {}

        def add(a: int, b: int, cap: int) -> None:
            residual.setdefault(a, {})[b] = residual.get(a, {}).get(b, 0) + cap
            residual.setdefault(b, {}).setdefault(a, 0)

        for i, edge in enumerate(self.edges):
            split = n + i
            add(ids[edge["from"]], split, 1 if edge["revocable"] else inf)
            add(split, ids[edge["to"]], inf)

        src, dst = ids[source], ids[target]
        total = 0
        while total < inf:
            previous = {src: -1}
            queue = deque([src])
            while queue and dst not in previous:
                node = queue.popleft()
                for nxt, cap in sorted(residual.get(node, {}).items()):
                    if cap > 0 and nxt not in previous:
                        previous[nxt] = node
                        queue.append(nxt)
            if dst not in previous:
                break
            gain = inf
            cursor = dst
            while cursor != src:
                prev = previous[cursor]
                gain = min(gain, residual[prev][cursor])
                cursor = prev
            cursor = dst
            while cursor != src:
                prev = previous[cursor]
                residual[prev][cursor] -= gain
                residual[cursor][prev] += gain
                cursor = prev
            total += gain

        if total >= inf:
            return []  # All-removable correction does not exist in this model.
        reachable = {src}
        queue = deque([src])
        while queue:
            node = queue.popleft()
            for nxt, cap in residual.get(node, {}).items():
                if cap > 0 and nxt not in reachable:
                    reachable.add(nxt)
                    queue.append(nxt)

        return [
            edge for i, edge in enumerate(self.edges)
            if edge["revocable"] and ids[edge["from"]] in reachable and n + i not in reachable
        ]
