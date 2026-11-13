# CLOUD-PATH — Offline IAM and RBAC Privilege Graph Research

CloudPath is a **synthetic graph-model security experiment**. It identifies chains of allowed transitions between identities, delegated roles and simulated high-impact resources, then computes a minimum set of removable permission edges that would sever every path in the modeled graph.

It does not read a real cloud account, authenticate to AWS or Kubernetes, deploy tooling, read secrets, or execute any request.

## Proof of concept

```sh
python -m unittest discover -s cloudpath/tests -p 'test_*.py' -v
python -m cloudpath.benchmark --output cloudpath-report.json
```

Uses only Python 3.11 stdlib. `fixtures/synthetic-org.json` includes a 4-hop access chain, an explicitly denied identity transition and an authorized public-document read.

**Core abilities:** stable path enumeration, maximum path length and result bounds, deny precedence for exact triples, condition-not-met rejection, cycle prevention, source-to-target diagnostics, and an exact **edge-level minimum s-t cut** over independently revocable grants. Non-revocable edges receive effectively infinite capacity. Results are deterministic and JSON serializable.

## Research questions and challenge milestones

1. Does a permission graph uncover privilege paths hidden across layered identity or role declarations?
2. Can a minimal-cut recommendation reduce excessive grants without breaking an approved workflow?
3. How much worse do false positives/negatives become once real-world conditions, wildcard scopes, Kubernetes aggregation and policy versioning are added?

**Extreme next stage:** build a real *offline* Terraform/IAM JSON and Kubernetes RBAC manifest parser, implement IAM policy intersection/denial and trust policy semantics, map graph edges to source file/line, add SAT/SMT model-checking of constraints, and benchmark against hundreds of labeled synthetic organizations with precision/recall and policy-diff verification.

## Boundaries

This engine models already-resolved allow/deny graph edges. **It is not an authoritative AWS IAM evaluator or Kubernetes RBAC emulator.** Real IAM has policy combinations, wildcard principals, conditions and organizational boundaries that cannot be safely inferred from this simple graph. A displayed path indicates possible reachability in the fixture model, not a confirmed exploitable cloud misconfiguration. A minimum cut is a suggested policy removal, not an automatically safe production change.

No live targets, user identities, credentials or production data are present. Authorized scope is defined by [AUTHORIZATION.md](../AUTHORIZATION.md).
