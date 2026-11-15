# Institutional-readiness evidence map

**Status: internal controls roadmap, not an accreditation. Reviewed 2026-11-15.**

This public repository demonstrates *first-party, synthetic, defensive research*. It does **not** demonstrate government affiliation, a government contract, external penetration-testing authority, accepted CVEs, ISO 27001 certification, NIST compliance, or admission to Anthropic's Cyber Verification Program (CVP).

## Decision boundaries

| Goal | Evidence in this repository | Evidence still needed outside GitHub |
| --- | --- | --- |
| Individual defensive researcher | Scoped local vulnerability demonstrations; CI; documented agent-safety experiments | True identity and account verification; independently attributable reporting history where required; provider approval |
| Organizational red team | Research methodology and sample rules of engagement only | Verified operating organization; qualified personnel; contracts/authorized assessments; managed endpoints, identity and network controls; provider review |
| Specialized critical-infrastructure research | No live infrastructure testing claimed | Real critical-infrastructure operator authorization, narrowly defined necessity, enhanced verification and review; provider decision |

See [control register](../governance/controls.json), checked by [validator](../governance/validate.py) in CI. Status `demonstrated_local` means that a **local file exists**, not that a regulator or third party independently audited the control.

## Evidence controls and responsibility

1. **Authorization before testing:** owner, legal authority, systems, explicit permission, methods, time window, emergency stop contact and exclusions must all be recorded before any non-local engagement. See [AUTHORIZATION.md](../AUTHORIZATION.md) and [rules of engagement](../engagement/rules-of-engagement.md).
2. **Classification and handling:** only synthetic/public data is permitted in this Git repository. Do not upload credentials, sensitive customer data, government documents or unpatched third-party vulnerability details. Classify restricted material in the client's own approved records environment, not GitHub.
3. **Execution boundaries:** current experiments are localhost-only; do not interpret a Python authorization decision as OS sandboxing, outbound firewall enforcement, endpoint protection or secure production deployment.
4. **Reproducibility:** reference the exact commit, test run, dataset digest, tool versions, expected and observed results, negative controls, and limitations. Store sanitized evidence only.
5. **Review and release:** use pull requests, check CI status, secure code review, dependency analysis and explicit approval before merging changes that expand scope.
6. **Incidents:** stop the experiment; preserve access-limited evidence; revoke affected credentials; contact the owner using the signed engagement process; do not publish details before coordinated disclosure.
7. **External validation:** link the original independent maintainer review, accepted report or issued credential. Do not turn a self-authored file or synthetic test into a claimed government or vendor qualification.

## Institutional control families to implement *outside* this repository

- Verifiable legal entity and authorized officers; customer contracts and procurement compliance.
- Identity provider with phishing-resistant MFA, least privilege, short-lived credentials and removal of departed users.
- Managed endpoints, encryption at rest, patch management and endpoint protection.
- Enforced network egress allowlists, logging, incident detection and retention policy.
- Secure development lifecycle, software inventory/SBOM, dependency remediation and release provenance.
- Risk assessments, third-party review, business continuity and disaster recovery exercises.
- Personnel screening only where legally permitted and proportionate; written responsibilities and ethics policy.
- For critical infrastructure: independent operator authorization, an approved test plan and strict safety constraints.

These are **engineering objectives**, not current attestations. Use NIST SSDF, NIST SP 800-53, OWASP SAMM and relevant Brazilian privacy/security law as reference frameworks; claiming certification requires a separate qualified assessment.

## Evidence advancement workflow

To promote a control from `planned` to `demonstrated_local`, attach an inspectable file containing a reproducible test or reviewed policy plus its limitations. To claim independent verification, record the **actual external authority, public verifiable record and date**, and obtain permission to disclose. Only the provider can determine CVP admission.

**Next independent milestones:** externally reviewed upstream security patch; acknowledged authorized disclosure; live model evaluation with exact model/dataset and repeatability; organization/contract evidence when it exists. Nothing here authorizes third-party testing.
