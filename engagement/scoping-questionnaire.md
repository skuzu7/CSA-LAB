# Scoping questionnaire

Answered by the client. Unanswered items are treated as out of scope.

## 1. Organization and authority

1. Legal entity commissioning the work, and registration number.
2. Who owns each system in scope? If any part is hosted or operated by a third
   party (cloud, SaaS, payment processor), who can authorize testing of it?
3. Name, role and contact of the person who will sign the authorization.

## 2. Objectives

4. What decision will this assessment inform (release, audit, incident follow-up,
   customer requirement)?
5. What would be the worst realistic outcome of a breach of these systems?
6. Is there a compliance driver (for example PCI DSS, ISO/IEC 27001, SOC 2, LGPD)?

## 3. Targets

7. Applications and APIs: URLs, environments (production, staging), tech stack.
8. Authentication: roles available for testing, number of test accounts per role.
9. AI features: models and providers used, tools or data the model can reach,
   whether the model acts on behalf of users.
10. Source code access: none, read-only, or full repository with build.
11. Explicit exclusions (hosts, paths, functions, tenants, time windows).

## 4. Constraints

12. Permitted testing windows and time zone. Any change freezes?
13. Is production in scope? If so, which actions need prior approval (data
    modification, account lockout risk, load)?
14. Rate limits, WAF or bot protection that should be allow-listed or kept active.
15. Data classes present (personal data, payment data, health data, secrets) and
    handling requirements for any encountered.

## 5. AI-assisted testing

16. May the assessor use AI models to analyse target material? If yes:
    which providers are acceptable, may target source code or responses be sent
    to them, and is provider-side data retention acceptable?

## 6. Delivery

17. Report audience (engineering, executives, auditors) and language.
18. Is a retest of fixes required, and by when?
19. Named contacts for findings triage and for emergency escalation (24h phone).
