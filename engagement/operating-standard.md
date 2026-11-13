# Operating standard for client engagements

The controls an assessor working from this repository's methodology must meet
before touching a client system. Written as requirements, not as a description
of any past engagement. Clients may ask for evidence of any item.

## 1. Authorization

- **OS-1** No testing without signed [rules of engagement](rules-of-engagement.md)
  naming every target and its owner.
- **OS-2** Scope changes are made in writing before the corresponding test, never
  after.

## 2. Accounts and devices

- **OS-3** Phishing-resistant multi-factor authentication (FIDO2 hardware
  security key) on every account that holds engagement data or reaches client
  systems: code hosting, email, cloud storage, AI providers.
- **OS-4** Engagement work is done on a device with full-disk encryption,
  automatic screen lock, a supported and patched operating system, and no shared
  user accounts.
- **OS-5** Client credentials are stored only in a password manager, never in
  notes, chat, source control or AI prompts.

## 3. Data

- **OS-6** Collect the minimum evidence that proves a finding. Personal data and
  secrets are masked at capture.
- **OS-7** Engagement data is kept in encrypted storage separate from personal
  and public material, and is never committed to a public repository.
- **OS-8** Data is deleted at the retention date in the rules of engagement and
  the deletion is confirmed to the client in writing.
- **OS-9** Suspected exposure of client data is reported to the client within
  24 hours.

## 4. AI-assisted work

- **OS-10** AI models are used on client material only with the permission
  recorded in the rules of engagement, and only through providers the client
  accepted.
- **OS-11** Every action against a client system is reviewed and issued by a
  human. Models propose; they do not act on targets autonomously.
- **OS-12** Offensive-security assistance is requested from AI providers only for
  targets with written authorization, within the provider's usage policy and any
  vetted-access programme terms, including provider-side retention where required.
- **OS-13** Prompts and outputs that informed a finding are retained with the
  engagement record so conclusions can be audited.

## 5. Evidence and reporting

- **OS-14** Every finding is reproducible from the report: request, response,
  affected code or configuration, and timestamp.
- **OS-15** Severity is stated as a CVSS vector and computed score, with the
  scoring assumptions written down.
- **OS-16** Fixes are retested, and the retest result is reported per finding.

## 6. Disclosure

- **OS-17** Client findings are confidential to the client.
- **OS-18** Vulnerabilities found in third-party software during an engagement
  are reported to that vendor through coordinated disclosure, with the client's
  knowledge, on a default 90-day timeline.
