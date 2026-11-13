# Security services

Independent application-security work by [@skuzu7](https://github.com/skuzu7),
delivered to the same evidence standard as this repository: every finding
reproducible, every fix retested, every severity computed.

[Português (Brasil)](#serviços-de-segurança-pt-br)

## What I do

| Service | You get | See an example |
| --- | --- | --- |
| **Web and API security assessment** | Manual testing of your application against the OWASP Top 10 and API Top 10 classes; report with root cause, proof, CVSS vector and fix per finding | [Sample report](reports/sample-assessment-report.md) |
| **Fix and retest** | Minimal patches or patch guidance, plus a regression test per finding that proves the flaw is gone and the feature still works | [Patched build](remediation/patched_app.py), [regression suite](tests/regression/test_fixes.py) |
| **Detection rules for what was found** | Sigma rules for each confirmed attack, validated against replayed traffic, with documented false positives and blind spots | [Detections](detections/README.md) |
| **AI agent and LLM application review** | Threat model of the agent's tools and data, prompt-injection test cases, and a host-side authorization gate design so the model cannot act outside its task | [TRACEGUARD](agent_replay_lab/README.md), [scoped agent evals](agent_evals/README.md) |

## How an engagement runs

1. **Scope** — you answer the [scoping questionnaire](engagement/scoping-questionnaire.md).
2. **Authorize** — we both sign the [rules of engagement](engagement/rules-of-engagement.md). No signature, no testing.
3. **Test** — within the agreed window and limits, under the [operating standard](engagement/operating-standard.md).
4. **Report** — findings ranked by computed severity, with reproduction and fixes.
5. **Retest** — your fixes are verified and the report is updated per finding.

Price and duration are quoted after step 1, per scope.

## What I do not claim

This repository is a lab and a portfolio. It contains no client data and
describes no paid engagement, CVE, bug-bounty award or third-party certification.
The planted vulnerabilities are educational fixtures. If you need references
from prior commercial work, ask — I will tell you plainly what exists.

## Contact

[LinkedIn](https://br.linkedin.com/in/antonioccjr) · [GitHub](https://github.com/skuzu7)

---

## Serviços de segurança (PT-BR)

Trabalho independente de segurança de aplicações, entregue com o mesmo padrão de
evidência deste repositório: todo achado reproduzível, toda correção retestada,
toda severidade calculada.

| Serviço | O que você recebe | Exemplo |
| --- | --- | --- |
| **Avaliação de segurança web e API** | Teste manual da aplicação nas classes do OWASP Top 10 e API Top 10; relatório com causa raiz, prova, vetor CVSS e correção por achado | [Relatório-modelo](reports/sample-assessment-report.md) |
| **Correção e reteste** | Patches mínimos ou orientação de correção, com um teste de regressão por achado provando que a falha sumiu e a funcionalidade continua | [Build corrigido](remediation/patched_app.py), [regressão](tests/regression/test_fixes.py) |
| **Regras de detecção para o que foi encontrado** | Regras Sigma para cada ataque confirmado, validadas com tráfego reproduzido, com falsos positivos e pontos cegos documentados | [Detecções](detections/README.md) |
| **Revisão de agentes de IA e aplicações com LLM** | Modelo de ameaças das ferramentas e dados do agente, casos de teste de prompt injection e desenho de um controle de autorização no host | [TRACEGUARD](agent_replay_lab/README.md) |

**Como funciona:** escopo ([questionário](engagement/scoping-questionnaire.md)) →
autorização assinada ([regras de engajamento](engagement/rules-of-engagement.md)) →
teste → relatório → reteste. Sem autorização por escrito do dono do sistema, não
há teste. Preço e prazo são definidos após o escopo.

**O que não afirmo:** este repositório é um laboratório e um portfólio. Não há
dados de clientes, CVE, premiação de bug bounty nem certificação de terceiros
descritos aqui.

**Contato:** [LinkedIn](https://br.linkedin.com/in/antonioccjr) · [GitHub](https://github.com/skuzu7)
