# Security Engineering Framework
## Applied to the ZTA Agentic AI Fraud Detection System

> **Formal Security Models · OWASP Agentic AI · NIST SP 800-207 · Azure Implementation**
> 
> Version 1.0 | February 2026

---

## Executive Summary

This document applies a Security Engineering Framework grounded in formal mathematical security models to the ZTA Agentic AI Fraud Detection system built on Microsoft Azure. The system comprises four autonomous agents communicating via Azure API Management (APIM) as the Policy Enforcement Point, governed by Microsoft Entra ID for identity, and monitored via Azure Monitor.

Formal security models — Bell-LaPadula, Biba, Clark-Wilson, and the Conservation of Complexity — are not theoretical abstractions. They are engineering mandates that map directly to real architectural decisions. This document demonstrates where each principle is already enforced in the built system and where gaps remain.

> **Key Finding:** The ZTA architecture already satisfies the most critical formal security requirements. The primary gaps are the absence of input sanitization between agents and cryptographically signed audit logs — both addressable with targeted enhancements.

---

## Table of Contents

1. [Formal Security Principles Applied to Our Architecture](#1-formal-security-principles-applied-to-our-architecture)
2. [OWASP Agentic AI Threat Mapping](#2-owasp-agentic-ai-threat-mapping)
3. [Five Engineering Mandates — Current Status](#3-five-engineering-mandates--current-status)
4. [Anti-Compatibility and the Agent Hierarchy](#4-anti-compatibility-and-the-agent-hierarchy)
5. [Prioritised Gap Analysis and Remediation Roadmap](#5-prioritised-gap-analysis-and-remediation-roadmap)
6. [What the Architecture Already Gets Right](#6-what-the-architecture-already-gets-right)

---

## 1. Formal Security Principles Applied to Our Architecture

### 1.1 Bell-LaPadula — Confidentiality (No Read Up, No Write Down)

Bell-LaPadula governs information flow confidentiality. A subject cannot read data at a higher classification level (**No Read Up**), and a subject cannot write data to a lower classification level (**No Write Down**). In our system, this maps directly to agent scope enforcement via APIM.

| Agent | Classification Level | No Read Up | No Write Down |
|-------|---------------------|------------|---------------|
| Agent 1 — Transaction Intake | HIGH — raw PII transaction data | N/A — entry point | ✅ Output scoped to Agent 2 only via APIM policy |
| Agent 2 — Risk Scoring | MEDIUM — enriched risk data | ✅ Cannot access Agent 1 raw data directly | ✅ Score passed to Agent 3 only |
| Agent 3 — Alert Agent | LOW — alert narrative only | ✅ Cannot read raw transaction or risk reasoning | ✅ Alert output only, no data written back upstream |
| Agent 4 — Compliance Logger | AUDIT — append only | ✅ Cannot read any agent output | ✅ N/A — append only, no downstream writes |

> **Where This Is Enforced:** Azure APIM XML policies restrict each agent to specific API operations. Agent 3 holds a token scoped only to the `/evaluate` endpoint — zero permission to call `/intake`. This is exactly what blocked the Act 2 breach attempt.

---

### 1.2 Biba Integrity — Chain of Command (No Write Up, No Read Down)

Biba protects data integrity. A subject cannot write to a higher integrity level (**No Write Up**) and cannot read from a lower integrity level without risking integrity contamination (**No Read Down**). In agentic systems this is the most critical model — a compromised agent must not corrupt the reasoning of a higher-integrity agent.

| Biba Rule | Agent Scenario | Current Enforcement | Gap / Risk |
|-----------|---------------|--------------------|-----------:|
| No Write Up | Agent 3 (compromised) attempts to write to Agent 1 | ✅ APIM blocks — 403 on scope violation | None |
| No Read Down | Agent 2 reads Agent 3 alert output | ✅ Data flows one-way downstream only | None |
| Integrity Chain | Agent 1 OpenAI output fed into Agent 2 | ⚠️ No integrity validation on LLM output between agents | **GAP** |
| Memory Poisoning (T1) | Malicious prompt injected via transaction payload | ⚠️ No input sanitization on Agent 1 intake | **GAP** |

> ⚠️ **Critical Gap:** The current architecture passes Azure OpenAI output from Agent 1 directly to Agent 2 without integrity validation. A prompt injection in the transaction payload could cause Agent 1 to produce a manipulated enrichment that Agent 2 accepts as high-integrity data. This violates the Biba No Read Down rule.

---

### 1.3 Clark-Wilson — Commercial Integrity (Well-Formed Transactions)

Clark-Wilson replaces military access rules with transaction-based integrity, requiring all data modifications to occur through controlled, well-formed procedures with separation of duties. This maps precisely to how our pipeline handles fraud decisions.

| Clark-Wilson Concept | Our Implementation | Status |
|---------------------|-------------------|--------|
| Constrained Data Items (CDI) | Transaction payload, risk score, alert narrative, audit log | ✅ Each is a constrained output — agents cannot modify other agents' outputs |
| Unconstrained Data Items (UDI) | Raw inbound transaction from external client | ✅ Agent 1 treats all incoming transactions as untrusted UDI |
| Transformation Procedures (TP) | Each agent's processing function | ✅ Each TP is isolated in a separate container with its own identity |
| Separation of Duties | No single agent can complete the full pipeline alone | ✅ Agent 3 cannot score. Agent 2 cannot log. Enforced by APIM scope. |
| Access Triple (user, TP, CDI) | APIM enforces: Agent identity + permitted operation + permitted data | ✅ JWT scope in APIM policy implements the Clark-Wilson access triple exactly |

---

### 1.4 Strong Tranquility Principle

Strong Tranquility mandates that the security classification of a subject or object cannot change while it is being referenced. In agentic systems this prevents **Goal Drifting** — an agent whose intent is dynamically altered mid-execution by a prompt injection or adversarial input.

**Current Status:** Partially enforced. Each agent container has a fixed identity (NPE-ID) and fixed APIM scope that cannot change at runtime — satisfying Strong Tranquility at the identity and permission layer.

**Gap:** The agent's internal reasoning state — its prompt context and planning phase — is not governed by Strong Tranquility. A prompt injection in a transaction payload could redirect Agent 1's planning mid-execution without changing its token. This maps directly to OWASP T6 Intent Breaking.

> **Recommendation:** Implement a prompt integrity wrapper on Agent 1 that hashes the system prompt at startup and verifies it before every inference request. Any deviation triggers an alert and rejects the transaction.

---

### 1.5 Computer Security Intermediate Value Theorem (CS-IVT)

CS-IVT states that if two systems of different security levels communicate through a network, the intermediate platform must be multilevel secure. If it is not, the entire architecture collapses to the lowest security level.

In our architecture, Agent 1 (HIGH — raw PII) communicates with Agent 2 (MEDIUM — risk score) through Azure APIM. CS-IVT requires APIM to be a multilevel secure platform.

> ✅ **CS-IVT Satisfied:** Azure APIM is a multilevel secure intermediate platform. It enforces different JWT scopes per agent, validates each token independently, and applies separate inbound policies per API. It does not simply pass traffic — it evaluates, validates, and transforms based on the caller's security level.

---

### 1.6 Conservation of Complexity

The Conservation of Complexity states that security complexity cannot be eliminated — only relocated. Moving autonomy to agents does not reduce the attack surface; it concentrates the formal verification burden on specific nodes.

| Where Complexity Lives | Our Architecture | Risk if This Node Fails |
|-----------------------|-----------------|------------------------|
| APIM — Policy Enforcement Point | All JWT validation, scope checking, routing logic | Total pipeline access collapse |
| Entra ID — Policy Engine | All token issuance and NPE identity management | All agent identities compromised |
| Agent 1 — Entry Point | All external input validation | Prompt injection — all downstream agents receive poisoned data |
| Super Agent (future) | Orchestration, health monitoring, failover | Single point of total system integrity collapse |

> ⚠️ **Super Agent Warning:** Adding a Super Agent concentrates complexity at a single orchestration node. Per the Conservation of Complexity, this does not reduce total system risk — it relocates it. The Super Agent must itself be hardened to the highest security standard with its own NPE identity, APIM policy, and immutable audit trail.

---

## 2. OWASP Agentic AI Threat Mapping

Every OWASP Agentic AI threat is a specific attempt to violate a formal security axiom. The following table maps each threat to its formal principle violation and documents current enforcement status.

| OWASP Threat | Formal Principle Violated | Attack Scenario | Current Enforcement | Gap |
|-------------|--------------------------|-----------------|--------------------|----|
| T1 — Memory Poisoning | Biba Integrity | Malicious transaction payload corrupts Agent 1 context | ❌ No input sanitization | **HIGH RISK** |
| T2 — Tool Misuse | Bell-LaPadula No Write Down | Agent instructed to exfiltrate Key Vault secrets | ⚠️ APIM blocks non-policy calls | Add outbound whitelist |
| T3 — Privilege Compromise | Bell-LaPadula | Agent 3 attempts to inherit Agent 1 scope via JWT | ✅ Entra ID issues static scoped tokens | None |
| T5 — Cascading Hallucination | Biba No Read Down | Agent 1 hallucination accepted as truth by Agent 2 | ❌ No cross-agent output validation | **HIGH RISK** |
| T6 — Intent Breaking | Tranquility Principle | Prompt injection redirects Agent 1 planning | ❌ No system prompt integrity check | **MEDIUM** |
| T11 — Unexpected RCE | Anti-Compatibility | Generated code requests elevated permissions | ✅ Containers non-root, APIM blocks elevated calls | Low |
| T12 — Agent Communication Poisoning | Biba Integrity Chain | Compromised Agent 3 injects malicious data into audit stream | ✅ Agent 4 is append-only | Low |
| T13 — Rogue Agents | Conservation of Complexity | Super Agent compromised — total orchestration collapse | ⚠️ Not yet applicable | Future |
| T16 — Protocol Abuse | Anti-Compatibility | MCP/A2A protocol payload manipulated to bypass APIM | ✅ All calls via APIM with JWT validation | None |

---

## 3. Five Engineering Mandates — Current Status

### Mandate 1 — Strict Identity (NHI Management)

> ✅ **FULLY IMPLEMENTED**

Each agent has a dedicated Entra ID App Registration with a unique Client ID (NPE identity). Secrets are stored in Azure Key Vault and accessed per-session. Short-lived JWT tokens are issued per call. No standing permissions.

| Agent | Client ID | Secret Storage | Token Lifetime |
|-------|-----------|---------------|----------------|
| Agent 1 — Transaction Intake | `6be12855-69e2-4f09-aac9-d876526bc7b9` | Key Vault — agent-a1-secret | Short-lived per session |
| Agent 2 — Risk Scoring | `bd56e8ab-f092-446f-837c-d1dfdc8c86e4` | Key Vault — agent-a2-secret | Short-lived per session |
| Agent 3 — Alert Agent | `50a80c80-5739-43c1-b0f8-2db667bf01d9` | Key Vault — agent-a3-secret | Short-lived per session |
| Agent 4 — Compliance Logger | `60fd7998-1eb0-460b-8aba-9d9503541d4a` | Key Vault — agent-a4-secret | Short-lived per session |

---

### Mandate 2 — Memory Sanitization and Integrity

> ❌ **GAP — NOT YET IMPLEMENTED**

The current architecture passes LLM output directly between agents without sanitization. Agent 1 OpenAI output is forwarded to Agent 2 as trusted data. This violates the Biba Integrity mandate and creates a cascading hallucination pathway (T5).

**Required implementation:**
- Add a sanitization wrapper on Agent 1 output before forwarding to APIM
- Validate OpenAI response against a defined JSON schema — reject malformed or unexpected outputs
- Implement confidence threshold check — flag for human review if below threshold
- Reset agent context to known good state after each transaction — no cross-transaction memory leakage

---

### Mandate 3 — Cryptographic Traceability

> ⚠️ **PARTIAL — Logs exist but are not cryptographically signed**

Azure Monitor captures all agent calls with Correlation IDs. Agent 4 writes an append-only audit trail. However logs are not cryptographically signed and do not include the full chain-of-thought reasoning path from each OpenAI call.

**Required enhancements:**
- Sign each Agent 4 log entry with an Azure Key Vault-managed key
- Include the full OpenAI reasoning trace (chain-of-thought) in the log payload
- Store logs in Azure Immutable Blob Storage with WORM policy
- Generate a hash of each log entry and include it in the next — tamper-evident chain

---

### Mandate 4 — Sandboxed Code Execution

> ✅ **LARGELY SATISFIED**

All four agents run in Azure Container Apps with isolated compute environments. Containers run as non-root. APIM blocks any API calls not in the defined policy.

**Recommendation:** If Azure OpenAI tool calling or code interpreter is enabled in future, wrap all generated code execution in an ephemeral Azure Container Instance with zero network egress and a maximum execution time limit.

---

### Mandate 5 — Multi-Agent Consensus Verification

> ❌ **NOT IMPLEMENTED — Recommended for Version 2**

The current architecture has no consensus mechanism. A single Agent 2 risk score determines downstream action with no secondary verification. For a banking system processing real financial decisions, this creates a single point of reasoning failure.

**Recommended implementation:**
- Deploy a secondary risk scoring model (Agent 2b) running in parallel with different parameters
- Require both Agent 2 and Agent 2b scores to agree within a tolerance band before Agent 3 is invoked
- Disagreement triggers human-in-the-loop escalation rather than automated alert
- The consensus coordinator becomes the foundation of the Super Agent architecture

---

## 4. Anti-Compatibility and the Agent Hierarchy

The Anti-Compatibility Principle states that sensitivity must be monotonically non-increasing as one moves away from the root process. In our architecture, Agent 1 is the root — it handles the highest sensitivity data. All downstream agents must operate at equal or lower sensitivity.

```
Agent 1 (ROOT) — HIGH sensitivity — Raw PII, transaction data
    │
    ▼ via APIM (MULTILEVEL SECURE — CS-IVT satisfied)
    │
Agent 2 — MEDIUM sensitivity — Enriched data, no raw PII
    │
    ├──▶ Agent 3 — LOW sensitivity — Alert narrative only
    │
    └──▶ Agent 4 — AUDIT — Metadata only, append-only
```

The Super Agent design must be approached carefully. An orchestrator that manages all four agents necessarily handles data at all sensitivity levels simultaneously — making it a multilevel subject that must be engineered to the strictest Bell-LaPadula and Biba standards.

---

## 5. Prioritised Gap Analysis and Remediation Roadmap

| Priority | Gap | Formal Principle | OWASP Threat | Remediation | Effort |
|----------|-----|-----------------|-------------|-------------|--------|
| **P1 — Critical** | No input sanitization on Agent 1 | Biba Integrity | T1, T5 | JSON schema validation + prompt guard before OpenAI call | Medium |
| **P1 — Critical** | LLM output passed between agents without validation | Biba No Read Down | T5 | Output schema validation + confidence threshold check | Medium |
| **P2 — High** | No cryptographic signing of audit logs | Cryptographic Traceability | T8 | Key Vault signing + Immutable Blob Storage | Medium |
| **P2 — High** | No system prompt integrity check | Tranquility Principle | T6 | Hash system prompt at startup, verify before every inference | Low |
| **P3 — Medium** | No outbound call restriction on agents | Bell-LaPadula No Write Down | T2 | APIM outbound policy — whitelist only permitted egress | Low |
| **P3 — Medium** | No multi-agent consensus on risk decisions | Conservation of Complexity | T13 | Deploy Agent 2b for consensus on high-risk scores | High |
| **P4 — Future** | Super Agent not hardened | Conservation of Complexity | T13 | Engineer Super Agent to multilevel secure standard | High |

---

## 6. What the Architecture Already Gets Right

The core ZTA architecture already satisfies the most critical formal security requirements:

- ✅ **NHI Identity Management (Mandate 1):** Every agent has a cryptographic identity, a scoped token, and a secret stored in Key Vault. No human credentials anywhere in the pipeline.

- ✅ **CS-IVT Compliance:** APIM as the multilevel secure intermediate platform satisfies CS-IVT exactly. It enforces different security levels per API — it does not collapse to the lowest common denominator.

- ✅ **Bell-LaPadula Scope Enforcement:** APIM XML policies enforce No Read Up and No Write Down at the API level. Agent 3 cannot read Agent 1 data. This is the principle that stopped the Act 2 breach.

- ✅ **Clark-Wilson Access Triples:** APIM JWT scope + agent identity + permitted endpoint implements the Clark-Wilson access triple in every single call.

- ✅ **Anti-Compatibility Pipeline:** The four-agent pipeline is naturally monotonically non-increasing in sensitivity from root (Agent 1) to leaf (Agent 3/4). The architecture satisfies the Anti-Compatibility principle by design.

- ✅ **Sandboxed Execution (Mandate 4):** Azure Container Apps provides isolated compute with non-root containers. The CI/CD pipeline uses OIDC — zero stored secrets.

---

## Closing Observation

> *The Conservation of Complexity does not work against this architecture — it validates it.*

The complexity of securing four autonomous AI agents has not been eliminated. It has been deliberately concentrated in three hardened, auditable, managed Azure services — APIM, Entra ID, and Key Vault — rather than distributed invisibly across agent code.

That is not a weakness. That is the correct engineering decision.

As AI autonomy increases, the Conservation of Complexity dictates that the engineering rigor required to secure these systems grows proportionally. Shifting autonomy to agents does not eliminate risk — it concentrates the requirement for formal defence within the architectural framework and protocol validation layers.

---

*Built with Azure Container Apps · APIM · Entra ID · Key Vault · Azure OpenAI · GitHub Actions OIDC*

*Repository: [github.com/Anishia-Canada/zta-agentic-demo](https://github.com/Anishia-Canada/zta-agentic-demo)*
