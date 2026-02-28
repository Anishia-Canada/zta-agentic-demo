---
name: "🛡️ Agent Vetting Request"
about: "Human-in-the-Loop design gate — must be completed and approved before any new agent is coded, deployed, or given an identity in Entra ID."
title: "[HVC] Agent Name — Vetting Request"
labels: ["hvc-pending", "design-gate", "human-review-required"]
assignees: ""
---

<!-- ═══════════════════════════════════════════════════════════════
     HUMAN VETTING CERTIFICATE (HVC) REQUEST
     ZTA Agentic AI Fraud Detection System
     
     ⚠️  This form must be completed BEFORE:
         - Any code is written for this agent
         - Any Entra ID App Registration is created
         - Any APIM policy is written
         - Any container is built or deployed
         
     A Human Vetting Certificate (HVC) ID will be assigned
     upon approval. All downstream artifacts must reference
     this HVC ID.
═══════════════════════════════════════════════════════════════ -->

## 1. Agent Identity

| Field | Value |
|-------|-------|
| **Proposed Agent Name** | <!-- e.g. Super Agent — Orchestrator --> |
| **Proposed NPE-ID** | <!-- e.g. A5 --> |
| **Proposed by** | <!-- GitHub username --> |
| **Date of request** | <!-- YYYY-MM-DD --> |
| **Target deployment date** | <!-- YYYY-MM-DD --> |

---

## 2. Sensitivity Classification

> Reviewer must validate this classification against Bell-LaPadula before approving.

- [ ] 🔴 **HIGH** — Handles raw PII, account data, or credentials
- [ ] 🟡 **MEDIUM** — Handles enriched or derived data (no raw PII)
- [ ] 🟢 **LOW** — Handles output narratives or alerts only
- [ ] 🔵 **AUDIT** — Append-only logging, no data read permissions

**Justification for this classification:**
```
<!-- Explain why this classification level is appropriate.
     What data will this agent touch? Why not higher/lower? -->
```

---

## 3. Data Flow — What This Agent Receives and Sends

> Reviewer must validate this flow does not violate Bell-LaPadula (No Read Up / No Write Down).

### Inbound — Data this agent will RECEIVE

| From | Via | Data Type | Sensitivity Level of Source |
|------|-----|-----------|----------------------------|
| <!-- e.g. Agent 2 --> | <!-- APIM --> | <!-- e.g. Risk score --> | <!-- MEDIUM --> |

### Outbound — Data this agent will SEND

| To | Via | Data Type | Sensitivity Level of Destination |
|----|-----|-----------|----------------------------------|
| <!-- e.g. Agent 3 --> | <!-- APIM --> | <!-- e.g. Orchestration command --> | <!-- LOW --> |

**Does this flow comply with Bell-LaPadula No Write Down?**
- [ ] Yes — this agent does not send higher-sensitivity data to a lower-sensitivity destination
- [ ] No — explain below

```
<!-- If No, provide justification or proposed mitigation -->
```

---

## 4. Proposed Scope and Permissions

> This is the exact list of API endpoints this agent will be permitted to call.
> Reviewer must confirm nothing beyond this list is required or permitted.

```
<!-- List every API endpoint this agent needs. Be specific.
     Example:
     - POST /agent2-risk/evaluate     (call Agent 2 risk scorer)
     - POST /agent4-logger/log        (write to compliance logger)
     - GET  /agent1-intake/health     (health check only — read)
     
     Anything NOT listed here will be blocked by APIM policy. -->
```

**Principle of Least Privilege confirmation:**
- [ ] This is the minimum scope required for this agent to function
- [ ] No broader permissions have been requested "just in case"
- [ ] Each permission has a specific, documented use case above

---

## 5. Biba Integrity Assessment

> Reviewer must confirm this agent cannot corrupt higher-integrity agents.

**Can this agent write to a higher-integrity agent? (No Write Up)**
- [ ] No — this agent has no write permissions to higher-classified agents
- [ ] Yes — explain and justify:

```
<!-- If yes, this is a Biba violation. Provide mitigation. -->
```

**Can this agent read from a lower-integrity source without sanitization? (No Read Down)**
- [ ] No — all inputs are from equal or higher integrity sources
- [ ] Yes — sanitization layer is in place:

```
<!-- Describe the sanitization mechanism -->
```

---

## 6. Strong Tranquility Confirmation

> Reviewer must confirm this agent's classification and intent cannot change mid-execution.

- [ ] This agent's security classification is fixed and cannot change at runtime
- [ ] This agent's system prompt will be hashed at startup and verified before every inference call
- [ ] This agent has no mechanism to accept dynamic role changes via input

**If any of the above are unchecked, describe the mitigation:**
```
<!-- Mitigation plan -->
```

---

## 7. Identity and Secret Management

| Field | Value |
|-------|-------|
| **Entra ID App Registration name** | <!-- e.g. zta-agent-superagent --> |
| **Key Vault secret name** | <!-- e.g. agent-a5-secret --> |
| **Secret rotation period** | <!-- e.g. 6 months --> |
| **Token scope requested** | <!-- e.g. https://management.azure.com/.default --> |

- [ ] A new, dedicated Entra ID App Registration will be created for this agent (no shared identities)
- [ ] The client secret will be stored in Azure Key Vault only — never in code or environment variables
- [ ] Token lifetime will be short-lived and per-session only

---

## 8. APIM Policy Outline

> Provide a plain-English description of the APIM policy that will govern this agent.
> The actual XML policy must reference the HVC ID once assigned.

```
<!-- Example:
     - Inbound: Validate JWT Bearer token from Entra ID
     - Inbound: Check scope claim matches 'agent-a5-scope'
     - Inbound: Assign Correlation ID header
     - Outbound: Strip internal headers before response
     - On-error: Return 401 with ZTA error message -->
```

---

## 9. Threat Assessment

> Reviewer must confirm the agent has been assessed against OWASP Agentic AI threats.

| Threat | Applicable? | Mitigation |
|--------|-------------|------------|
| T1 — Memory Poisoning | <!-- Yes/No --> | <!-- Mitigation --> |
| T3 — Privilege Compromise | <!-- Yes/No --> | <!-- Mitigation --> |
| T6 — Intent Breaking | <!-- Yes/No --> | <!-- Mitigation --> |
| T13 — Rogue Agent (if Super Agent) | <!-- Yes/No --> | <!-- Mitigation --> |

---

## 10. Reviewer Sign-Off

> To be completed by the designated Human Reviewer only.
> Do NOT fill this section in as the requester.

**Reviewer ID (HV-XXX):** _______________

**Decision:**
- [ ] ✅ APPROVED — HVC ID assigned below
- [ ] 🔄 CHANGES REQUESTED — see comments
- [ ] ❌ DENIED — see comments

**Human Vetting Certificate ID:** `HVC-AX-YYYY-XXX`

**Conditions of approval (if any):**
```
<!-- Any conditions that must be met before code starts -->
```

**Reviewer signature (GitHub username + date):** _______________

---

<!-- ═══════════════════════════════════════════════════════════════
     ONCE APPROVED — the HVC ID must be referenced in:
     
     ✅ Entra ID App Registration description field
     ✅ APIM policy XML header comment
     ✅ GitHub Pull Request description
     ✅ Container App environment variable: HVC_ID
     ✅ Every Agent 4 audit log entry
     ✅ SECURITY_FRAMEWORK.md agent registry
     
     No HVC = No code. No code = No deployment.
═══════════════════════════════════════════════════════════════ -->
