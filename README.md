
# ZTA Agentic Demo — NIST SP 800-207

**Zero Trust Architecture for AI Agent Communication**  
All 7 NIST 800-207 tenets enforced across a 4-agent fraud detection pipeline on Azure.

---

## Architecture

```
Transaction → [APIM PEP] → Agent 1 (Intake)
                             ↓ [APIM PEP — scope: agent1 only]
                           Agent 2 (Risk Scoring)
                             ↓ [APIM PEP — scope: agent2 only]
                           Agent 3 (Alert)  ← COMPROMISED IN ACT 2
                             ↓ [APIM PEP — scope: agent2+3 only]
                           Agent 4 (Compliance Logger)

Control Plane: Azure Entra ID (Policy Engine) + APIM (PEP/PA) + Key Vault
Data Plane:    Azure Container Apps (4 isolated agent services)
Telemetry:     Azure Monitor + Application Insights
```

## The 7 Tenets — Implementation

| Tenet | NIST Statement | Implementation |
|-------|---------------|----------------|
| T1 | All data sources are resources | Each agent endpoint registered in Entra ID |
| T2 | All comms secured | HTTPS + JWT Bearer on every APIM call |
| T3 | Per-session access | 5-min TTL tokens, no standing trust |
| T4 | Dynamic policy | APIM validates caller `appid` claim per route |
| T5 | Monitor all assets | `/health` endpoints + Azure Monitor |
| T6 | Dynamic auth/authz | Token revocation takes effect immediately |
| T7 | Collect telemetry | Agent 4 audit log + Azure Monitor structured logs |

---

## Setup (One Time)

### Prerequisites
- Azure subscription (fresh is fine)
- GitHub repository (private): `zta-agentic-demo`
- Azure CLI installed locally

### Step 1 — Azure Resources to Create Manually

| Resource | Name | Notes |
|----------|------|-------|
| Azure OpenAI | any | Deploy `gpt-4o` model |
| Entra ID App Registrations | `zta-agent-transaction-intake` | + 3 more (see below) |
| Key Vault | `zta-demo-keyvault` | Store all secrets here |
| API Management | `zta-demo-apim` | Developer tier, takes 20 min |
| Container Registry | `ztademoregistry` | Basic SKU |
| Container Apps Environment | `zta-demo-env` | Default settings |

**4 App Registrations** (each gets its own Client Secret stored in Key Vault):
- `zta-agent-transaction-intake` → secret name: `agent-a1-secret`
- `zta-agent-risk-scoring` → secret name: `agent-a2-secret`
- `zta-agent-alert` → secret name: `agent-a3-secret`
- `zta-agent-compliance-logger` → secret name: `agent-a4-secret`

**1 App Registration for GitHub Actions:**
- `zta-github-actions-deployer`
- Add Federated Credential: GitHub Actions, your repo, branch: `main`
- Grant `Contributor` on subscription + `AcrPush` on ACR

### Step 2 — GitHub Secrets

Add these in: Settings → Secrets and Variables → Actions

```
AZURE_CLIENT_ID          # zta-github-actions-deployer Client ID
AZURE_TENANT_ID          # Your Entra ID tenant ID
AZURE_SUBSCRIPTION_ID    # Your subscription ID
ACR_LOGIN_SERVER         # ztademoregistry.azurecr.io
APIM_BASE_URL            # https://zta-demo-apim.azure-api.net
APIM_SUBSCRIPTION_KEY    # From APIM → Subscriptions
KEYVAULT_URL             # https://zta-demo-keyvault.vault.azure.net
AOAI_ENDPOINT            # Your Azure OpenAI endpoint
AGENT1_CLIENT_ID         # Client ID of zta-agent-transaction-intake
AGENT2_CLIENT_ID         # Client ID of zta-agent-risk-scoring
AGENT3_CLIENT_ID         # Client ID of zta-agent-alert
AGENT4_CLIENT_ID         # Client ID of zta-agent-compliance-logger
APIM_SCOPE               # api://<APIM_APP_ID>/.default
```

### Step 3 — APIM Policies

After APIM provisions, apply policies from `apim/policies/`:
1. `global-policy.xml` → All APIs → Inbound (replace `YOUR_TENANT_ID`)
2. `agent2-policy.xml` → agent2-risk API (replace `AGENT1_CLIENT_ID`)
3. `agent3-agent4-policy.xml` → agent3-alert API

### Step 4 — Run Infrastructure Script

```bash
# Fill in YOUR values at the top of the script first
chmod +x infra/deploy.sh
./infra/deploy.sh
```

### Step 5 — Deploy via GitHub Actions

```bash
git add .
git commit -m "Initial ZTA agent deployment"
git push origin main
```

Watch: GitHub → Actions → "ZTA Agent Pipeline — Build & Deploy"

---

## Running the Demo

```bash
pip install requests rich
export APIM_BASE_URL=https://zta-demo-apim.azure-api.net
export APIM_SUBSCRIPTION_KEY=your_key_here
```

### Act 1 — Happy Path
```bash
python demo/trigger_transaction.py --act 1
```

### Act 2 — Breach Scenario
First, redeploy Agent 3 in compromised state:
- GitHub Actions → Run workflow → `agent3_compromised = true`

Then run:
```bash
python demo/trigger_transaction.py --act 2
```

During Act 2, when prompted, revoke Agent 3's secret in Entra ID.

### Act 3 — Recovery
```bash
python demo/trigger_transaction.py --act 3
```

---

## Project Structure

```
zta-agentic-demo/
├── .github/workflows/deploy.yml     # CI/CD — OIDC auth, no stored secrets
├── shared/zta_auth.py               # ZTA identity library (all agents use this)
├── agents/
│   ├── agent1_intake/               # Transaction Intake — external entry point
│   ├── agent2_risk/                 # Risk Scoring — internal only
│   ├── agent3_alert/                # Alert Agent — THE BREACH AGENT
│   └── agent4_logger/              # Compliance Logger — append-only
├── apim/policies/                   # APIM XML policies (JWT + scope enforcement)
├── infra/deploy.sh                  # One-time Azure wiring script
└── demo/trigger_transaction.py      # 3-Act demo script
```

---

## ZTA NPE Identity Model

Each agent is a **Non-Person Entity (NPE)** per NIST 800-207 §5.7:

| Agent | NPE Identity | Scope | Can Call |
|-------|-------------|-------|----------|
| Agent 1 | `zta-agent-transaction-intake` | intake:write | Agent 2 only |
| Agent 2 | `zta-agent-risk-scoring` | risk:read, alert:write, log:write | Agent 3, 4 |
| Agent 3 | `zta-agent-alert` | alert:write, log:write | Agent 4 only |
| Agent 4 | `zta-agent-compliance-logger` | log:append | Nobody |

**No agent can call any agent outside its defined scope. APIM enforces this on every single request.**
=======
# zta-agentic-demo
Full Walkthrough- YouTube Link : https://youtu.be/C3KR6bzc9Bk

