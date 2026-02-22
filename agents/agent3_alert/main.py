"""
Agent 3 — Alert Agent
NPE Identity: zta-agent-alert

Responsibilities:
  - Receives ONLY the risk score (not raw transaction data) from Agent 2
  - Calls Azure OpenAI to generate human-readable alert narrative
  - Writes alert to alert store

ZTA Tenets demonstrated:
  Tenet 1: Protected resource with narrow scope
  Tenet 2: All comms secured — cannot reach raw data even if compromised
  Tenet 3: Per-session token — revocation takes effect immediately
  Tenet 4: Dynamic policy — APIM checks scope on every call
  Tenet 6: THIS IS THE AGENT THAT GETS COMPROMISED IN ACT 2
           When its token is revoked in Entra ID, the next call fails
           and the entire breach attempt is blocked and logged

*** DEMO BREACH SCENARIO ***
In Act 2, this agent will attempt to call Agent 1's /intake endpoint
directly — a scope violation. APIM will block it (403).
Then its Entra ID token will be revoked.
All subsequent calls from this agent will fail with 401.
The rest of the pipeline (Agents 1, 2, 4) continue unaffected.
This demonstrates blast radius = zero under ZTA.
"""

import os
import uuid
import json
import logging
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from openai import AzureOpenAI
from typing import Optional, List
import sys

sys.path.append("/app/shared")
from zta_auth import ZTAIdentity, ZTAAuthorizationError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent3_alert")

app = FastAPI(title="ZTA Agent 3 — Alert Agent")

identity = ZTAIdentity(agent_id="agent3-alert")

aoai_client = AzureOpenAI(
    azure_endpoint=os.environ["AOAI_ENDPOINT"],
    api_key=os.environ["AOAI_API_KEY"],
    api_version="2024-02-01"
)
AOAI_DEPLOYMENT = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o")

# In-memory alert store (would be Azure Cosmos DB in production)
alert_store: List[dict] = []

# ═══════════════════════════════════════════════════════════════════
# BREACH SIMULATION FLAG
# Set via environment variable: AGENT3_COMPROMISED=true
# When true, agent attempts unauthorized data access (scope violation)
# This triggers APIM 403, which triggers Entra ID revocation in demo
# ═══════════════════════════════════════════════════════════════════
IS_COMPROMISED = os.environ.get("AGENT3_COMPROMISED", "false").lower() == "true"


class RiskScorePayload(BaseModel):
    transaction_id: str
    user_id: str
    risk_score: int
    risk_level: str
    risk_factors: List[str]
    recommendation: str
    scoring_reasoning: str
    correlation_id: str
    scoring_agent: str


@app.get("/health")
async def health():
    """Tenet 5: Health + compromise status visible to monitoring"""
    return {
        "agent": "agent3-alert",
        "status": "COMPROMISED" if IS_COMPROMISED else "healthy",
        "zta_identity": identity.client_id,
        "compromise_flag": IS_COMPROMISED  # Visible in monitoring dashboard
    }


@app.post("/evaluate")
async def evaluate_and_alert(
    payload: RiskScorePayload,
    request: Request,
    x_agent_id: str = Header(default=None),
    x_correlation_id: str = Header(default=None)
):
    """
    Alert evaluation endpoint.

    Tenet 4: APIM has validated Agent 2's scope before we get here
    Tenet 6: If token revoked, this endpoint will return 401 on next call
    """
    correlation_id = x_correlation_id or payload.correlation_id

    # ═══════════════════════════════════════════════════════════════
    # ACT 2: BREACH SIMULATION
    # When compromised, agent attempts to access raw transaction data
    # from Agent 1 — a clear scope violation.
    # APIM will return 403. This is logged and surfaced to the demo.
    # ═══════════════════════════════════════════════════════════════
    if IS_COMPROMISED:
        identity.audit_log("⚠️  BREACH_ATTEMPT_INITIATED", {
            "message": "Compromised agent attempting unauthorized data access",
            "target": "agent1-intake /intake (SCOPE VIOLATION)",
            "correlation_id": correlation_id
        }, level="ERROR")

        try:
            # This call WILL FAIL — Agent 3 has no scope to call Agent 1
            # APIM policy: agent3 scope = alert:write only
            unauthorized_payload = {
                "transaction_id": payload.transaction_id,
                "breach_attempt": True
            }
            identity.call_agent(
                target_endpoint="/agent1-intake/intake",  # UNAUTHORIZED
                payload=unauthorized_payload,
                correlation_id=correlation_id
            )
        except ZTAAuthorizationError as e:
            # ✅ ZTA WORKS — breach blocked by APIM PEP
            identity.audit_log("🛡️  BREACH_BLOCKED_BY_ZTA", {
                "message": "APIM (PEP) denied unauthorized scope access",
                "error": str(e),
                "tenet_enforced": "Tenet 4 — Dynamic Policy + Tenet 6 — Dynamic AuthZ",
                "correlation_id": correlation_id
            }, level="ERROR")

            # In the demo, at this point the presenter revokes the token in Entra ID
            # Subsequent calls to /evaluate will return 401

            return JSONResponse(
                status_code=403,
                content={
                    "status": "BREACH_BLOCKED",
                    "message": "ZTA prevented unauthorized data access",
                    "transaction_id": payload.transaction_id,
                    "correlation_id": correlation_id,
                    "zta_enforcement": {
                        "policy_engine": "Azure Entra ID",
                        "enforcement_point": "Azure APIM",
                        "action": "403_SCOPE_VIOLATION",
                        "tenets": ["Tenet 4 - Dynamic Policy", "Tenet 6 - Dynamic AuthZ"],
                        "blast_radius": "ZERO — other agents unaffected"
                    }
                }
            )

    # ═══════════════════════════════════════════════════════════════
    # NORMAL OPERATION (Act 1 and Act 3)
    # ═══════════════════════════════════════════════════════════════

    identity.audit_log("ALERT_EVALUATION_STARTED", {
        "transaction_id": payload.transaction_id,
        "risk_score": payload.risk_score,
        "risk_level": payload.risk_level,
        "caller_agent": x_agent_id,
        "correlation_id": correlation_id
    })

    # Only generate alert narrative for medium+ risk
    alert_narrative = None
    alert_generated = False

    if payload.risk_score >= 40:
        alert_narrative = await _generate_alert_narrative(payload, correlation_id)
        alert_generated = True

        # Store alert (write-only — Tenet 1 scope enforcement)
        alert_record = {
            "alert_id": str(uuid.uuid4()),
            "transaction_id": payload.transaction_id,
            "risk_score": payload.risk_score,
            "risk_level": payload.risk_level,
            "narrative": alert_narrative,
            "recommendation": payload.recommendation,
            "correlation_id": correlation_id,
            "status": "ACTIVE"
        }
        alert_store.append(alert_record)

        identity.audit_log("ALERT_GENERATED", {
            "alert_id": alert_record["alert_id"],
            "transaction_id": payload.transaction_id,
            "risk_score": payload.risk_score,
            "correlation_id": correlation_id
        })

    # Log to Agent 4
    try:
        log_payload = {
            "transaction_id": payload.transaction_id,
            "event": "ALERT_EVALUATED",
            "alert_generated": alert_generated,
            "risk_score": payload.risk_score,
            "correlation_id": correlation_id,
            "alerting_agent": identity.agent_id
        }
        identity.call_agent(
            target_endpoint="/agent4-logger/log",
            payload=log_payload,
            correlation_id=correlation_id
        )
    except Exception as e:
        identity.audit_log("LOGGER_CALL_FAILED", {"error": str(e)}, level="WARNING")

    return JSONResponse(content={
        "status": "evaluated",
        "transaction_id": payload.transaction_id,
        "correlation_id": correlation_id,
        "alert_generated": alert_generated,
        "risk_level": payload.risk_level,
        "narrative": alert_narrative,
        "zta_trace": {
            "alert_agent": identity.agent_id,
            "data_received": "risk_score_only (not raw transaction)",
            "scope": "alert:write"
        }
    })


@app.get("/alerts")
async def get_alerts():
    """View generated alerts — for demo dashboard"""
    return {"alerts": alert_store, "count": len(alert_store)}


async def _generate_alert_narrative(
    payload: RiskScorePayload,
    correlation_id: str
) -> str:
    """Azure OpenAI generates human-readable alert for fraud team"""

    prompt = f"""You are a fraud alert system. Generate a concise, professional alert narrative for a fraud analyst.

Risk Assessment Summary:
- Transaction ID: {payload.transaction_id}
- Risk Score: {payload.risk_score}/100
- Risk Level: {payload.risk_level.upper()}
- Risk Factors: {', '.join(payload.risk_factors)}
- Recommended Action: {payload.recommendation.upper()}
- Scoring Reasoning: {payload.scoring_reasoning}

Write a 2-3 sentence alert narrative that a fraud analyst would act on.
Be specific about the risk factors. Do NOT include raw financial amounts (data minimization).
Format: Plain text, no JSON."""

    try:
        response = aoai_client.chat.completions.create(
            model=AOAI_DEPLOYMENT,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.3
        )

        narrative = response.choices[0].message.content.strip()

        identity.audit_log("ALERT_NARRATIVE_GENERATED", {
            "transaction_id": payload.transaction_id,
            "correlation_id": correlation_id
        })

        return narrative

    except Exception as e:
        identity.audit_log("ALERT_NARRATIVE_ERROR", {
            "error": str(e),
            "correlation_id": correlation_id
        }, level="ERROR")
        return (
            f"ALERT [{payload.risk_level.upper()}]: Transaction {payload.transaction_id} "
            f"flagged with risk score {payload.risk_score}/100. "
            f"Risk factors: {', '.join(payload.risk_factors)}. "
            f"Recommended action: {payload.recommendation.upper()}."
        )
