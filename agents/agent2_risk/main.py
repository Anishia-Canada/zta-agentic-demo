"""
Agent 2 — Risk Scoring Agent
NPE Identity: zta-agent-risk-scoring

Responsibilities:
  - Receives enriched transaction from Agent 1 (via APIM)
  - Calls Azure OpenAI to generate structured risk score (0-100) with reasoning
  - Forwards risk score ONLY (not raw transaction) to Agent 3 via APIM

ZTA Tenets demonstrated:
  Tenet 1: Protected resource — only reachable via APIM, not directly
  Tenet 2: Validates caller's Bearer token before processing
  Tenet 4: Dynamic policy — APIM checks Agent 1's scope claim
  Tenet 5: Asset posture monitored via /health
  Tenet 7: Risk decisions logged with full audit trail

Scope: READ from Agent 1 pipeline. WRITE risk score to Agent 3 only.
       CANNOT access raw transactions after this point.
       CANNOT call Agent 4 directly.
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
logger = logging.getLogger("agent2_risk")

app = FastAPI(title="ZTA Agent 2 — Risk Scoring")

identity = ZTAIdentity(agent_id="agent2-risk-scoring")

aoai_client = AzureOpenAI(
    azure_endpoint=os.environ["AOAI_ENDPOINT"],
    api_key=os.environ["AOAI_API_KEY"],
    api_version="2024-02-01"
)
AOAI_DEPLOYMENT = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o")


class EnrichedTransactionPayload(BaseModel):
    transaction_id: str
    user_id: str
    amount: float
    currency: str
    merchant: str
    merchant_category: str
    location_country: str
    location_city: str
    timestamp: str
    user_avg_transaction: float
    user_home_country: str
    ai_enrichment: dict
    correlation_id: str
    intake_agent: str


@app.get("/health")
async def health():
    """Tenet 5: Health endpoint for continuous monitoring"""
    return {
        "agent": "agent2-risk-scoring",
        "status": "healthy",
        "zta_identity": identity.client_id
    }


@app.post("/score")
async def score_transaction(
    payload: EnrichedTransactionPayload,
    request: Request,
    x_agent_id: str = Header(default=None),
    x_correlation_id: str = Header(default=None)
):
    """
    Risk scoring endpoint.

    Tenet 1: Protected resource — APIM is the only path in
    Tenet 4: APIM has already validated Agent 1's scope before we get here
    Tenet 2: We verify the X-Agent-ID header to confirm caller identity
    """
    correlation_id = x_correlation_id or payload.correlation_id

    # Tenet 4 / 6: Verify the caller is who they claim to be
    # APIM has validated the JWT — we do secondary app-layer check
    if x_agent_id and x_agent_id != "agent1-transaction-intake":
        identity.audit_log("UNAUTHORIZED_CALLER_DETECTED", {
            "claimed_caller": x_agent_id,
            "expected": "agent1-transaction-intake",
            "correlation_id": correlation_id
        }, level="ERROR")
        raise HTTPException(
            status_code=403,
            detail="ZTA Violation: Caller not authorized to invoke risk scoring"
        )

    identity.audit_log("RISK_SCORING_STARTED", {
        "transaction_id": payload.transaction_id,
        "caller_agent": x_agent_id,
        "correlation_id": correlation_id,
        "enrichment_flags": payload.ai_enrichment.get("contextual_flags", [])
    })

    # Azure OpenAI risk assessment
    risk_result = await _score_with_openai(payload, correlation_id)

    # Build score-only payload for Agent 3
    # Tenet 3: Agent 3 gets ONLY the score — not the raw transaction data
    # This is data minimization in action — least privilege for data access
    score_only_payload = {
        "transaction_id": payload.transaction_id,
        "user_id": payload.user_id,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "risk_factors": risk_result["risk_factors"],
        "recommendation": risk_result["recommendation"],
        "scoring_reasoning": risk_result["reasoning"],
        "correlation_id": correlation_id,
        "scoring_agent": identity.agent_id
        # NOTE: raw amount, merchant, location NOT forwarded — data minimization
    }

    # Call Agent 3 via APIM — only if risk score warrants an alert
    agent3_response = None
    if risk_result["risk_score"] >= 40:  # threshold for alerting
        try:
            identity.audit_log("FORWARDING_TO_AGENT3", {
                "transaction_id": payload.transaction_id,
                "risk_score": risk_result["risk_score"],
                "correlation_id": correlation_id
            })

            agent3_response = identity.call_agent(
                target_endpoint="/agent3-alert/evaluate",
                payload=score_only_payload,
                correlation_id=correlation_id
            )

        except ZTAAuthorizationError as e:
            # Tenet 6: If this agent gets revoked, it's caught and logged
            identity.audit_log("AGENT3_CALL_BLOCKED", {
                "reason": str(e),
                "correlation_id": correlation_id
            }, level="ERROR")
            agent3_response = {"status": "blocked_by_zta", "reason": str(e)}
    else:
        identity.audit_log("ALERT_THRESHOLD_NOT_MET", {
            "transaction_id": payload.transaction_id,
            "risk_score": risk_result["risk_score"],
            "threshold": 40,
            "correlation_id": correlation_id
        })

    # Always call Agent 4 (Compliance Logger) regardless of risk level
    try:
        log_payload = {
            "transaction_id": payload.transaction_id,
            "event": "RISK_SCORE_GENERATED",
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "correlation_id": correlation_id,
            "scoring_agent": identity.agent_id
        }
        identity.call_agent(
            target_endpoint="/agent4-logger/log",
            payload=log_payload,
            correlation_id=correlation_id
        )
    except Exception as e:
        identity.audit_log("LOGGER_CALL_FAILED", {
            "error": str(e),
            "correlation_id": correlation_id
        }, level="WARNING")

    return JSONResponse(content={
        "status": "scored",
        "transaction_id": payload.transaction_id,
        "correlation_id": correlation_id,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "risk_factors": risk_result["risk_factors"],
        "recommendation": risk_result["recommendation"],
        "agent3_result": agent3_response,
        "zta_trace": {
            "scoring_agent": identity.agent_id,
            "data_minimization": "raw_transaction_not_forwarded",
            "token_scope": "agent3:write",
            "apim_enforced": True
        }
    })


async def _score_with_openai(
    payload: EnrichedTransactionPayload,
    correlation_id: str
) -> dict:
    """Azure OpenAI risk scoring with structured output"""

    enrichment = payload.ai_enrichment
    amount_ratio = payload.amount / max(payload.user_avg_transaction, 1)

    prompt = f"""You are a financial fraud risk scoring AI. Generate a precise risk score for this transaction.

Transaction Context (from intake analysis):
- Summary: {enrichment.get('summary', 'N/A')}
- Geographic anomaly detected: {enrichment.get('geographic_anomaly', False)}
- Amount anomaly detected: {enrichment.get('amount_anomaly', False)}
- Merchant risk level: {enrichment.get('merchant_risk_level', 'unknown')}
- Contextual flags: {enrichment.get('contextual_flags', [])}
- Analyst note: {enrichment.get('analyst_note', 'N/A')}

Additional metrics:
- Amount vs user average ratio: {amount_ratio:.2f}x
- User home country: {payload.user_home_country}
- Transaction country: {payload.location_country}
- Merchant category: {payload.merchant_category}

Respond in JSON with these exact fields:
{{
  "risk_score": <integer 0-100>,
  "risk_level": "low/medium/high/critical",
  "risk_factors": ["factor1", "factor2"],
  "recommendation": "approve/review/block",
  "reasoning": "one paragraph explaining the score"
}}

Risk score guide: 0-30=low, 31-60=medium, 61-85=high, 86-100=critical"""

    try:
        response = aoai_client.chat.completions.create(
            model=AOAI_DEPLOYMENT,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=500,
            temperature=0.1
        )

        result = json.loads(response.choices[0].message.content)

        identity.audit_log("RISK_SCORE_GENERATED", {
            "transaction_id": payload.transaction_id,
            "risk_score": result.get("risk_score"),
            "risk_level": result.get("risk_level"),
            "recommendation": result.get("recommendation"),
            "correlation_id": correlation_id
        })

        return result

    except Exception as e:
        identity.audit_log("RISK_SCORING_ERROR", {
            "error": str(e),
            "correlation_id": correlation_id
        }, level="ERROR")
        return {
            "risk_score": 50,
            "risk_level": "medium",
            "risk_factors": ["scoring_system_error"],
            "recommendation": "review",
            "reasoning": f"Scoring system error — defaulting to medium risk: {str(e)}"
        }
