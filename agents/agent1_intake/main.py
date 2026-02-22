"""
Agent 1 — Transaction Intake Agent
NPE Identity: zta-agent-transaction-intake

Responsibilities:
  - Receives raw transaction payload from external caller
  - Calls Azure OpenAI for first-pass contextual enrichment
  - Forwards enriched payload to Agent 2 (Risk Scoring) via APIM

ZTA Tenets demonstrated:
  Tenet 1: This agent's endpoint is a registered, protected resource
  Tenet 2: All outbound calls to Agent 2 go through APIM with Bearer token
  Tenet 3: Short-lived token fetched per-session before calling Agent 2
  Tenet 7: Every action logged with correlation ID for full pipeline trace

Scope: WRITE to Agent 2 only. Cannot call Agent 3 or Agent 4 directly.
       APIM enforces this via scope claim validation.
"""

import os
import uuid
import json
import logging
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from openai import AzureOpenAI
import sys

sys.path.append("/app/shared")
from zta_auth import ZTAIdentity, ZTAAuthorizationError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent1_intake")

app = FastAPI(title="ZTA Agent 1 — Transaction Intake")

# Agent identity — instantiated once at startup
# Tenet 1: This agent is a registered NPE with its own unique identity
identity = ZTAIdentity(agent_id="agent1-transaction-intake")

# Azure OpenAI client
aoai_client = AzureOpenAI(
    azure_endpoint=os.environ["AOAI_ENDPOINT"],
    api_key=os.environ["AOAI_API_KEY"],
    api_version="2024-02-01"
)
AOAI_DEPLOYMENT = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o")


class TransactionPayload(BaseModel):
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


@app.get("/health")
async def health():
    """Tenet 5: Health endpoint for continuous asset monitoring"""
    return {
        "agent": "agent1-transaction-intake",
        "status": "healthy",
        "zta_identity": identity.client_id
    }


@app.post("/intake")
async def intake_transaction(
    payload: TransactionPayload,
    request: Request,
    x_correlation_id: str = Header(default=None)
):
    """
    Main intake endpoint.
    Receives transaction, enriches with OpenAI, forwards to Agent 2.

    Tenet 1: This endpoint is a protected resource registered in Entra ID
    Tenet 7: Full telemetry logged throughout
    """
    correlation_id = x_correlation_id or str(uuid.uuid4())

    identity.audit_log("TRANSACTION_RECEIVED", {
        "transaction_id": payload.transaction_id,
        "amount": payload.amount,
        "currency": payload.currency,
        "merchant": payload.merchant,
        "location": f"{payload.location_city}, {payload.location_country}",
        "correlation_id": correlation_id
    })

    # Step 1: Azure OpenAI enrichment
    enrichment = await _enrich_with_openai(payload, correlation_id)

    # Step 2: Build enriched payload for Agent 2
    enriched_payload = {
        "transaction_id": payload.transaction_id,
        "user_id": payload.user_id,
        "amount": payload.amount,
        "currency": payload.currency,
        "merchant": payload.merchant,
        "merchant_category": payload.merchant_category,
        "location_country": payload.location_country,
        "location_city": payload.location_city,
        "timestamp": payload.timestamp,
        "user_avg_transaction": payload.user_avg_transaction,
        "user_home_country": payload.user_home_country,
        "ai_enrichment": enrichment,
        "correlation_id": correlation_id,
        "intake_agent": identity.agent_id
    }

    # Step 3: Call Agent 2 via APIM (PEP)
    # Tenet 2: Goes through APIM with Bearer token
    # Tenet 3: Fresh token fetched for this session
    # Tenet 4: APIM validates this agent's scope before allowing the call
    try:
        identity.audit_log("FORWARDING_TO_AGENT2", {
            "transaction_id": payload.transaction_id,
            "correlation_id": correlation_id
        })

        agent2_response = identity.call_agent(
            target_endpoint="/agent2-risk/score",
            payload=enriched_payload,
            correlation_id=correlation_id
        )

        identity.audit_log("AGENT2_RESPONSE_RECEIVED", {
            "transaction_id": payload.transaction_id,
            "risk_score": agent2_response.get("risk_score"),
            "correlation_id": correlation_id
        })

        return JSONResponse(content={
            "status": "pipeline_initiated",
            "transaction_id": payload.transaction_id,
            "correlation_id": correlation_id,
            "enrichment_summary": enrichment.get("summary"),
            "agent2_result": agent2_response,
            "zta_trace": {
                "intake_agent": identity.agent_id,
                "token_scope": "agent2:write",
                "apim_enforced": True
            }
        })

    except ZTAAuthorizationError as e:
        # Tenet 6: Authorization failure is logged and surfaced
        identity.audit_log("PIPELINE_BLOCKED_BY_ZTA", {
            "error": str(e),
            "correlation_id": correlation_id
        }, level="ERROR")
        raise HTTPException(status_code=403, detail=f"ZTA Policy Denied: {str(e)}")


async def _enrich_with_openai(
    payload: TransactionPayload,
    correlation_id: str
) -> dict:
    """
    Azure OpenAI call for contextual transaction enrichment.
    Agent 1's intelligence — first-pass anomaly context.
    """
    identity.audit_log("OPENAI_ENRICHMENT_STARTED", {
        "transaction_id": payload.transaction_id,
        "correlation_id": correlation_id
    })

    prompt = f"""You are a financial transaction analyst. Analyze this transaction and provide a brief contextual enrichment.

Transaction Details:
- Amount: {payload.amount} {payload.currency}
- Merchant: {payload.merchant} (Category: {payload.merchant_category})
- Location: {payload.location_city}, {payload.location_country}
- Transaction Time: {payload.timestamp}
- User's home country: {payload.user_home_country}
- User's average transaction amount: {payload.user_avg_transaction} {payload.currency}

Respond in JSON with these exact fields:
{{
  "summary": "one sentence describing the transaction context",
  "geographic_anomaly": true/false,
  "amount_anomaly": true/false,
  "merchant_risk_level": "low/medium/high",
  "contextual_flags": ["list", "of", "flags"],
  "analyst_note": "brief note for risk scoring agent"
}}"""

    try:
        response = aoai_client.chat.completions.create(
            model=AOAI_DEPLOYMENT,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=400,
            temperature=0.1
        )

        enrichment = json.loads(response.choices[0].message.content)

        identity.audit_log("OPENAI_ENRICHMENT_COMPLETE", {
            "transaction_id": payload.transaction_id,
            "geographic_anomaly": enrichment.get("geographic_anomaly"),
            "amount_anomaly": enrichment.get("amount_anomaly"),
            "merchant_risk": enrichment.get("merchant_risk_level"),
            "correlation_id": correlation_id
        })

        return enrichment

    except Exception as e:
        identity.audit_log("OPENAI_ENRICHMENT_ERROR", {
            "error": str(e),
            "correlation_id": correlation_id
        }, level="ERROR")
        # Graceful degradation — pipeline continues without enrichment
        return {
            "summary": "Enrichment unavailable — proceeding with raw data",
            "geographic_anomaly": False,
            "amount_anomaly": False,
            "merchant_risk_level": "unknown",
            "contextual_flags": ["enrichment_failed"],
            "analyst_note": f"OpenAI error: {str(e)}"
        }
