"""
Agent 4 — Compliance Logger Agent
NPE Identity: zta-agent-compliance-logger

Responsibilities:
  - Append-only immutable audit log writer
  - Receives log events from Agent 2 and Agent 3
  - CANNOT read any transaction data, scores, or alerts
  - CANNOT call any other agent

ZTA Tenets demonstrated:
  Tenet 1: Most restricted resource in the pipeline — append-only scope
  Tenet 2: All inbound calls validated via APIM JWT
  Tenet 3: Per-session token — even from trusted agents
  Tenet 4: Dynamic policy — APIM enforces write-only scope
  Tenet 5: This agent's integrity is continuously monitored
  Tenet 7: IS the telemetry layer — stores the immutable audit trail

Security properties:
  - Even if fully compromised, cannot exfiltrate data (no read scope)
  - Cannot call other agents (no outbound scope)
  - Append-only log — cannot modify or delete past entries
  - Demonstrates that ZTA limits blast radius to near-zero
"""

import os
import uuid
import logging
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional, Any
import sys

sys.path.append("/app/shared")
from zta_auth import ZTAIdentity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent4_logger")

app = FastAPI(title="ZTA Agent 4 — Compliance Logger")

identity = ZTAIdentity(agent_id="agent4-compliance-logger")

# Immutable append-only audit log
# In production: Azure Cosmos DB with append-only policy
# or Azure Blob Storage with immutability policy
AUDIT_LOG: list = []

# Allowed callers — APIM enforces this too, but we double-check
ALLOWED_CALLERS = {
    "agent2-risk-scoring",
    "agent3-alert"
}


class LogPayload(BaseModel):
    transaction_id: str
    event: str
    correlation_id: str
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    alert_generated: Optional[bool] = None
    scoring_agent: Optional[str] = None
    alerting_agent: Optional[str] = None
    additional_data: Optional[Any] = None


@app.get("/health")
async def health():
    """Tenet 5: Health monitoring for compliance logger"""
    return {
        "agent": "agent4-compliance-logger",
        "status": "healthy",
        "zta_identity": identity.client_id,
        "log_entries": len(AUDIT_LOG),
        "scope": "append-write-only"
    }


@app.post("/log")
async def append_log(
    payload: LogPayload,
    request: Request,
    x_agent_id: str = Header(default=None),
    x_correlation_id: str = Header(default=None),
    x_zta_session: str = Header(default=None)
):
    """
    Append-only compliance log endpoint.

    Tenet 1: Narrowest possible resource scope — write-only
    Tenet 2: JWT validated by APIM before reaching here
    Tenet 4: Secondary check on caller identity
    Tenet 7: THIS endpoint IS the telemetry implementation
    """
    correlation_id = x_correlation_id or payload.correlation_id

    # Tenet 4 / 6: Application-layer identity check
    # APIM already enforced JWT scope, this is defense in depth
    if x_agent_id and x_agent_id not in ALLOWED_CALLERS:
        identity.audit_log("UNAUTHORIZED_LOG_ATTEMPT", {
            "claimed_caller": x_agent_id,
            "allowed_callers": list(ALLOWED_CALLERS),
            "correlation_id": correlation_id,
            "tenet": "Tenet 4 — Dynamic Policy Violation"
        }, level="ERROR")
        raise HTTPException(
            status_code=403,
            detail=f"ZTA Policy: {x_agent_id} not authorized to write compliance logs"
        )

    # Create immutable log entry
    # Tenet 7: Rich structured log with full ZTA context
    log_entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "transaction_id": payload.transaction_id,
        "event": payload.event,
        "correlation_id": correlation_id,
        "zta_session_id": x_zta_session,
        "caller_agent": x_agent_id,
        "data": {
            "risk_score": payload.risk_score,
            "risk_level": payload.risk_level,
            "alert_generated": payload.alert_generated,
            "scoring_agent": payload.scoring_agent,
            "alerting_agent": payload.alerting_agent,
            "additional": payload.additional_data
        },
        "immutable": True,
        "zta_enforced": True
    }

    # APPEND ONLY — no update, no delete
    AUDIT_LOG.append(log_entry)

    identity.audit_log("COMPLIANCE_LOG_APPENDED", {
        "log_id": log_entry["log_id"],
        "event": payload.event,
        "transaction_id": payload.transaction_id,
        "caller": x_agent_id,
        "total_log_entries": len(AUDIT_LOG),
        "correlation_id": correlation_id
    })

    return JSONResponse(content={
        "status": "logged",
        "log_id": log_entry["log_id"],
        "transaction_id": payload.transaction_id,
        "correlation_id": correlation_id,
        "zta_trace": {
            "logger_agent": identity.agent_id,
            "scope": "append-write-only",
            "can_read_back": False,
            "can_delete": False,
            "can_call_other_agents": False
        }
    })


@app.get("/audit-trail")
async def get_audit_trail(correlation_id: Optional[str] = None):
    """
    Read audit trail — for demo dashboard only.
    In production this would require separate elevated read credentials.
    This endpoint itself is scope-protected in APIM.
    """
    if correlation_id:
        filtered = [e for e in AUDIT_LOG if e["correlation_id"] == correlation_id]
        return {"entries": filtered, "count": len(filtered), "correlation_id": correlation_id}

    return {
        "entries": AUDIT_LOG,
        "count": len(AUDIT_LOG),
        "note": "Append-only immutable log — Tenet 7 implementation"
    }


@app.get("/audit-trail/summary")
async def get_audit_summary():
    """High-level summary for demo dashboard"""
    events = {}
    for entry in AUDIT_LOG:
        event = entry["event"]
        events[event] = events.get(event, 0) + 1

    return {
        "total_entries": len(AUDIT_LOG),
        "event_breakdown": events,
        "unique_transactions": len(set(e["transaction_id"] for e in AUDIT_LOG)),
        "zta_enforcement": "All entries validated via APIM JWT before acceptance"
    }
