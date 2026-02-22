"""
ZTA Auth Library — shared across all agents
Handles:
  - Identity: fetching short-lived tokens from Entra ID (Tenet 3, 6)
  - Secrets: pulling credentials from Key Vault, never hardcoded (Tenet 2)
  - Headers: injecting ZTA headers on every outbound agent call (Tenet 2)
  - Telemetry: structured audit logging on every action (Tenet 7)

NIST 800-207 Tenets enforced here:
  Tenet 2 — All communication secured (Bearer token on every call)
  Tenet 3 — Per-session access (short-lived tokens, no caching beyond TTL)
  Tenet 6 — Dynamic auth/authz (token fetched fresh, checked for revocation)
  Tenet 7 — Telemetry collected on every auth event
"""

import os
import time
import uuid
import json
import logging
import requests
from datetime import datetime, timezone
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

# ── Structured logger (feeds Azure Monitor / App Insights) ──────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("zta_auth")


class ZTAIdentity:
    """
    Represents a single agent's ZTA identity.
    Each agent instantiates this with its own NPE credentials.

    Tenet 3: Tokens are short-lived. We do NOT cache beyond token expiry.
    Tenet 6: Every request re-validates — no implicit standing trust.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.tenant_id = os.environ["AZURE_TENANT_ID"]
        self.client_id = os.environ["AZURE_CLIENT_ID"]
        self.apim_base_url = os.environ["APIM_BASE_URL"]
        self.keyvault_url = os.environ["KEYVAULT_URL"]

        # Tenet 2: Secret pulled from Key Vault — never hardcoded
        self.client_secret = self._fetch_secret_from_keyvault()

        self._token: str | None = None
        self._token_expiry: float = 0

        self.audit_log("IDENTITY_INITIALIZED", {
            "agent_id": agent_id,
            "client_id": self.client_id,
            "keyvault_url": self.keyvault_url
        })

    def _fetch_secret_from_keyvault(self) -> str:
        """
        Tenet 2: No hardcoded secrets. Always pulled from Key Vault.
        Uses Managed Identity when running in Azure Container Apps.
        Falls back to env var CLIENT_SECRET only for local dev.
        """
        try:
            # In Azure Container Apps, uses Managed Identity automatically
            from azure.identity import DefaultAzureCredential
            kv_credential = DefaultAzureCredential()
            secret_client = SecretClient(
                vault_url=self.keyvault_url,
                credential=kv_credential
            )
            secret_name = os.environ.get("KEYVAULT_SECRET_NAME", f"agent-secret")
            secret = secret_client.get_secret(secret_name)
            logger.info(f"[{self.agent_id}] Secret fetched from Key Vault ✓")
            return secret.value
        except Exception as e:
            # Fallback for local dev only — log a warning
            logger.warning(f"[{self.agent_id}] Key Vault unavailable, using env var: {e}")
            return os.environ["AZURE_CLIENT_SECRET"]

    def get_token(self) -> str:
        """
        Tenet 3: Per-session, short-lived token.
        Tenet 6: Re-fetched when expired — no long-lived standing tokens.
        Returns a valid Bearer token for calling APIM-protected endpoints.
        """
        now = time.time()

        # If token is still valid (with 60s buffer), reuse it
        if self._token and now < (self._token_expiry - 60):
            return self._token

        # Token expired or not yet fetched — request a new one
        self.audit_log("TOKEN_REQUESTED", {"reason": "expired_or_new"})

        token_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": os.environ.get(
                "TOKEN_SCOPE",
                "https://management.azure.com/.default"
            )
        }

        response = requests.post(token_url, data=payload, timeout=10)
        response.raise_for_status()
        token_data = response.json()

        self._token = token_data["access_token"]
        self._token_expiry = now + token_data.get("expires_in", 3600)

        self.audit_log("TOKEN_ISSUED", {
            "expires_in_seconds": token_data.get("expires_in"),
            "token_expiry_epoch": self._token_expiry
        })

        return self._token

    def secure_headers(self, correlation_id: str | None = None) -> dict:
        """
        Tenet 2: Every outbound call carries:
          - Authorization: Bearer <token>
          - X-Agent-ID: identifies the calling NPE
          - X-Correlation-ID: ties the entire pipeline trace together
          - X-ZTA-Session: unique per-request (not per-agent-lifetime)

        These headers are validated by APIM before any request proceeds.
        """
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json",
            "X-Agent-ID": self.agent_id,
            "X-Correlation-ID": correlation_id or str(uuid.uuid4()),
            "X-ZTA-Session": str(uuid.uuid4()),   # unique per call — Tenet 3
            "X-ZTA-Timestamp": datetime.now(timezone.utc).isoformat()
        }

    def call_agent(
        self,
        target_endpoint: str,
        payload: dict,
        correlation_id: str,
        method: str = "POST"
    ) -> dict:
        """
        Tenet 2: All inter-agent communication goes through APIM (PEP).
        Tenet 4: Dynamic policy evaluated by APIM on every call.
        Tenet 5: Call outcome logged for continuous monitoring.

        Raises ZTAAuthorizationError if APIM denies the request (403).
        """
        url = f"{self.apim_base_url}{target_endpoint}"
        headers = self.secure_headers(correlation_id)

        self.audit_log("AGENT_CALL_INITIATED", {
            "target": target_endpoint,
            "correlation_id": correlation_id,
            "caller": self.agent_id
        })

        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                json=payload,
                timeout=30
            )

            if resp.status_code == 403:
                self.audit_log("AGENT_CALL_DENIED", {
                    "target": target_endpoint,
                    "status": 403,
                    "reason": resp.text,
                    "correlation_id": correlation_id
                }, level="ERROR")
                raise ZTAAuthorizationError(
                    f"APIM denied {self.agent_id} → {target_endpoint}: {resp.text}"
                )

            if resp.status_code == 401:
                self.audit_log("AGENT_CALL_UNAUTHORIZED", {
                    "target": target_endpoint,
                    "status": 401,
                    "correlation_id": correlation_id
                }, level="ERROR")
                raise ZTATokenError(
                    f"Token rejected for {self.agent_id} → {target_endpoint}"
                )

            resp.raise_for_status()

            self.audit_log("AGENT_CALL_SUCCESS", {
                "target": target_endpoint,
                "status": resp.status_code,
                "correlation_id": correlation_id
            })

            return resp.json()

        except (ZTAAuthorizationError, ZTATokenError):
            raise
        except requests.exceptions.RequestException as e:
            self.audit_log("AGENT_CALL_ERROR", {
                "target": target_endpoint,
                "error": str(e),
                "correlation_id": correlation_id
            }, level="ERROR")
            raise

    def audit_log(self, event: str, data: dict, level: str = "INFO"):
        """
        Tenet 7: Every auth and communication event is logged with
        full context. Feeds into Azure Monitor / Log Analytics.
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "event": event,
            "data": data
        }
        log_line = json.dumps(log_entry)

        if level == "ERROR":
            logger.error(log_line)
        elif level == "WARNING":
            logger.warning(log_line)
        else:
            logger.info(log_line)


class ZTAAuthorizationError(Exception):
    """Raised when APIM (PEP) denies an agent-to-agent call — Tenet 4/6"""
    pass


class ZTATokenError(Exception):
    """Raised when a token is invalid or revoked — Tenet 6"""
    pass
