#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZTA Demo — Azure Infrastructure Setup Script
# Run this ONCE after APIM finishes provisioning
# Sets up Resource Group, APIM APIs, Key Vault access, and Container App secrets
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ── FILL THESE IN ─────────────────────────────────────────────────────────────
TENANT_ID="YOUR_TENANT_ID"
SUBSCRIPTION_ID="YOUR_SUBSCRIPTION_ID"
RESOURCE_GROUP="zta-demo-rg"
LOCATION="eastus"

ACR_NAME="ztademoregistry"
KEYVAULT_NAME="zta-demo-keyvault"
APIM_NAME="zta-demo-apim"
CONTAINER_ENV="zta-demo-env"

# Agent Client IDs (from your 4 App Registrations)
AGENT1_CLIENT_ID="YOUR_AGENT1_CLIENT_ID"
AGENT2_CLIENT_ID="YOUR_AGENT2_CLIENT_ID"
AGENT3_CLIENT_ID="YOUR_AGENT3_CLIENT_ID"
AGENT4_CLIENT_ID="YOUR_AGENT4_CLIENT_ID"

AOAI_ENDPOINT="YOUR_AZURE_OPENAI_ENDPOINT"
# ─────────────────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════════════"
echo "  ZTA DEMO — AZURE INFRASTRUCTURE SETUP"
echo "════════════════════════════════════════════════════════════"

# ── 1. Login and set subscription ─────────────────────────────────────────────
echo ""
echo "▶ Step 1: Azure login..."
az login --use-device-code
az account set --subscription $SUBSCRIPTION_ID
echo "✓ Logged in to subscription: $SUBSCRIPTION_ID"

# ── 2. Create Resource Group ──────────────────────────────────────────────────
echo ""
echo "▶ Step 2: Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION
echo "✓ Resource group: $RESOURCE_GROUP"

# ── 3. Grant agents access to Key Vault ───────────────────────────────────────
# Tenet 2: Agents pull secrets from Key Vault — no hardcoded credentials
echo ""
echo "▶ Step 3: Granting Key Vault access to all agent identities..."

for CLIENT_ID in $AGENT1_CLIENT_ID $AGENT2_CLIENT_ID $AGENT3_CLIENT_ID $AGENT4_CLIENT_ID; do
    az keyvault set-policy \
        --name $KEYVAULT_NAME \
        --spn $CLIENT_ID \
        --secret-permissions get list \
        --output none
    echo "  ✓ Key Vault access granted to: $CLIENT_ID"
done

# ── 4. Grant ACR pull rights to Container Apps ────────────────────────────────
echo ""
echo "▶ Step 4: Granting ACR pull rights..."
ACR_ID=$(az acr show --name $ACR_NAME --query id --output tsv)
az role assignment create \
    --assignee "$(az containerapp env show --name $CONTAINER_ENV --resource-group $RESOURCE_GROUP --query identity.principalId --output tsv)" \
    --role AcrPull \
    --scope $ACR_ID \
    --output none
echo "✓ Container Apps environment can pull from ACR"

# ── 5. Create APIM APIs ───────────────────────────────────────────────────────
echo ""
echo "▶ Step 5: Creating APIM API definitions..."

APIM_BASE="https://${APIM_NAME}.azure-api.net"

# Get Container App FQDNs
AGENT1_FQDN=$(az containerapp show --name agent1-intake --resource-group $RESOURCE_GROUP --query properties.configuration.ingress.fqdn --output tsv 2>/dev/null || echo "pending")
AGENT2_FQDN=$(az containerapp show --name agent2-risk --resource-group $RESOURCE_GROUP --query properties.internalIngressFqdn --output tsv 2>/dev/null || echo "pending")
AGENT3_FQDN=$(az containerapp show --name agent3-alert --resource-group $RESOURCE_GROUP --query properties.internalIngressFqdn --output tsv 2>/dev/null || echo "pending")
AGENT4_FQDN=$(az containerapp show --name agent4-logger --resource-group $RESOURCE_GROUP --query properties.internalIngressFqdn --output tsv 2>/dev/null || echo "pending")

echo "  Agent 1 FQDN: $AGENT1_FQDN"
echo "  Agent 2 FQDN: $AGENT2_FQDN"
echo "  Agent 3 FQDN: $AGENT3_FQDN"
echo "  Agent 4 FQDN: $AGENT4_FQDN"

# Create Agent 1 API in APIM
az apim api create \
    --resource-group $RESOURCE_GROUP \
    --service-name $APIM_NAME \
    --api-id agent1-intake \
    --display-name "Agent 1 — Transaction Intake" \
    --path "agent1-intake" \
    --service-url "https://${AGENT1_FQDN}" \
    --protocols https \
    --output none
echo "  ✓ APIM API created: agent1-intake"

# Create Agent 2 API in APIM
az apim api create \
    --resource-group $RESOURCE_GROUP \
    --service-name $APIM_NAME \
    --api-id agent2-risk \
    --display-name "Agent 2 — Risk Scoring" \
    --path "agent2-risk" \
    --service-url "https://${AGENT2_FQDN}" \
    --protocols https \
    --output none
echo "  ✓ APIM API created: agent2-risk"

# Create Agent 3 API in APIM
az apim api create \
    --resource-group $RESOURCE_GROUP \
    --service-name $APIM_NAME \
    --api-id agent3-alert \
    --display-name "Agent 3 — Alert Agent" \
    --path "agent3-alert" \
    --service-url "https://${AGENT3_FQDN}" \
    --protocols https \
    --output none
echo "  ✓ APIM API created: agent3-alert"

# Create Agent 4 API in APIM
az apim api create \
    --resource-group $RESOURCE_GROUP \
    --service-name $APIM_NAME \
    --api-id agent4-logger \
    --display-name "Agent 4 — Compliance Logger" \
    --path "agent4-logger" \
    --service-url "https://${AGENT4_FQDN}" \
    --protocols https \
    --output none
echo "  ✓ APIM API created: agent4-logger"

# ── 6. Print GitHub Secrets needed ───────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  GITHUB SECRETS TO ADD"
echo "  (Settings → Secrets and Variables → Actions)"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  AZURE_TENANT_ID        = $TENANT_ID"
echo "  AZURE_SUBSCRIPTION_ID  = $SUBSCRIPTION_ID"
echo "  ACR_LOGIN_SERVER       = ${ACR_NAME}.azurecr.io"
echo "  APIM_BASE_URL          = $APIM_BASE"
echo "  KEYVAULT_URL           = https://${KEYVAULT_NAME}.vault.azure.net"
echo "  AOAI_ENDPOINT          = $AOAI_ENDPOINT"
echo "  AGENT1_CLIENT_ID       = $AGENT1_CLIENT_ID"
echo "  AGENT2_CLIENT_ID       = $AGENT2_CLIENT_ID"
echo "  AGENT3_CLIENT_ID       = $AGENT3_CLIENT_ID"
echo "  AGENT4_CLIENT_ID       = $AGENT4_CLIENT_ID"
echo "  APIM_SCOPE             = api://<YOUR_APIM_APP_ID>/.default"
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  SETUP COMPLETE ✓"
echo "  Next: Add secrets to GitHub → push to main → watch Actions"
echo "════════════════════════════════════════════════════════════"
