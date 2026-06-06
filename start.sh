#!/bin/bash
# ==============================================================================
# DevSecOps Supply Chain Security - Bootstrapping Script
# Simulates: TruffleHog, Trivy, Grype, Cosign, Rekor, Kyverno, OPA, Falco, Vault
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   🛡️  BOOTSTRAPPING DEVSECOPS SUPPLY CHAIN SECURITY       ${NC}"
echo -e "${CYAN}   TruffleHog · Trivy · Grype · Cosign · Kyverno · Falco  ${NC}"
echo -e "${CYAN}============================================================${NC}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Validate Docker
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
  exit 1
fi

echo -e "\n${BLUE}>>> [STEP 1/3] Building and starting container platform...${NC}"
docker-compose up -d --build

echo -e "\n${BLUE}>>> [STEP 2/3] Waiting for Backend Security API to initialize...${NC}"
retries=15
while [ $retries -gt 0 ]; do
  if curl -s http://localhost:8000/health | grep -q "ok"; then
    echo -e "${GREEN}✓ Backend Security API verified ONLINE!${NC}"
    break
  fi
  sleep 2
  retries=$((retries-1))
done

if [ $retries -eq 0 ]; then
  echo -e "${RED}⚠️  Warning: Backend did not respond. Check: docker-compose logs backend${NC}"
fi

echo -e "\n${BLUE}>>> [STEP 3/3] Verifying Vault KMS keys configuration...${NC}"
KEYS_STATUS=$(curl -s http://localhost:8000/api/vault/keys 2>/dev/null | grep -o '"status":"active"' || echo "inactive")
if [ "$KEYS_STATUS" = '"status":"active"' ]; then
  echo -e "${GREEN}    ✓ Vault KMS Transit Engine keys reporting ACTIVE${NC}"
else
  echo -e "${RED}    ⚠️  Warning: Vault keys reporting inactive or down${NC}"
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}  🎉 DevSecOps Software Supply Chain Platform is Live!       ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "${CYAN}🖥️  Dashboard Simulator: http://localhost:3000${NC}"
echo -e "${CYAN}⚙️   API Service Docs:    http://localhost:8000/docs${NC}"
echo -e "${CYAN}🩺  Health Checks:        http://localhost:8000/health${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "${PURPLE}  Stack: TruffleHog → Trivy/Grype → Cosign → Kyverno/OPA → Falco${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "To view logs:  docker-compose logs -f backend"
echo -e "To stop:       ./stop.sh"
echo -e "${GREEN}============================================================${NC}\n"
