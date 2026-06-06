#!/bin/bash
# ==============================================================================
# DevSecOps Supply Chain Security - Shutdown Script
# ==============================================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}       Stopping DevSecOps Platform Containers               ${NC}"
echo -e "${CYAN}============================================================${NC}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

docker-compose down

echo -e "${GREEN}✓ DevSecOps containers stopped and networks deleted.${NC}"
echo -e "${GREEN}============================================================${NC}"
