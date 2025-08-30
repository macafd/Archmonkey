
# ============================================================================
# FASE 3 - DISCO AUXILIAR
# ============================================================================
echo -e "${GREEN}Criando fase3-disco-auxiliar.sh...${NC}"
cat << 'EOF' > fase3-disco-auxiliar.sh
#!/bin/bash
# fase3-disco-auxiliar.sh - Configuração do disco auxiliar (opcional)
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_NAME="fase3-disco-auxiliar"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"

[[ ! -f "$ENV_FILE" ]] && { echo -e "${RED}Execute fase1 primeiro!${NC}"; exit 1; }
source "$ENV_FILE"

[[ -z "$DISCO_AUXILIAR" ]] && { echo -e "${YELLOW}Disco auxiliar não configurado. Pulando...${NC}"; exit 0; }

setup_logging() {
    [[ "$SIMULATE" == "true" ]] && LOG_DIR="./logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 3: DISCO AUXILIAR ==="
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        LUKS_AUX_PASSWORD=$(jq -r '.luks_aux_password' "$CONFIG_FILE")
        LINUX_ONLY=$(jq -r '.linux_only // false' "$CONFIG_FILE")
    else
        echo -e "${YELLOW}Senha LUKS para disco auxiliar:${NC}"
        read -rs LUKS_AUX_PASSWORD
        echo
        
        echo -e "${YELLOW}Usar ext4 (Linux only) em vez de exFAT? [s/N]:${NC}"
        read -r linux_only
        [[ "$linux_only" =~ ^[Ss]$ ]] && LINUX_ONLY=true || LINUX_ONLY=false
    fi
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}FORMATAR $DISCO_AUXILIAR? Digite CONFIRM:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && exit 0
    fi
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Nada foi alterado"; exit 0; }
    
    # Particionar
    wipefs -af "$DISCO_AUXILIAR"
    parted -s "$DISCO_AUXILIAR" mklabel gpt mkpart DATA 0% 100%
    
    AUX_PART="${DISCO_AUXILIAR}1"
    [[ "$DISCO_AUXILIAR" =~ nvme ]] && AUX_PART="${DISCO_AUXILIAR}p1"
    
    # LUKS
    echo -n "$LUKS_AUX_PASSWORD" | cryptsetup luksFormat \
        --type luks2 \
        --pbkdf argon2id \
        --iter-time 3000 \
        --pbkdf-memory 262144 \
        "$AUX_PART" -
    
    echo -n "$LUKS_AUX_PASSWORD" | cryptsetup open "$AUX_PART" cryptdata -
    
    # Formatar
    if [[ "$LINUX_ONLY" == "true" ]]; then
        mkfs.ext4 -L DATA /dev/mapper/cryptdata
    else
        mkfs.exfat -n DATA /dev/mapper/cryptdata
    fi
    
    AUX_UUID=$(blkid -s UUID -o value "$AUX_PART")
    
    echo "export AUX_PART=\"$AUX_PART\"" >> "$ENV_FILE"
    echo "export AUX_UUID=\"$AUX_UUID\"" >> "$ENV_FILE"
    
    cryptsetup close cryptdata
    
    log "$GREEN" "Disco auxiliar configurado! Próximo: ./fase4-base-system.sh"
}

main
EOF
