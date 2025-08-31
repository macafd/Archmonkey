#!/bin/bash
# fase3-disco-auxiliar.sh - Configuracao do disco auxiliar (opcional)
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

# Definir valor padrão para CONFIG_FILE se não estiver definida
CONFIG_FILE=${CONFIG_FILE:-"/root/2/Archmonkey/config.json"}

[[ -z "$DISCO_AUXILIAR" ]] && { echo -e "${YELLOW}Disco auxiliar nao configurado. Pulando...${NC}"; exit 0; }

setup_logging() {
    [[ "$SIMULATE" == "true" ]] && LOG_DIR="./logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

check_commands() {
    local cmds=("cryptsetup" "parted" "wipefs" "partprobe" "blkid")
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessarios nao encontrados: ${missing[*]}"
        exit 1
    fi
}

get_configuration() {
    # Verificação robusta para modo não interativo
    if [[ -f "$CONFIG_FILE" ]]; then
        NON_INTERACTIVE="true"
        log "$GREEN" "Arquivo de configuracao detectado: $CONFIG_FILE"
        log "$BLUE" "Modo non-interactive ativado automaticamente"
    fi

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log "$BLUE" "Lendo configuracao do arquivo: $CONFIG_FILE"
        
        # Verificar se o jq está instalado
        if ! command -v jq &>/dev/null; then
            log "$RED" "jq necessario para modo non-interactive!"
            log "$YELLOW" "Instalando jq..."
            pacman -Sy jq --noconfirm || {
                log "$RED" "Falha ao instalar jq!"
                exit 1
            }
        fi
        
        # Verificar se o arquivo de configuração existe
        if [[ ! -f "$CONFIG_FILE" ]]; then
            log "$RED" "Arquivo de configuracao nao encontrado: $CONFIG_FILE"
            exit 1
        fi
        
        # Verificar se o JSON é válido
        if ! jq . "$CONFIG_FILE" > /dev/null 2>&1; then
            log "$RED" "Arquivo de configuracao JSON invalido!"
            exit 1
        fi
        
        # Extrair valores com jq
        LUKS_AUX_PASSWORD=$(jq -r '.luks_aux_password // ""' "$CONFIG_FILE")
        LINUX_ONLY=$(jq -r '.linux_only // false' "$CONFIG_FILE")
        
        # Validar valores
        if [[ -z "$LUKS_AUX_PASSWORD" ]] || [[ "$LUKS_AUX_PASSWORD" == "null" ]]; then
            log "$RED" "Senha LUKS auxiliar nao encontrada no arquivo de configuracao!"
            exit 1
        fi
        
        log "$GREEN" "Configuracao carregada: LINUX_ONLY=${LINUX_ONLY}"
        
    else
        echo -e "${YELLOW}Senha LUKS para disco auxiliar:${NC}"
        read -rs LUKS_AUX_PASSWORD
        echo
        echo -e "${YELLOW}Confirme a senha:${NC}"
        read -rs LUKS_AUX_CONFIRM
        echo
        
        if [[ "$LUKS_AUX_PASSWORD" != "$LUKS_AUX_CONFIRM" ]]; then
            log "$RED" "Senhas nao coincidem!"
            exit 1
        fi
        
        if [[ ${#LUKS_AUX_PASSWORD} -lt 8 ]]; then
            echo -e "${RED}Senha muito curta! Use pelo menos 8 caracteres.${NC}"
            exit 1
        fi
        
        echo -e "${YELLOW}Usar ext4 (Linux only) em vez de exFAT? [s/N]:${NC}"
        read -r linux_only
        [[ "$linux_only" =~ ^[Ss]$ ]] && LINUX_ONLY=true || LINUX_ONLY=false
    fi
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 3: DISCO AUXILIAR ==="
    
    check_commands
    get_configuration
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}FORMATAR $DISCO_AUXILIAR? Digite CONFIRM:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operacao cancelada"; exit 0; }
    fi
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Nada foi alterado"; exit 0; }
    
    # Particionar
    log "$BLUE" "Particionando $DISCO_AUXILIAR..."
    wipefs -af "$DISCO_AUXILIAR"
    parted -s "$DISCO_AUXILIAR" mklabel gpt mkpart DATA 0% 100%
    sleep 1
    partprobe "$DISCO_AUXILIAR"
    
    # Detectar particao corretamente
    if [[ "$DISCO_AUXILIAR" =~ nvme|mmcblk|loop ]]; then
        AUX_PART="${DISCO_AUXILIAR}p1"
    else
        AUX_PART="${DISCO_AUXILIAR}1"
    fi
    
    # Verificar se particao foi criada
    if [[ ! -b "$AUX_PART" ]]; then
        log "$RED" "Erro: Particao $AUX_PART nao foi criada!"
        exit 1
    fi
    
    # LUKS
    log "$BLUE" "Criando volume LUKS em $AUX_PART..."
    echo -n "$LUKS_AUX_PASSWORD" | cryptsetup luksFormat \
        --type luks2 \
        --pbkdf argon2id \
        --iter-time 3000 \
        --pbkdf-memory 262144 \
        --batch-mode \
        "$AUX_PART" -
    
    echo -n "$LUKS_AUX_PASSWORD" | cryptsetup open "$AUX_PART" cryptdata -
    
    # Formatar
    if [[ "$LINUX_ONLY" == "true" ]]; then
        log "$BLUE" "Formatando com ext4..."
        if command -v mkfs.ext4 &>/dev/null; then
            mkfs.ext4 -L DATA /dev/mapper/cryptdata
        else
            log "$RED" "mkfs.ext4 nao encontrado!"
            exit 1
        fi
    else
        log "$BLUE" "Formatando com exFAT..."
        if command -v mkfs.exfat &>/dev/null; then
            mkfs.exfat -n DATA /dev/mapper/cryptdata
        elif command -v mkexfatfs &>/dev/null; then
            mkexfatfs -n DATA /dev/mapper/cryptdata
        else
            log "$RED" "mkfs.exfat nao encontrado! Instale exfatprogs ou exfat-utils"
            exit 1
        fi
    fi
    
    AUX_UUID=$(blkid -s UUID -o value "$AUX_PART")
    
    echo "export AUX_PART=\"$AUX_PART\"" >> "$ENV_FILE"
    echo "export AUX_UUID=\"$AUX_UUID\"" >> "$ENV_FILE"
    
    cryptsetup close cryptdata
    
    log "$GREEN" "Disco auxiliar configurado! Proximo: ./fase4-base-system.sh"
}

main