


#!/bin/bash
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Gerando Arch Secure Setup (Versao Final Corrigida) ===${NC}"

# Criar diretorio
mkdir -p arch-secure-setup
cd arch-secure-setup

# ============================================================================
# FASE 1 - PREPARO
# ============================================================================
cat << 'EOF' > fase1-preparo.sh
#!/bin/bash
# fase1-preparo.sh - Deteccao de hardware e preparacao inicial
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuracao
SCRIPT_NAME="fase1-preparo"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
VERSION="1.2.0"

# Variaveis globais
DRY_RUN=false
SIMULATE=false
NON_INTERACTIVE=false
CONFIG_FILE=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) DRY_RUN=true; shift ;;
            --simulate) SIMULATE=true; shift ;;
            --non-interactive) 
                NON_INTERACTIVE=true
                CONFIG_FILE="${2:-config.json}"
                # Converter para caminho absoluto
                if command -v realpath &>/dev/null; then
                    CONFIG_FILE="$(realpath "$CONFIG_FILE" 2>/dev/null || echo "$CONFIG_FILE")"
                else
                    CONFIG_FILE="$(cd "$(dirname "$CONFIG_FILE")" 2>/dev/null && pwd)/$(basename "$CONFIG_FILE")" || CONFIG_FILE="$CONFIG_FILE"
                fi
                shift 2 
                ;;
            --help) show_help; exit 0 ;;
            *) echo -e "${RED}Argumento desconhecido: $1${NC}"; exit 1 ;;
        esac
    done
}

show_help() {
    cat << HELP
Uso: $0 [OPCOES]

OPCOES:
    --dry-run           Simula execucao sem fazer alteracoes
    --simulate          Usa dispositivos loopback para teste
    --non-interactive   Usa arquivo de configuracao JSON
    --help              Mostra esta ajuda
HELP
}

check_commands() {
    local cmds=("lsblk" "free" "nproc")
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessarios nao encontrados: ${missing[*]}"
        log "$YELLOW" "Instale: pacman -S util-linux procps-ng coreutils"
        exit 1
    fi
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if ! command -v "jq" &>/dev/null; then
            log "$RED" "jq necessario para modo non-interactive!"
            log "$YELLOW" "Instale com: pacman -S jq"
            exit 1
        fi
    fi
}

setup_logging() {
    [[ "$SIMULATE" == "true" ]] && LOG_DIR="./logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

check_requirements() {
    log "$BLUE" "Verificando requisitos..."
    
    [[ $EUID -ne 0 ]] && { log "$RED" "Execute como root!"; exit 1; }
    
    check_commands
    
    # Detectar modo de boot
    [[ -d /sys/firmware/efi ]] && BOOT_MODE="UEFI" || BOOT_MODE="BIOS"
    
    log "$GREEN" "Boot mode: $BOOT_MODE"
}

detect_hardware() {
    log "$BLUE" "Detectando hardware..."
    
    CPU_CORES=$(nproc)
    MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
    
    mapfile -t DISKS < <(lsblk -rno NAME,TYPE,SIZE | awk '$2=="disk" {print "/dev/"$1"|"$3}')
    
    if [[ ${#DISKS[@]} -eq 0 ]]; then
        log "$RED" "Nenhum disco detectado!"
        exit 1
    fi
    
    for disk in "${DISKS[@]}"; do
        IFS='|' read -r device size <<< "$disk"
        log "$NC" "  Disco: $device - $size"
    done
}

validate_config_file() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ ! -f "$CONFIG_FILE" ]]; then
            log "$RED" "Arquivo de configuracao nao encontrado: $CONFIG_FILE"
            exit 1
        fi
        
        # Validar JSON
        if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
            log "$RED" "Arquivo JSON invalido: $CONFIG_FILE"
            exit 1
        fi
        
        # Validar campos obrigatorios
        local required_fields=("disco_principal" "hostname" "username" "user_password" "root_password")
        for field in "${required_fields[@]}"; do
            local value=$(jq -r ".$field // \"\"" "$CONFIG_FILE")
            if [[ -z "$value" ]] || [[ "$value" == "null" ]]; then
                log "$RED" "Campo obrigatorio ausente ou vazio: $field"
                exit 1
            fi
        done
    fi
}

select_disks() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        validate_config_file
        DISCO_PRINCIPAL=$(jq -r '.disco_principal' "$CONFIG_FILE")
        DISCO_AUXILIAR=$(jq -r '.disco_auxiliar // ""' "$CONFIG_FILE")
        
        # Validar que os discos existem (exceto em modo simulate)
        if [[ "$SIMULATE" != "true" ]]; then
            if [[ ! -b "$DISCO_PRINCIPAL" ]]; then
                log "$RED" "Disco principal nao existe: $DISCO_PRINCIPAL"
                exit 1
            fi
            
            if [[ -n "$DISCO_AUXILIAR" ]] && [[ "$DISCO_AUXILIAR" != "null" ]] && [[ ! -b "$DISCO_AUXILIAR" ]]; then
                log "$RED" "Disco auxiliar nao existe: $DISCO_AUXILIAR"
                exit 1
            fi
        fi
        
        # Limpar valor null do JSON
        [[ "$DISCO_AUXILIAR" == "null" ]] && DISCO_AUXILIAR=""
    else
        echo -e "${YELLOW}Discos disponiveis:${NC}"
        local i=1
        for disk in "${DISKS[@]}"; do
            IFS='|' read -r device size <<< "$disk"
            echo "  $i) $device - $size"
            ((i++))
        done
        
        echo -e "${YELLOW}Numero do disco PRINCIPAL:${NC}"
        read -r disk_num
        
        if [[ ! "$disk_num" =~ ^[0-9]+$ ]] || [[ "$disk_num" -lt 1 ]] || [[ "$disk_num" -gt ${#DISKS[@]} ]]; then
            log "$RED" "Numero de disco invalido!"
            exit 1
        fi
        
        IFS='|' read -r DISCO_PRINCIPAL _ <<< "${DISKS[$((disk_num-1))]}"
        
        echo -e "${YELLOW}Disco AUXILIAR? [s/N]:${NC}"
        read -r aux
        if [[ "$aux" =~ ^[Ss]$ ]]; then
            echo -e "${YELLOW}Numero do disco AUXILIAR:${NC}"
            read -r disk_num
            
            if [[ ! "$disk_num" =~ ^[0-9]+$ ]] || [[ "$disk_num" -lt 1 ]] || [[ "$disk_num" -gt ${#DISKS[@]} ]]; then
                log "$RED" "Numero de disco invalido!"
                exit 1
            fi
            
            IFS='|' read -r DISCO_AUXILIAR _ <<< "${DISKS[$((disk_num-1))]}"
        else
            DISCO_AUXILIAR=""
        fi
    fi
}

save_configuration() {
    cat > "$ENV_FILE" << CONFIG
export DRY_RUN="$DRY_RUN"
export SIMULATE="$SIMULATE"
export NON_INTERACTIVE="$NON_INTERACTIVE"
export CONFIG_FILE="$CONFIG_FILE"
export BOOT_MODE="$BOOT_MODE"
export CPU_CORES="$CPU_CORES"
export MEM_TOTAL="$MEM_TOTAL"
export DISCO_PRINCIPAL="$DISCO_PRINCIPAL"
export DISCO_AUXILIAR="$DISCO_AUXILIAR"
CONFIG
    log "$GREEN" "Configuracao salva em $ENV_FILE"
}

main() {
    parse_args "$@"
    setup_logging
    log "$BLUE" "=== FASE 1: PREPARACAO ==="
    check_requirements
    detect_hardware
    select_disks
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}AVISO: OS DISCOS SELECIONADOS SERAO FORMATADOS!${NC}"
        echo -e "${RED}Disco principal: $DISCO_PRINCIPAL${NC}"
        [[ -n "$DISCO_AUXILIAR" ]] && echo -e "${RED}Disco auxiliar: $DISCO_AUXILIAR${NC}"
        echo -e "${RED}TODOS OS DADOS SERAO PERDIDOS!${NC}"
        echo -e "${RED}Digite CONFIRM para continuar:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operacao cancelada"; exit 0; }
    fi
    
    save_configuration
    log "$GREEN" "Fase 1 concluida! Proximo: ./fase2-disco-principal.sh"
}

main "$@"
EOF
