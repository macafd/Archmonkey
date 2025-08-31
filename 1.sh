#!/bin/bash
# generate-arch-secure-setup-FIXED.sh
# Script gerador do pacote Arch Secure Setup - VERSÃO CORRIGIDA
# Correções aplicadas:
# - UUID do swap corrigido
# - Verificação de comandos melhorada
# - CONFIG_FILE propagado corretamente
# - Tratamento de erros aprimorado
# - Verificações de segurança adicionadas

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Gerando Arch Secure Setup (Versão Corrigida) ===${NC}"

# Criar diretório
mkdir -p arch-secure-setup
cd arch-secure-setup

# ============================================================================
# FASE 1 - PREPARO (CORRIGIDA)
# ============================================================================
cat << 'EOF' > fase1-preparo.sh
#!/bin/bash
# fase1-preparo.sh - Detecção de hardware e preparação inicial
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuração
SCRIPT_NAME="fase1-preparo"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
VERSION="1.1.0"

# Variáveis globais
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
                CONFIG_FILE="$(realpath "$CONFIG_FILE" 2>/dev/null || echo "$CONFIG_FILE")"
                shift 2 
                ;;
            --help) show_help; exit 0 ;;
            *) echo -e "${RED}Argumento desconhecido: $1${NC}"; exit 1 ;;
        esac
    done
}

show_help() {
    cat << HELP
Uso: $0 [OPÇÕES]

OPÇÕES:
    --dry-run           Simula execução sem fazer alterações
    --simulate          Usa dispositivos loopback para teste
    --non-interactive   Usa arquivo de configuração JSON
    --help              Mostra esta ajuda
HELP
}

check_commands() {
    local cmds=("lsblk" "free" "nproc" "realpath")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "$RED" "Comando necessário não encontrado: $cmd"
            exit 1
        fi
    done
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if ! command -v "jq" &>/dev/null; then
            log "$RED" "jq necessário para modo non-interactive!"
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
            log "$RED" "Arquivo de configuração não encontrado: $CONFIG_FILE"
            exit 1
        fi
        
        # Validar JSON
        if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
            log "$RED" "Arquivo JSON inválido: $CONFIG_FILE"
            exit 1
        fi
        
        # Validar campos obrigatórios
        local required_fields=("disco_principal" "hostname" "username")
        for field in "${required_fields[@]}"; do
            if ! jq -e ".$field" "$CONFIG_FILE" &>/dev/null; then
                log "$RED" "Campo obrigatório ausente no config: $field"
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
                log "$RED" "Disco principal não existe: $DISCO_PRINCIPAL"
                exit 1
            fi
            
            if [[ -n "$DISCO_AUXILIAR" && ! -b "$DISCO_AUXILIAR" ]]; then
                log "$RED" "Disco auxiliar não existe: $DISCO_AUXILIAR"
                exit 1
            fi
        fi
    else
        echo -e "${YELLOW}Discos disponíveis:${NC}"
        local i=1
        for disk in "${DISKS[@]}"; do
            IFS='|' read -r device size <<< "$disk"
            echo "  $i) $device - $size"
            ((i++))
        done
        
        echo -e "${YELLOW}Número do disco PRINCIPAL:${NC}"
        read -r disk_num
        
        if [[ ! "$disk_num" =~ ^[0-9]+$ ]] || [[ "$disk_num" -lt 1 ]] || [[ "$disk_num" -gt ${#DISKS[@]} ]]; then
            log "$RED" "Número de disco inválido!"
            exit 1
        fi
        
        IFS='|' read -r DISCO_PRINCIPAL _ <<< "${DISKS[$((disk_num-1))]}"
        
        echo -e "${YELLOW}Disco AUXILIAR? [s/N]:${NC}"
        read -r aux
        if [[ "$aux" =~ ^[Ss]$ ]]; then
            echo -e "${YELLOW}Número do disco AUXILIAR:${NC}"
            read -r disk_num
            
            if [[ ! "$disk_num" =~ ^[0-9]+$ ]] || [[ "$disk_num" -lt 1 ]] || [[ "$disk_num" -gt ${#DISKS[@]} ]]; then
                log "$RED" "Número de disco inválido!"
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
    log "$GREEN" "Configuração salva em $ENV_FILE"
}

main() {
    parse_args "$@"
    setup_logging
    log "$BLUE" "=== FASE 1: PREPARAÇÃO ==="
    check_requirements
    detect_hardware
    select_disks
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}AVISO: OS DISCOS SELECIONADOS SERÃO FORMATADOS!${NC}"
        echo -e "${RED}Disco principal: $DISCO_PRINCIPAL${NC}"
        [[ -n "$DISCO_AUXILIAR" ]] && echo -e "${RED}Disco auxiliar: $DISCO_AUXILIAR${NC}"
        echo -e "${RED}TODOS OS DADOS SERÃO PERDIDOS!${NC}"
        echo -e "${RED}Digite CONFIRM para continuar:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operação cancelada"; exit 0; }
    fi
    
    save_configuration
    log "$GREEN" "Fase 1 concluída! Próximo: ./fase2-disco-principal.sh"
}

main "$@"
EOF
