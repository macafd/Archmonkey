#!/bin/bash
# fase7-autodestruicao.sh - Configuração de autodestruição (CORRIGIDO)
# EXECUTE DENTRO DO CHROOT

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuração
SCRIPT_NAME="fase7-autodestruicao"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
SELFDESTRUCT_SCRIPT="/usr/local/bin/selfdestruct-now.sh"

# Carregar configuração se existir
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
fi

# Setup logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"
    shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

# Verificar comandos necessários
check_commands() {
    local cmds=("cryptsetup" "dd" "blkdiscard" "lsblk" "sync" "poweroff")
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$YELLOW" "Comandos ausentes: ${missing[*]}"
        log "$YELLOW" "Alguns recursos podem não funcionar completamente"
    fi
}

# Criar script de autodestruição runtime
create_selfdestruct_script() {
    log "$BLUE" "Criando script de autodestruição"
    
    cat > "$SELFDESTRUCT_SCRIPT" << 'SELFDESTRUCT_EOF'
#!/bin/bash
# selfdestruct-now.sh - Autodestruição de emergência
# AVISO: ISTO DESTRUIRÁ PERMANENTEMENTE TODOS OS DADOS!

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuração
LOG_FILE="/var/log/selfdestruct-$(date +%Y%m%d-%H%M%S).log"

# Função de log
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo -e "$msg" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$msg"
}

# Verificar root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERRO: Execute como root${NC}"
    exit 1
fi

# Verificar modo
SIMULATE=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --simulate)
            SIMULATE=true
            log "${YELLOW}MODO SIMULAÇÃO - Nenhuma operação destrutiva será realizada${NC}"
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            echo "Uso: $0 [--simulate] [--force]"
            echo "  --simulate : Simula operações sem destruir dados"
            echo "  --force    : Pula confirmações (PERIGOSO!)"
            exit 0
            ;;
        *)
            echo -e "${RED}Opção desconhecida: $1${NC}"
            exit 1
            ;;
    esac
done

# Função de destruição
destroy_data() {
    local device="$1"
    local device_type="${2:-disk}"
    
    if [[ ! -b "$device" ]]; then
        log "${YELLOW}Dispositivo não existe: $device${NC}"
        return
    fi
    
    if [[ "$SIMULATE" == "true" ]]; then
        log "${YELLOW}[SIMULATE] Destruiria: $device${NC}"
        return
    fi
    
    log "${RED}Destruindo $device...${NC}"
    
    # Tentar apagar headers LUKS
    if command -v cryptsetup &>/dev/null; then
        if cryptsetup isLuks "$device" 2>/dev/null; then
            log "  Apagando headers LUKS..."
            cryptsetup luksErase "$device" --batch-mode 2>/dev/null || \
                log "${YELLOW}  Falha ao apagar headers LUKS${NC}"
        fi
    fi
    
    # Verificar se suporta TRIM/discard
    local use_discard=false
    local device_base=$(basename "$device")
    
    # Verificar suporte a discard
    if command -v blkdiscard &>/dev/null; then
        if [[ -f "/sys/block/${device_base}/queue/discard_max_bytes" ]]; then
            local discard_max=$(cat "/sys/block/${device_base}/queue/discard_max_bytes" 2>/dev/null || echo "0")
            if [[ "$discard_max" != "0" ]]; then
                use_discard=true
            fi
        fi
    fi
    
    if [[ "$use_discard" == "true" ]]; then
        log "  Executando secure erase via TRIM..."
        if blkdiscard -f "$device" 2>/dev/null; then
            log "${GREEN}  TRIM executado com sucesso${NC}"
        else
            log "${YELLOW}  TRIM falhou, tentando método alternativo${NC}"
            use_discard=false
        fi
    fi
    
    # Fallback para sobrescrita com dd
    if [[ "$use_discard" == "false" ]]; then
        if command -v dd &>/dev/null; then
            log "  Sobrescrevendo com dados aleatórios (primeiros 100MB)..."
            
            # Usar /dev/urandom se disponível, senão /dev/zero
            local source="/dev/urandom"
            [[ ! -c "$source" ]] && source="/dev/zero"
            
            if dd if="$source" of="$device" bs=1M count=100 oflag=direct status=none 2>/dev/null; then
                log "${GREEN}  Sobrescrita concluída${NC}"
            else
                log "${YELLOW}  Sobrescrita parcial ou falhou${NC}"
            fi
        else
            log "${RED}  dd não disponível para sobrescrita${NC}"
        fi
    fi
}

# Confirmação final
if [[ "$SIMULATE" != "true" ]] && [[ "$FORCE" != "true" ]]; then
    echo
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    AUTODESTRUIÇÃO TOTAL                      ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║        TODOS OS DADOS SERÃO PERMANENTEMENTE DESTRUÍDOS!      ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║                  ESTA AÇÃO É IRREVERSÍVEL!                   ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║         Digite: DESTROY-ALL-DATA para continuar              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    read -r confirmation
    if [[ "$confirmation" != "DESTROY-ALL-DATA" ]]; then
        log "${YELLOW}Operação cancelada${NC}"
        exit 0
    fi
    
    echo
    echo -e "${RED}Última chance! Digite novamente: DESTROY-ALL-DATA${NC}"
    read -r final_confirmation
    if [[ "$final_confirmation" != "DESTROY-ALL-DATA" ]]; then
        log "${YELLOW}Operação cancelada${NC}"
        exit 0
    fi
fi

log "${RED}Iniciando sequência de autodestruição...${NC}"

# Sincronizar dados pendentes
log "Sincronizando dados pendentes..."
sync

# Desmontar sistemas de arquivos
if [[ "$SIMULATE" != "true" ]]; then
    log "Desmontando sistemas de arquivos..."
    
    # Desativar swap
    swapoff -a 2>/dev/null || log "${YELLOW}Swap já desativado ou não existe${NC}"
    
    # Tentar desmontar tudo exceto filesystems críticos
    for mount in $(findmnt -rno TARGET | grep -v -E '^/(sys|proc|dev|run)?$' | tac); do
        umount -l "$mount" 2>/dev/null || true
    done
fi

# Destruir swap criptografado
if [[ -b /dev/mapper/cryptswap ]]; then
    destroy_data /dev/mapper/cryptswap "swap"
fi

# Detectar e destruir dispositivos
log "Detectando dispositivos..."

# Partições primeiro (mais específico)
if command -v lsblk &>/dev/null; then
    while IFS= read -r device; do
        if [[ -n "$device" ]] && [[ -b "/dev/$device" ]]; then
            destroy_data "/dev/$device" "part"
        fi
    done < <(lsblk -rno NAME,TYPE | awk '$2=="part" {print $1}' | sort -u)
    
    # Depois discos inteiros
    while IFS= read -r device; do
        if [[ -n "$device" ]] && [[ -b "/dev/$device" ]]; then
            destroy_data "/dev/$device" "disk"
        fi
    done < <(lsblk -rno NAME,TYPE | awk '$2=="disk" {print $1}' | sort -u)
else
    # Fallback se lsblk não estiver disponível
    for device in /dev/sd[a-z] /dev/nvme[0-9]n[0-9] /dev/mmcblk[0-9]; do
        [[ -b "$device" ]] && destroy_data "$device" "disk"
    done
fi

# Sincronizar uma última vez
sync

if [[ "$SIMULATE" == "true" ]]; then
    log "${YELLOW}[SIMULATE] Simulação concluída - nenhum dado foi destruído${NC}"
else
    log "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    log "${RED}║                   DESTRUIÇÃO COMPLETA!                       ║${NC}"
    log "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    # Tentar desligar o sistema
    if command -v poweroff &>/dev/null; then
        log "${RED}Desligando sistema em 5 segundos...${NC}"
        sleep 5
        poweroff -f
    elif command -v halt &>/dev/null; then
        halt -f
    else
        log "${RED}Sistema destruído. Desligue manualmente.${NC}"
    fi
fi
SELFDESTRUCT_EOF
    
    chmod +x "$SELFDESTRUCT_SCRIPT"
    log "$GREEN" "Script de autodestruição criado: $SELFDESTRUCT_SCRIPT"
}

# Criar alias seguro
create_safe_alias() {
    log "$BLUE" "Criando aliases de segurança"
    
    # Adicionar ao bashrc do root se não existir
    if ! grep -q "alias panic=" /root/.bashrc 2>/dev/null; then
        cat >> /root/.bashrc << 'ALIAS_EOF'

# Aliases de autodestruição com confirmação
alias panic='echo "Use: selfdestruct-now.sh (requer confirmação)"'
alias destroy='echo "Use: selfdestruct-now.sh (requer confirmação)"'
ALIAS_EOF
        log "$GREEN" "Aliases de segurança criados"
    else
        log "$YELLOW" "Aliases já existem"
    fi
}

# Criar script de teste
create_test_script() {
    log "$BLUE" "Criando script de teste"
    
    local TEST_SCRIPT="/usr/local/bin/test-selfdestruct.sh"
    cat > "$TEST_SCRIPT" << 'TEST_EOF'
#!/bin/bash
# test-selfdestruct.sh - Teste do sistema de autodestruição

echo "Testando sistema de autodestruição em modo simulação..."
echo
/usr/local/bin/selfdestruct-now.sh --simulate
echo
echo "Teste concluído. Para executar destruição real:"
echo "  /usr/local/bin/selfdestruct-now.sh"
echo
echo "AVISO: A execução real DESTRUIRÁ TODOS OS DADOS!"
TEST_EOF
    
    chmod +x "$TEST_SCRIPT"
    log "$GREEN" "Script de teste criado: $TEST_SCRIPT"
}

# Informações de uso
show_usage_info() {
    echo
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           SISTEMA DE AUTODESTRUIÇÃO INSTALADO                ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}COMPONENTES INSTALADOS:${NC}"
    echo
    echo -e "${BLUE}1. Script de autodestruição runtime:${NC}"
    echo -e "   ${GREEN}$SELFDESTRUCT_SCRIPT${NC}"
    echo -e "   Opções:"
    echo -e "   ${YELLOW}--simulate${NC} : Testa sem destruir"
    echo -e "   ${YELLOW}--force${NC}    : Pula confirmações (PERIGOSO!)"
    echo
    echo -e "${BLUE}2. Script de teste:${NC}"
    echo -e "   ${GREEN}/usr/local/bin/test-selfdestruct.sh${NC}"
    echo
    echo -e "${BLUE}3. Hook initramfs (se habilitado na fase 5):${NC}"
    echo -e "   Ativado por: ${YELLOW}selfdestruct=1${NC} no kernel cmdline"
    echo -e "   Entrada GRUB disponível no menu de boot"
    echo
    echo -e "${RED}AVISOS IMPORTANTES:${NC}"
    echo -e "- A autodestruição é ${RED}IRREVERSÍVEL${NC}"
    echo -e "- Mantenha backups dos headers LUKS em local seguro"
    echo -e "- Teste primeiro com ${YELLOW}--simulate${NC}"
    echo -e "- Requer confirmação dupla digitando: ${RED}DESTROY-ALL-DATA${NC}"
    echo
    echo -e "${YELLOW}Para testar:${NC} /usr/local/bin/test-selfdestruct.sh"
    echo -e "${RED}Para executar:${NC} $SELFDESTRUCT_SCRIPT"
    echo
}

# Função principal
main() {
    setup_logging
    
    log "$BLUE" "=== FASE 7: CONFIGURAÇÃO DE AUTODESTRUIÇÃO ==="
    
    # Verificar se está no chroot ou sistema instalado
    if [[ ! -d /boot ]] && [[ ! -d /etc ]]; then
        log "$RED" "ERRO: Execute este script no sistema instalado ou chroot!"
        exit 1
    fi
    
    check_commands
    
    # Verificar modo de instalação
    local INSTALL_MODE="interactive"
    
    if [[ "${NON_INTERACTIVE:-false}" == "true" ]]; then
        INSTALL_MODE="non-interactive"
        if [[ -f "${CONFIG_FILE:-}" ]]; then
            if command -v jq &>/dev/null; then
                local AUTODESTRUCT=$(jq -r '.autodestruct_enabled // false' "$CONFIG_FILE" 2>/dev/null || echo "false")
                if [[ "$AUTODESTRUCT" != "true" ]]; then
                    log "$YELLOW" "Autodestruição não habilitada no config. Pulando..."
                    exit 0
                fi
            fi
        else
            log "$YELLOW" "Config file não encontrado. Usando modo interativo."
            INSTALL_MODE="interactive"
        fi
    fi
    
    if [[ "$INSTALL_MODE" == "interactive" ]]; then
        echo
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                         ATENÇÃO!                             ║${NC}"
        echo -e "${RED}║                                                              ║${NC}"
        echo -e "${RED}║     Este recurso permite a DESTRUIÇÃO TOTAL dos dados!       ║${NC}"
        echo -e "${RED}║                                                              ║${NC}"
        echo -e "${RED}║              Use apenas se absolutamente necessário          ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${YELLOW}Instalar sistema de autodestruição? [s/N]:${NC}"
        read -r install_input
        
        if [[ ! "$install_input" =~ ^[Ss]$ ]]; then
            log "$YELLOW" "Instalação cancelada"
            exit 0
        fi
        
        echo -e "${RED}Digite CONFIRM para instalar o sistema de autodestruição:${NC}"
        read -r confirmation
        
        if [[ "$confirmation" != "CONFIRM" ]]; then
            log "$YELLOW" "Instalação cancelada"
            exit 0
        fi
    fi
    
    create_selfdestruct_script
    create_safe_alias
    create_test_script
    
    log "$GREEN" "=== FASE 7 CONCLUÍDA ==="
    
    show_usage_info
}

main "$@"
