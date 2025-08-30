
# ============================================================================
# FASE 7 - AUTODESTRUIÇÃO 
# ============================================================================
cat << 'EOF_FASE7' > fase7-autodestruicao.sh
#!/bin/bash
# fase7-autodestruicao.sh - Configuração de autodestruição de emergência
# AVISO: Este recurso é EXTREMAMENTE PERIGOSO e IRREVERSÍVEL!

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
SELFDESTRUCT_SCRIPT="/usr/local/bin/selfdestruct-now.sh"

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

# Criar script de autodestruição runtime
create_selfdestruct_script() {
    log "$BLUE" "Criando script de autodestruição"
    
    cat > "$SELFDESTRUCT_SCRIPT" << 'EOF'
#!/bin/bash
# selfdestruct-now.sh - Autodestruição de emergência
# AVISO: ISTO DESTRUIRÁ PERMANENTEMENTE TODOS OS DADOS!

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificar root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERRO: Execute como root${NC}"
    exit 1
fi

# Verificar modo
if [[ "${1:-}" == "--simulate" ]]; then
    SIMULATE=true
    echo -e "${YELLOW}MODO SIMULAÇÃO - Nenhuma operação destrutiva será realizada${NC}"
else
    SIMULATE=false
fi

# Função de destruição
destroy_data() {
    local device="$1"
    
    if [[ "$SIMULATE" == "true" ]]; then
        echo -e "${YELLOW}[SIMULATE] Destruiria: $device${NC}"
        return
    fi
    
    echo -e "${RED}Destruindo $device...${NC}"
    
    # Tentar apagar headers LUKS
    if cryptsetup isLuks "$device" 2>/dev/null; then
        echo "  Apagando headers LUKS..."
        cryptsetup luksErase "$device" --batch-mode || true
    fi
    
    # Verificar se suporta TRIM/discard
    if hdparm -I "$device" 2>/dev/null | grep -q "TRIM supported"; then
        echo "  Executando secure erase via TRIM..."
        blkdiscard -s "$device" || true
    else
        echo "  Sobrescrevendo com dados aleatórios (primeiros 100MB)..."
        dd if=/dev/urandom of="$device" bs=1M count=100 oflag=direct status=progress || true
    fi
}

# Confirmação final
if [[ "$SIMULATE" != "true" ]]; then
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    AUTODESTRUIÇÃO TOTAL                      ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║        TODOS OS DADOS SERÃO PERMANENTEMENTE DESTRUÍDOS!      ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║                  ESTA AÇÃO É IRREVERSÍVEL!                   ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║         Digite: DESTROY-ALL-DATA para continuar              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    read -r confirmation
    if [[ "$confirmation" != "DESTROY-ALL-DATA" ]]; then
        echo -e "${YELLOW}Operação cancelada${NC}"
        exit 0
    fi
    
    echo -e "${RED}Última chance! Digite novamente: DESTROY-ALL-DATA${NC}"
    read -r final_confirmation
    if [[ "$final_confirmation" != "DESTROY-ALL-DATA" ]]; then
        echo -e "${YELLOW}Operação cancelada${NC}"
        exit 0
    fi
fi

echo -e "${RED}Iniciando sequência de autodestruição...${NC}"

# Desmontar tudo
echo "Desmontando sistemas de arquivos..."
if [[ "$SIMULATE" != "true" ]]; then
    swapoff -a 2>/dev/null || true
    umount -a -r 2>/dev/null || true
fi

# Destruir swap
if [[ -b /dev/mapper/cryptswap ]]; then
    destroy_data /dev/mapper/cryptswap
fi

# Listar e destruir todos os dispositivos de bloco
for device in $(lsblk -rno NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}'); do
    if [[ -b "$device" ]]; then
        destroy_data "$device"
    fi
done

# Para cada partição
for device in $(lsblk -rno NAME,TYPE | awk '$2=="part" {print "/dev/"$1}'); do
    if [[ -b "$device" ]]; then
        destroy_data "$device"
    fi
done

if [[ "$SIMULATE" == "true" ]]; then
    echo -e "${YELLOW}[SIMULATE] Simulação concluída - nenhum dado foi destruído${NC}"
else
    echo -e "${RED}DESTRUIÇÃO COMPLETA!${NC}"
    echo -e "${RED}Desligando sistema...${NC}"
    poweroff -f
fi
EOF
    
    chmod +x "$SELFDESTRUCT_SCRIPT"
    log "$GREEN" "Script de autodestruição criado: $SELFDESTRUCT_SCRIPT"
}

# Criar alias seguro
create_safe_alias() {
    log "$BLUE" "Criando alias de segurança"
    
    # Adicionar ao bashrc do root
    cat >> /root/.bashrc << 'EOF'

# Alias de autodestruição com confirmação
alias panic='echo "Use: selfdestruct-now.sh (requer confirmação)"'
alias destroy='echo "Use: selfdestruct-now.sh (requer confirmação)"'
EOF
    
    log "$GREEN" "Aliases de segurança criados"
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
    echo -e "   Para testar: ${YELLOW}$SELFDESTRUCT_SCRIPT --simulate${NC}"
    echo -e "   Para executar: ${RED}$SELFDESTRUCT_SCRIPT${NC}"
    echo
    echo -e "${BLUE}2. Hook initramfs (se habilitado na fase 5):${NC}"
    echo -e "   Ativado por: ${YELLOW}selfdestruct=1${NC} no kernel cmdline"
    echo -e "   Entrada GRUB disponível no menu de boot"
    echo
    echo -e "${RED}AVISOS IMPORTANTES:${NC}"
    echo -e "- A autodestruição é ${RED}IRREVERSÍVEL${NC}"
    echo -e "- Mantenha backups dos headers LUKS em local seguro"
    echo -e "- Teste primeiro com ${YELLOW}--simulate${NC}"
    echo -e "- Requer confirmação dupla digitando: ${RED}DESTROY-ALL-DATA${NC}"
    echo
}

# Função principal
main() {
    setup_logging
    
    log "$BLUE" "=== FASE 7: CONFIGURAÇÃO DE AUTODESTRUIÇÃO ==="
    
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
    
    create_selfdestruct_script
    create_safe_alias
    
    log "$GREEN" "=== FASE 7 CONCLUÍDA ==="
    
    show_usage_info
}

main
EOF_FASE7


