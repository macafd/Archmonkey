#!/bin/bash
# ============================================================================
# FASE 4 - SISTEMA BASE - VERSÃO CORRIGIDA
# ============================================================================
# fase4-base-system.sh - Instalação do sistema base Arch Linux
# Autor: Security Expert
# Versão: 2.0
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configurações do script
readonly SCRIPT_NAME="fase4-base-system"
readonly SCRIPT_VERSION="2.0"
readonly ENV_FILE="/tmp/arch_setup_vars.env"

# Variáveis de log
LOG_DIR="/var/log/arch-secure-setup"
LOG_FILE=""

# Trap para limpeza em caso de erro
trap 'error_handler $? $LINENO' ERR
trap cleanup EXIT

error_handler() {
    local exit_code=$1
    local line_no=$2
    log "$RED" "ERRO: Comando falhou com código $exit_code na linha $line_no"
    cleanup
    exit "$exit_code"
}

cleanup() {
    # Limpeza de recursos temporários se necessário
    if [[ -n "${TMP_DIR:-}" ]] && [[ -d "${TMP_DIR:-}" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_logging() {
    # Configurar diretório de logs
    if [[ "${SIMULATE:-false}" == "true" ]]; then
        LOG_DIR="./logs"
    fi
    
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo -e "${RED}Erro ao criar diretório de logs: $LOG_DIR${NC}"
        exit 1
    fi
    
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
    
    # Criar arquivo de log com permissões seguras
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log no arquivo
    echo "[${timestamp}] $message" >> "$LOG_FILE"
    
    # Output no terminal com cores
    echo -e "${level}[${timestamp}] $message${NC}"
}

check_environment() {
    log "$BLUE" "Verificando ambiente de execução..."
    
    # Verificar se está rodando como root
    if [[ $EUID -ne 0 ]]; then
        log "$RED" "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Verificar arquivo de variáveis de ambiente
    if [[ ! -f "$ENV_FILE" ]]; then
        log "$RED" "Arquivo de configuração não encontrado: $ENV_FILE"
        log "$YELLOW" "Execute as fases anteriores primeiro!"
        exit 1
    fi
    
    # Carregar variáveis de ambiente
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    
    # Verificar variáveis obrigatórias
    local required_vars=("BOOT_MODE" "DISK" "DRY_RUN")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log "$RED" "Variável obrigatória não definida: $var"
            exit 1
        fi
    done
}

check_network() {
    log "$BLUE" "Verificando conectividade de rede..."
    
    if ! ping -c 1 -W 2 archlinux.org &>/dev/null; then
        log "$YELLOW" "Aviso: Sem conectividade com archlinux.org"
        log "$YELLOW" "Tentando DNS alternativo..."
        
        if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
            log "$RED" "Erro: Sem conectividade de rede!"
            log "$YELLOW" "Verifique sua conexão com a internet"
            exit 1
        fi
    fi
    
    log "$GREEN" "Conectividade de rede OK"
}

check_mounts() {
    log "$BLUE" "Verificando pontos de montagem..."
    
    # Verificar montagem principal
    if ! mountpoint -q /mnt; then
        log "$RED" "Erro: /mnt não está montado!"
        log "$YELLOW" "Execute a fase 2 primeiro ou monte manualmente"
        exit 1
    fi
    
    # Verificar montagem de boot
    if ! mountpoint -q /mnt/boot; then
        log "$RED" "Erro: /mnt/boot não está montado!"
        exit 1
    fi
    
    # Verificar montagem EFI se UEFI
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        if ! mountpoint -q /mnt/boot/efi; then
            log "$RED" "Erro: /mnt/boot/efi não está montado (modo UEFI)!"
            exit 1
        fi
    fi
    
    log "$GREEN" "Pontos de montagem verificados"
}

update_mirrorlist() {
    log "$BLUE" "Atualizando mirrorlist..."
    
    # Backup do mirrorlist atual
    cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
    
    # Usar reflector se disponível
    if command -v reflector &>/dev/null; then
        log "$CYAN" "Usando reflector para otimizar mirrors..."
        reflector --country Brazil,US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist
    else
        log "$YELLOW" "Reflector não disponível, usando mirrorlist padrão"
    fi
    
    # Atualizar base de dados do pacman
    pacman -Syy
}

install_base_system() {
    log "$BLUE" "Instalando sistema base..."
    
    # Lista de pacotes essenciais
    local packages=(
        # Sistema base
        base base-devel
        linux linux-firmware linux-headers
        
        # Bootloader e criptografia
        grub efibootmgr
        cryptsetup lvm2 device-mapper
        
        # Sistema de arquivos
        btrfs-progs xfsprogs
        exfatprogs dosfstools ntfs-3g
        
        # Rede
        networkmanager nm-connection-editor network-manager-applet
        dhcpcd iwd wireless_tools wpa_supplicant
        
        # Ferramentas essenciais
        vim nano
        sudo wget curl git
        zsh bash-completion
        
        # Microcode
        intel-ucode amd-ucode
        
        # Utilitários
        man-db man-pages texinfo
        hdparm smartmontools
        openssh rsync
        jq gnupg tar zip unzip
        htop btop neofetch
        
        # Ferramentas de desenvolvimento
        gcc make cmake
        python python-pip
    )
    
    # Converter array em string
    local package_list="${packages[*]}"
    
    log "$CYAN" "Pacotes a serem instalados:"
    for pkg in "${packages[@]}"; do
        echo "  - $pkg" | tee -a "$LOG_FILE"
    done
    
    # Instalar pacotes
    if ! pacstrap -K /mnt $package_list; then
        log "$RED" "Erro ao instalar sistema base!"
        log "$YELLOW" "Verifique logs em: $LOG_FILE"
        exit 1
    fi
    
    log "$GREEN" "Sistema base instalado com sucesso!"
}

generate_fstab() {
    log "$BLUE" "Gerando fstab..."
    
    # Backup se já existir
    if [[ -f /mnt/etc/fstab ]]; then
        cp /mnt/etc/fstab /mnt/etc/fstab.backup
    fi
    
    # Gerar fstab com UUIDs
    genfstab -U /mnt > /mnt/etc/fstab
    
    # Adicionar opções de segurança
    log "$CYAN" "Aplicando opções de segurança ao fstab..."
    
    # Adicionar nodev,nosuid,noexec para /tmp se existir
    if grep -q '/tmp' /mnt/etc/fstab; then
        sed -i '/\/tmp/s/defaults/defaults,nodev,nosuid,noexec/' /mnt/etc/fstab
    fi
    
    # Mostrar fstab gerado
    log "$CYAN" "fstab gerado:"
    cat /mnt/etc/fstab | tee -a "$LOG_FILE"
}

copy_setup_files() {
    log "$BLUE" "Copiando arquivos de configuração..."
    
    # Criar diretórios necessários
    mkdir -p /mnt/root/setup
    mkdir -p /mnt/tmp
    
    # Copiar arquivo de variáveis
    cp "$ENV_FILE" /mnt/tmp/
    
    # Copiar arquivo de configuração JSON se existir
    if [[ -n "${CONFIG_FILE:-}" ]] && [[ -f "${CONFIG_FILE:-}" ]]; then
        cp "$CONFIG_FILE" /mnt/tmp/config.json
        echo "export CONFIG_FILE=\"/tmp/config.json\"" >> /mnt/tmp/arch_setup_vars.env
        log "$GREEN" "Arquivo de configuração copiado"
    fi
    
    # Copiar scripts das próximas fases
    local scripts=(
        "fase5-config-chroot.sh"
        "fase6-backup-scripts.sh"
        "fase7-autodestruicao.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            cp "$script" /mnt/root/setup/
            chmod +x /mnt/root/setup/"$script"
            log "$GREEN" "Script copiado: $script"
        else
            log "$YELLOW" "Aviso: Script não encontrado: $script"
        fi
    done
    
    # Criar script helper para facilitar chroot
    cat > /mnt/root/setup/enter-chroot.sh << 'CHROOT_SCRIPT'
#!/bin/bash
# Script helper para entrar no chroot
echo "Entrando no ambiente chroot..."
echo "Para continuar a instalação, execute:"
echo "  cd /root/setup && ./fase5-config-chroot.sh"
echo ""
exec /bin/bash
CHROOT_SCRIPT
    
    chmod +x /mnt/root/setup/enter-chroot.sh
}

show_summary() {
    log "$GREEN" "============================================"
    log "$GREEN" "       FASE 4 CONCLUÍDA COM SUCESSO!"
    log "$GREEN" "============================================"
    log "$CYAN" "Sistema base instalado em: ${DISK}"
    log "$CYAN" "Modo de boot: ${BOOT_MODE}"
    log "$CYAN" "Log salvo em: $LOG_FILE"
    echo ""
    log "$YELLOW" "PRÓXIMOS PASSOS:"
    log "$YELLOW" "1. Entre no chroot:"
    log "$BLUE" "   arch-chroot /mnt /root/setup/enter-chroot.sh"
    log "$YELLOW" "2. No chroot, execute:"
    log "$BLUE" "   cd /root/setup && ./fase5-config-chroot.sh"
    echo ""
    log "$CYAN" "Dica: Você pode revisar o fstab em /mnt/etc/fstab"
}

main() {
    log "$BLUE" "=========================================="
    log "$BLUE" "    FASE 4: INSTALAÇÃO DO SISTEMA BASE"
    log "$BLUE" "    Versão: $SCRIPT_VERSION"
    log "$BLUE" "=========================================="
    
    # Verificações iniciais
    check_environment
    
    # Modo dry-run
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log "$YELLOW" "MODO DRY-RUN: Simulando instalação..."
        log "$CYAN" "Verificações que seriam realizadas:"
        echo "  - Verificação de rede"
        echo "  - Verificação de montagens"
        echo "  - Atualização de mirrorlist"
        echo "  - Instalação de pacotes base"
        echo "  - Geração de fstab"
        echo "  - Cópia de arquivos de setup"
        log "$GREEN" "Simulação concluída!"
        exit 0
    fi
    
    # Executar instalação
    check_network
    check_mounts
    update_mirrorlist
    install_base_system
    generate_fstab
    copy_setup_files
    
    # Mostrar resumo
    show_summary
}

# Configurar logging
setup_logging

# Executar script principal
main "$@"