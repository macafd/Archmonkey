#!/bin/bash
# ============================================================================
# FASE 4 - SISTEMA BASE COM GRUB CRIPTOGRAFADO - VERSÃO ENHANCED
# ============================================================================
# fase4-base-system-encrypted.sh - Instalação com suporte a GRUB criptografado
# Autor: Security Expert
# Versão: 3.0
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# Configurações do script
readonly SCRIPT_NAME="fase4-base-system-encrypted"
readonly SCRIPT_VERSION="3.0"
readonly ENV_FILE="/tmp/arch_setup_vars.env"
readonly KEYFILE_NAME="crypto_keyfile.bin"
readonly KEYFILE_SIZE=4096

# Variáveis de log
LOG_DIR="/var/log/arch-secure-setup"
LOG_FILE=""

# Variáveis globais para criptografia
LUKS_UUID=""
LUKS_DEVICE=""
BOOT_PARTITION=""
ROOT_PARTITION=""

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
    # Limpeza segura de arquivos temporários
    if [[ -n "${TMP_DIR:-}" ]] && [[ -d "${TMP_DIR:-}" ]]; then
        # Sobrescrever arquivos sensíveis antes de deletar
        find "$TMP_DIR" -type f -exec shred -vfz {} \; 2>/dev/null || true
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

    # Detectar partições automaticamente se não definidas
    detect_partitions
}

detect_partitions() {
    log "$BLUE" "Detectando configuração de partições..."

    # Verificar se é NVMe ou SATA
    if [[ "$DISK" == *"nvme"* ]]; then
        BOOT_PARTITION="${DISK}p1"
        LUKS_DEVICE="${DISK}p2"
    else
        BOOT_PARTITION="${DISK}1"
        LUKS_DEVICE="${DISK}2"
    fi

    # Detectar se está usando criptografia
    if [[ -e /dev/mapper/cryptroot ]]; then
        ROOT_PARTITION="/dev/mapper/cryptroot"
        LUKS_UUID=$(cryptsetup luksUUID "$LUKS_DEVICE" 2>/dev/null || echo "")
        log "$GREEN" "Criptografia LUKS detectada"
        log "$CYAN" "  LUKS Device: $LUKS_DEVICE"
        log "$CYAN" "  LUKS UUID: $LUKS_UUID"
        log "$CYAN" "  Root: $ROOT_PARTITION"
        
        # Salvar informações de criptografia
        echo "LUKS_DEVICE=\"$LUKS_DEVICE\"" >> "$ENV_FILE"
        echo "LUKS_UUID=\"$LUKS_UUID\"" >> "$ENV_FILE"
        echo "ROOT_PARTITION=\"$ROOT_PARTITION\"" >> "$ENV_FILE"
        echo "BOOT_PARTITION=\"$BOOT_PARTITION\"" >> "$ENV_FILE"
        echo "ENCRYPTION_ENABLED=\"true\"" >> "$ENV_FILE"
    else
        ROOT_PARTITION="${DISK}2"
        log "$YELLOW" "Sistema sem criptografia detectado"
        echo "ENCRYPTION_ENABLED=\"false\"" >> "$ENV_FILE"
    fi
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
            log "$YELLOW" "Aviso: /mnt/boot/efi não está montado"
            log "$CYAN" "Criando e montando partição EFI..."
            mkdir -p /mnt/boot/efi
            mount "$BOOT_PARTITION" /mnt/boot/efi
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
    log "$BLUE" "Instalando sistema base com suporte a criptografia..."

    # Lista de pacotes essenciais com suporte a criptografia
    local packages=(
        # Sistema base
        base base-devel
        linux linux-firmware linux-headers

        # Bootloader e criptografia COMPLETA
        grub efibootmgr os-prober
        cryptsetup lvm2 device-mapper
        
        # IMPORTANTE: Pacotes para GRUB criptografado
        grub-btrfs  # Se usar BTRFS
        mkinitcpio-encrypt-detached-header  # Para headers destacados
        argon2  # Para Argon2 key derivation

        # Sistema de arquivos
        btrfs-progs xfsprogs
        exfatprogs dosfstools ntfs-3g
        e2fsprogs  # Para ext4

        # Rede
        networkmanager nm-connection-editor network-manager-applet
        dhcpcd iwd wireless_tools wpa_supplicant
        openvpn wireguard-tools  # VPN

        # Ferramentas essenciais
        vim nano
        sudo wget curl git
        zsh bash-completion
        tmux screen

        # Segurança
        gnupg pass
        ufw fail2ban
        rkhunter aide
        apparmor

        # Microcode
        intel-ucode amd-ucode

        # Utilitários
        man-db man-pages texinfo
        hdparm smartmontools
        openssh rsync
        jq tar zip unzip p7zip
        htop btop neofetch
        lsof strace

        # Ferramentas de desenvolvimento
        gcc make cmake
        python python-pip
        go rust
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

create_luks_keyfile() {
    log "$MAGENTA" "========================================"
    log "$MAGENTA" "    CONFIGURANDO KEYFILE PARA LUKS"
    log "$MAGENTA" "========================================"

    # Verificar se a criptografia está habilitada
    if [[ "${ENCRYPTION_ENABLED:-false}" != "true" ]]; then
        log "$YELLOW" "Sistema sem criptografia, pulando criação de keyfile"
        return 0
    fi

    local keyfile_path="/mnt/root/$KEYFILE_NAME"

    log "$BLUE" "Criando keyfile para evitar dupla digitação de senha..."

    # Criar keyfile com dados aleatórios
    log "$CYAN" "Gerando $KEYFILE_SIZE bytes de dados aleatórios..."
    dd if=/dev/urandom of="$keyfile_path" bs=1 count=$KEYFILE_SIZE status=progress 2>&1 | tee -a "$LOG_FILE"

    # Definir permissões ultra-restritivas
    chmod 000 "$keyfile_path"
    chown root:root "$keyfile_path"

    log "$BLUE" "Adicionando keyfile ao dispositivo LUKS..."
    log "$YELLOW" "ATENÇÃO: Você precisará digitar sua senha LUKS atual"

    # Adicionar keyfile como uma chave adicional
    if ! cryptsetup luksAddKey "$LUKS_DEVICE" "$keyfile_path"; then
        log "$RED" "Erro ao adicionar keyfile ao LUKS!"
        log "$YELLOW" "Removendo keyfile..."
        shred -vfz "$keyfile_path"
        rm -f "$keyfile_path"
        return 1
    fi

    log "$GREEN" "Keyfile criado e adicionado com sucesso!"

    # Salvar caminho do keyfile nas variáveis
    echo "LUKS_KEYFILE=\"/root/$KEYFILE_NAME\"" >> "$ENV_FILE"
    echo "LUKS_KEYFILE=\"/root/$KEYFILE_NAME\"" >> "/mnt/tmp/arch_setup_vars.env"

    return 0
}

configure_mkinitcpio() {
    log "$MAGENTA" "========================================"
    log "$MAGENTA" "    CONFIGURANDO MKINITCPIO"
    log "$MAGENTA" "========================================"

    local mkinitcpio_conf="/mnt/etc/mkinitcpio.conf"

    # Backup da configuração original
    cp "$mkinitcpio_conf" "$mkinitcpio_conf.backup"

    log "$BLUE" "Configurando hooks para criptografia..."

    # Configurar HOOKS para criptografia
    if [[ "${ENCRYPTION_ENABLED:-true}" == "true" ]]; then
        # HOOKS com suporte a criptografia (ordem importa!)
        local new_hooks="base udev autodetect modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck"
        
        sed -i "s/^HOOKS=.*/HOOKS=($new_hooks)/" "$mkinitcpio_conf"

        # Adicionar módulos necessários
        sed -i 's/^MODULES=.*/MODULES=(dm_mod dm_crypt ext4 aes_x86_64 sha256 sha512)/' "$mkinitcpio_conf"

        # Se tiver keyfile, adicionar aos FILES
        if [[ -f "/mnt/root/$KEYFILE_NAME" ]]; then
            log "$CYAN" "Adicionando keyfile ao initramfs..."
            sed -i "s|^FILES=.*|FILES=(/root/$KEYFILE_NAME)|" "$mkinitcpio_conf"
        fi
    fi

    log "$GREEN" "mkinitcpio.conf configurado!"

    # Mostrar configuração
    log "$CYAN" "Configuração do mkinitcpio:"
    grep -E "^(MODULES|HOOKS|FILES)=" "$mkinitcpio_conf" | tee -a "$LOG_FILE"
}

prepare_grub_encryption() {
    log "$MAGENTA" "========================================"
    log "$MAGENTA" "    PREPARANDO GRUB PARA CRIPTOGRAFIA"
    log "$MAGENTA" "========================================"

    if [[ "${ENCRYPTION_ENABLED:-false}" != "true" ]]; then
        log "$YELLOW" "Sistema sem criptografia, pulando configuração do GRUB"
        return 0
    fi

    local grub_default="/mnt/etc/default/grub"

    log "$BLUE" "Criando configuração do GRUB para criptografia..."

    # Criar arquivo de configuração do GRUB
    cat > "$grub_default" << 'GRUB_CONFIG'
# GRUB Configuration for Encrypted System
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="Arch"
GRUB_CMDLINE_LINUX_DEFAULT="quiet loglevel=3 udev.log_level=3"

# Criptografia - será substituído com valores reais
GRUB_CMDLINE_LINUX="cryptdevice=UUID=LUKS_UUID_PLACEHOLDER:cryptroot:allow-discards root=/dev/mapper/cryptroot"

# Habilitar criptografia no GRUB
GRUB_ENABLE_CRYPTODISK=y

# Preload modules necessários
GRUB_PRELOAD_MODULES="part_gpt part_msdos luks cryptodisk gcry_rijndael gcry_sha256 gcry_sha512"

# Configurações de segurança
GRUB_DISABLE_RECOVERY="false"
GRUB_DISABLE_SUBMENU=y

# Terminal
GRUB_TERMINAL_INPUT="console"
GRUB_TERMINAL_OUTPUT="console"

# Tema (opcional)
GRUB_THEME="/usr/share/grub/themes/starfield/theme.txt"
GRUB_GFXMODE=1920x1080
GRUB_GFXPAYLOAD_LINUX=keep

# Desabilitar os-prober por segurança
GRUB_DISABLE_OS_PROBER=true
GRUB_CONFIG

    # Substituir UUID placeholder pelo real
    if [[ -n "$LUKS_UUID" ]]; then
        sed -i "s/LUKS_UUID_PLACEHOLDER/$LUKS_UUID/" "$grub_default"
        log "$GREEN" "UUID LUKS configurado: $LUKS_UUID"
    fi

    # Se tiver keyfile, adicionar ao cmdline
    if [[ -f "/mnt/root/$KEYFILE_NAME" ]]; then
        local cmdline=$(grep "^GRUB_CMDLINE_LINUX=" "$grub_default" | sed 's/GRUB_CMDLINE_LINUX=//')
        cmdline="${cmdline%\"} cryptkey=rootfs:/root/$KEYFILE_NAME\""
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=$cmdline|" "$grub_default"
        log "$GREEN" "Keyfile adicionado à configuração do GRUB"
    fi

    # Criar script de instalação do GRUB para a fase 5
    cat > /mnt/root/setup/install-grub.sh << 'INSTALL_GRUB'
#!/bin/bash
# Script para instalar GRUB com criptografia

set -e

echo "Instalando GRUB com suporte a criptografia..."

# Detectar modo de boot
if [ -d /sys/firmware/efi ]; then
    echo "Modo UEFI detectado"
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --recheck
    
    # Instalar fallback
    mkdir -p /boot/efi/EFI/BOOT
    cp /boot/efi/EFI/ARCH/grubx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
else
    echo "Modo BIOS detectado"
    DISK=$(lsblk -no pkname $(findmnt -n -o SOURCE /) | head -1)
    grub-install --target=i386-pc --recheck /dev/$DISK
fi

# Gerar configuração
echo "Gerando configuração do GRUB..."
grub-mkconfig -o /boot/grub/grub.cfg

# Verificar se a criptografia foi configurada
if grep -q "cryptdevice" /boot/grub/grub.cfg; then
    echo "✓ Criptografia configurada no GRUB com sucesso!"
else
    echo "⚠ AVISO: Criptografia pode não estar configurada corretamente!"
fi

echo "GRUB instalado com sucesso!"
INSTALL_GRUB

    chmod +x /mnt/root/setup/install-grub.sh
    
    log "$GREEN" "Preparação do GRUB concluída!"
    log "$CYAN" "Execute /root/setup/install-grub.sh no chroot para instalar"
}

generate_fstab() {
    log "$BLUE" "Gerando fstab otimizado..."

    # Backup se já existir
    if [[ -f /mnt/etc/fstab ]]; then
        cp /mnt/etc/fstab /mnt/etc/fstab.backup
    fi

    # Gerar fstab com UUIDs
    genfstab -U /mnt > /mnt/etc/fstab

    # Adicionar opções de segurança e performance
    log "$CYAN" "Aplicando opções de segurança e otimização ao fstab..."

    # Otimizações para SSD se detectado
    if [[ -f /sys/block/${DISK##*/}/queue/rotational ]]; then
        if [[ $(cat /sys/block/${DISK##*/}/queue/rotational) -eq 0 ]]; then
            log "$CYAN" "SSD detectado, aplicando otimizações..."
            # Adicionar noatime,discard para partições em SSD
            sed -i 's/relatime/noatime,discard/g' /mnt/etc/fstab
        fi
    fi

    # Adicionar opções de segurança para /tmp
    if ! grep -q '/tmp' /mnt/etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0" >> /mnt/etc/fstab
    fi

    # Adicionar /proc com hidepid
    echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /mnt/etc/fstab

    # Mostrar fstab gerado
    log "$CYAN" "fstab gerado:"
    cat /mnt/etc/fstab | tee -a "$LOG_FILE"
}

create_security_scripts() {
    log "$BLUE" "Criando scripts de segurança adicionais..."

    # Script para verificar integridade do GRUB
    cat > /mnt/root/setup/verify-grub.sh << 'VERIFY_GRUB'
#!/bin/bash
# Verificar integridade do GRUB

echo "Verificando integridade do GRUB..."

# Verificar se os módulos de criptografia estão presentes
for module in luks cryptodisk gcry_rijndael gcry_sha256; do
    if ! grub-probe --target=module / | grep -q "$module"; then
        echo "⚠ AVISO: Módulo $module não encontrado!"
    else
        echo "✓ Módulo $module OK"
    fi
done

# Verificar configuração
if grep -q "GRUB_ENABLE_CRYPTODISK=y" /etc/default/grub; then
    echo "✓ Criptografia habilitada no GRUB"
else
    echo "✗ Criptografia NÃO habilitada no GRUB!"
fi

# Verificar se o initramfs tem os hooks corretos
if lsinitcpio /boot/initramfs-linux.img | grep -q "encrypt"; then
    echo "✓ Hook encrypt presente no initramfs"
else
    echo "✗ Hook encrypt NÃO encontrado no initramfs!"
fi

echo "Verificação concluída!"
VERIFY_GRUB

    chmod +x /mnt/root/setup/verify-grub.sh

    # Script para backup das chaves LUKS
    cat > /mnt/root/setup/backup-luks-header.sh << 'BACKUP_LUKS'
#!/bin/bash
# Backup do header LUKS

LUKS_DEVICE="${1:-$(grep "cryptdevice" /etc/default/grub | sed 's/.*UUID=\([^:]*\).*/\/dev\/disk\/by-uuid\/\1/')}"
BACKUP_FILE="/root/luks-header-backup-$(date +%Y%m%d-%H%M%S).img"

if [ -z "$LUKS_DEVICE" ]; then
    echo "Erro: Dispositivo LUKS não encontrado!"
    exit 1
fi

echo "Fazendo backup do header LUKS de $LUKS_DEVICE..."
cryptsetup luksHeaderBackup "$LUKS_DEVICE" --header-backup-file "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    chmod 400 "$BACKUP_FILE"
    echo "✓ Backup salvo em: $BACKUP_FILE"
    echo "⚠ IMPORTANTE: Copie este arquivo para um local seguro FORA do sistema!"
else
    echo "✗ Erro ao criar backup!"
fi
BACKUP_LUKS

    chmod +x /mnt/root/setup/backup-luks-header.sh

    log "$GREEN" "Scripts de segurança criados!"
}

copy_setup_files() {
    log "$BLUE" "Copiando arquivos de configuração..."

    # Criar diretórios necessários
    mkdir -p /mnt/root/setup
    mkdir -p /mnt/tmp

    # Copiar arquivo de variáveis atualizado
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

    # Criar script helper melhorado para chroot
    cat > /mnt/root/setup/enter-chroot.sh << 'CHROOT_SCRIPT'
#!/bin/bash
# Script helper para entrar no chroot com ambiente configurado

echo "========================================"
echo "    ENTRANDO NO AMBIENTE CHROOT"
echo "========================================"
echo ""
echo "Scripts disponíveis em /root/setup/:"
echo "  • install-grub.sh     - Instalar GRUB com criptografia"
echo "  • verify-grub.sh      - Verificar configuração do GRUB"
echo "  • backup-luks-header.sh - Fazer backup do header LUKS"
echo "  • fase5-config-chroot.sh - Continuar instalação"
echo ""
echo "Para continuar a instalação:"
echo "  1. cd /root/setup"
echo "  2. ./fase5-config-chroot.sh"
echo ""
echo "Para instalar o GRUB manualmente:"
echo "  1. mkinitcpio -P  # Gerar initramfs"
echo "  2. ./install-grub.sh  # Instalar GRUB"
echo ""

# Carregar variáveis de ambiente se existirem
if [ -f /tmp/arch_setup_vars.env ]; then
    source /tmp/arch_setup_vars.env
    export LUKS_UUID LUKS_DEVICE BOOT_PARTITION ROOT_PARTITION
fi

exec /bin/bash
CHROOT_SCRIPT

    chmod +x /mnt/root/setup/enter-chroot.sh
}

show_summary() {
    log "$GREEN" "============================================"
    log "$GREEN" "    FASE 4 CONCLUÍDA COM SUCESSO!"
    log "$GREEN" "============================================"
    log "$CYAN" "Sistema base instalado em: ${DISK}"
    log "$CYAN" "Modo de boot: ${BOOT_MODE}"
    
    if [[ "${ENCRYPTION_ENABLED:-false}" == "true" ]]; then
        log "$MAGENTA" "╔══════════════════════════════════════╗"
        log "$MAGENTA" "║   CRIPTOGRAFIA LUKS CONFIGURADA!    ║"
        log "$MAGENTA" "╚══════════════════════════════════════╝"
        log "$CYAN" "  • Dispositivo: $LUKS_DEVICE"
        log "$CYAN" "  • UUID: $LUKS_UUID"
        if [[ -f "/mnt/root/$KEYFILE_NAME" ]]; then
            log "$GREEN" "  • Keyfile criado: /root/$KEYFILE_NAME"
            log "$YELLOW" "  • Boot sem dupla senha habilitado!"
        fi
        log "$CYAN" "  • mkinitcpio preparado"
        log "$CYAN" "  • GRUB pronto para instalação"
    fi
    
    log "$CYAN" "Log salvo em: $LOG_FILE"
    echo ""
    log "$YELLOW" "PRÓXIMOS PASSOS:"
    log "$YELLOW" "1. Entre no chroot:"
    log "$BLUE" "   arch-chroot /mnt /root/setup/enter-chroot.sh"
    echo ""
    log "$YELLOW" "2. No chroot, execute:"
    log "$BLUE" "   cd /root/setup"
    log "$BLUE" "   ./fase5-config-chroot.sh"
    echo ""
    if [[ "${ENCRYPTION_ENABLED:-false}" == "true" ]]; then
        log "$MAGENTA" "IMPORTANTE - Segurança:"
        log "$YELLOW" "• Faça backup do header LUKS após instalação:"
        log "$BLUE" "  ./backup-luks-header.sh"
        log "$YELLOW" "• Verifique a configuração do GRUB:"
        log "$BLUE" "  ./verify-grub.sh"
    fi
}

main() {
    log "$BLUE" "=========================================="
    log "$BLUE" "    FASE 4: SISTEMA BASE + GRUB CRYPTO"
    log "$BLUE" "    Versão: $SCRIPT_VERSION"
    log "$BLUE" "=========================================="

    # Verificações iniciais
    check_environment

    # Modo dry-run
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log "$YELLOW" "MODO DRY-RUN: Simulando instalação..."
        log "$CYAN" "Ações que seriam realizadas:"
        echo "  ✓ Verificação de rede"
        echo "  ✓ Verificação de montagens"
        echo "  ✓ Atualização de mirrorlist"
        echo "  ✓ Instalação de pacotes base + criptografia"
        echo "  ✓ Criação de keyfile LUKS"
        echo "  ✓ Configuração do mkinitcpio"
        echo "  ✓ Preparação do GRUB criptografado"
        echo "  ✓ Geração de fstab otimizado"
        echo "  ✓ Criação de scripts de segurança"
        echo "  ✓ Cópia de arquivos de setup"
        log "$GREEN" "Simulação concluída!"
        exit 0
    fi

    # Executar instalação
    check_network
    check_mounts
    update_mirrorlist
    install_base_system
    
    # Configurações de criptografia
    create_luks_keyfile
    configure_mkinitcpio
    prepare_grub_encryption
    
    # Finalização
    generate_fstab
    create_security_scripts
    copy_setup_files

    # Mostrar resumo
    show_summary
}

# Configurar logging
setup_logging

# Executar script principal
main "$@"