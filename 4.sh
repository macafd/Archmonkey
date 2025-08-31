# ============================================================================
# FASE 4 - SISTEMA BASE
# ============================================================================
cat << 'EOF' > fase4-base-system.sh
#!/bin/bash
# fase4-base-system.sh - Instalacao do sistema base
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_NAME="fase4-base-system"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"

[[ ! -f "$ENV_FILE" ]] && { echo -e "${RED}Execute fases anteriores primeiro!${NC}"; exit 1; }
source "$ENV_FILE"

setup_logging() {
    [[ "$SIMULATE" == "true" ]] && LOG_DIR="./logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

check_mounts() {
    log "$BLUE" "Verificando pontos de montagem..."
    
    if ! mountpoint -q /mnt; then
        log "$RED" "Erro: /mnt nao esta montado!"
        log "$YELLOW" "Execute fase2 primeiro ou monte manualmente"
        exit 1
    fi
    
    if ! mountpoint -q /mnt/boot; then
        log "$RED" "Erro: /mnt/boot nao esta montado!"
        exit 1
    fi
    
    if [[ "$BOOT_MODE" == "UEFI" ]] && ! mountpoint -q /mnt/boot/efi; then
        log "$RED" "Erro: /mnt/boot/efi nao esta montado!"
        exit 1
    fi
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 4: SISTEMA BASE ==="
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Nada instalado"; exit 0; }
    
    check_mounts
    
    # Pacotes essenciais
    PACKAGES="base linux linux-firmware linux-headers base-devel"
    PACKAGES="$PACKAGES btrfs-progs cryptsetup grub efibootmgr"
    PACKAGES="$PACKAGES networkmanager nm-connection-editor network-manager-applet"
    PACKAGES="$PACKAGES vim nano sudo wget curl git"
    PACKAGES="$PACKAGES intel-ucode amd-ucode"
    PACKAGES="$PACKAGES xfsprogs exfatprogs dosfstools ntfs-3g"
    PACKAGES="$PACKAGES lvm2 device-mapper"
    PACKAGES="$PACKAGES zsh bash-completion"
    PACKAGES="$PACKAGES man-db man-pages texinfo"
    PACKAGES="$PACKAGES hdparm smartmontools"
    PACKAGES="$PACKAGES openssh rsync"
    PACKAGES="$PACKAGES jq gnupg tar"
    
    log "$BLUE" "Instalando sistema base..."
    if ! pacstrap /mnt $PACKAGES; then
        log "$RED" "Erro ao instalar sistema base!"
        log "$YELLOW" "Verifique sua conexao com internet e espelhos"
        exit 1
    fi
    
    log "$BLUE" "Gerando fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab
    
    # Copiar scripts e configuracao
    cp "$ENV_FILE" /mnt/tmp/
    
    # Copiar arquivo de configuracao se existir
    if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" /mnt/tmp/config.json
        # Atualizar ENV_FILE no chroot para apontar para o novo local
        echo "export CONFIG_FILE=\"/tmp/config.json\"" >> /mnt/tmp/arch_setup_vars.env
    fi
    
    # Copiar scripts da fase 5 em diante
    for script in fase5-config-chroot.sh fase6-backup-scripts.sh fase7-autodestruicao.sh; do
        if [[ -f "$script" ]]; then
            cp "$script" /mnt/root/
            chmod +x /mnt/root/"$script"
        else
            log "$YELLOW" "Aviso: $script nao encontrado"
        fi
    done
    
    log "$GREEN" "Sistema base instalado!"
    log "$YELLOW" "Proximos passos:"
    log "$YELLOW" "1. Entre no chroot: arch-chroot /mnt"
    log "$YELLOW" "2. Execute: cd /root && ./fase5-config-chroot.sh"
}

main
EOF 
