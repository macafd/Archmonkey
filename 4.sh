# ============================================================================
# FASE 4 - SISTEMA BASE
# ============================================================================
echo -e "${GREEN}Criando fase4-base-system.sh...${NC}"
cat << 'EOF' > fase4-base-system.sh
#!/bin/bash
# fase4-base-system.sh - Instalação do sistema base
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

main() {
    setup_logging
    log "$BLUE" "=== FASE 4: SISTEMA BASE ==="
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Nada instalado"; exit 0; }
    
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
    PACKAGES="$PACKAGES jq"
    
    log "$BLUE" "Instalando sistema base..."
    pacstrap /mnt $PACKAGES
    
    log "$BLUE" "Gerando fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab
    
    # Copiar scripts e configuração
    cp "$ENV_FILE" /mnt/tmp/
    cp fase5-config-chroot.sh /mnt/root/
    cp fase6-backup-scripts.sh /mnt/root/
    cp fase7-autodestruicao.sh /mnt/root/
    chmod +x /mnt/root/*.sh
    
    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" /mnt/tmp/
    
    log "$GREEN" "Sistema base instalado!"
    log "$YELLOW" "Próximos passos:"
    log "$YELLOW" "1. Entre no chroot: arch-chroot /mnt"
    log "$YELLOW" "2. Execute: cd /root && ./fase5-config-chroot.sh"
}

main
EOF

