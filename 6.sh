# ============================================================================
# FILE: fase6-backup-scripts.sh
# ============================================================================
cat << 'EOF_FASE6' > fase6-backup-scripts.sh
#!/bin/bash
# fase6-backup-scripts.sh - Instalação de scripts de backup para headers LUKS
# EXECUTE DENTRO DO CHROOT

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuração
SCRIPT_NAME="fase6-backup-scripts"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
BACKUP_SCRIPT="/usr/local/bin/backup-luks-headers.sh"
BACKUP_DIR="/root/luks-backups"

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

# Criar script de backup
create_backup_script() {
    log "$BLUE" "Criando script de backup de headers LUKS"
    
    cat > "$BACKUP_SCRIPT" << 'EOF'
#!/bin/bash
# backup-luks-headers.sh - Backup de headers LUKS com criptografia GPG

set -euo pipefail

# Configuração
BACKUP_DIR="/root/luks-backups"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
USB_DEVICE="${1:-}"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="luks-headers-${DATE}"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Função de log
log() {
    echo -e "$1[$(date '+%Y-%m-%d %H:%M:%S')] $2${NC}"
}

# Verificar root
if [[ $EUID -ne 0 ]]; then
    log "$RED" "ERRO: Execute como root"
    exit 1
fi

# Criar diretório de backup
mkdir -p "$BACKUP_DIR"
cd "$BACKUP_DIR"

# Criar diretório temporário
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

log "$BLUE" "Iniciando backup de headers LUKS"

# Detectar dispositivos LUKS
LUKS_DEVICES=()
for dev in $(lsblk -rno NAME,TYPE | awk '$2=="part" {print "/dev/"$1}'); do
    if cryptsetup isLuks "$dev" 2>/dev/null; then
        LUKS_DEVICES+=("$dev")
        log "$GREEN" "Dispositivo LUKS detectado: $dev"
    fi
done

if [[ ${#LUKS_DEVICES[@]} -eq 0 ]]; then
    log "$YELLOW" "Nenhum dispositivo LUKS encontrado"
    exit 0
fi

# Fazer backup de cada header
for device in "${LUKS_DEVICES[@]}"; do
    device_name=$(echo "$device" | tr '/' '_')
    header_file="${TEMP_DIR}/header${device_name}.img"
    
    log "$BLUE" "Fazendo backup de $device"
    cryptsetup luksHeaderBackup "$device" --header-backup-file "$header_file"
    
    # Adicionar informações do dispositivo
    echo "Device: $device" > "${header_file}.info"
    echo "Date: $(date)" >> "${header_file}.info"
    echo "UUID: $(blkid -s UUID -o value $device)" >> "${header_file}.info"
    cryptsetup luksDump "$device" >> "${header_file}.info" 2>/dev/null || true
done

# Criar arquivo tar
log "$BLUE" "Criando arquivo tar"
tar -czf "${TEMP_DIR}/${BACKUP_NAME}.tar.gz" -C "$TEMP_DIR" .

# Criptografar com GPG
log "$BLUE" "Criptografando backup"
echo -e "${YELLOW}Digite a senha para criptografar o backup:${NC}"
gpg -c --cipher-algo AES256 --compress-algo none \
    -o "${BACKUP_NAME}.tar.gz.gpg" \
    "${TEMP_DIR}/${BACKUP_NAME}.tar.gz"

# Copiar para USB se especificado
if [[ -n "$USB_DEVICE" ]]; then
    if [[ -b "$USB_DEVICE" ]]; then
        log "$BLUE" "Copiando backup para $USB_DEVICE"
        
        # Montar USB temporariamente
        USB_MOUNT=$(mktemp -d)
        mount "$USB_DEVICE" "$USB_MOUNT" || {
            log "$RED" "ERRO: Não foi possível montar $USB_DEVICE"
            rmdir "$USB_MOUNT"
            exit 1
        }
        
        # Criar diretório de backups no USB
        mkdir -p "${USB_MOUNT}/luks-backups"
        
        # Copiar backup
        cp "${BACKUP_NAME}.tar.gz.gpg" "${USB_MOUNT}/luks-backups/"
        
        # Sincronizar e desmontar
        sync
        umount "$USB_MOUNT"
        rmdir "$USB_MOUNT"
        
        log "$GREEN" "Backup copiado para USB"
    else
        log "$RED" "ERRO: $USB_DEVICE não é um dispositivo válido"
    fi
fi

# Limpar backups antigos
log "$BLUE" "Removendo backups antigos (mais de $RETENTION_DAYS dias)"
find "$BACKUP_DIR" -name "luks-headers-*.tar.gz.gpg" -mtime +$RETENTION_DAYS -delete

log "$GREEN" "Backup concluído: ${BACKUP_NAME}.tar.gz.gpg"
log "$YELLOW" "IMPORTANTE: Guarde este backup em local seguro!"
log "$YELLOW" "Para restaurar: gpg -d backup.tar.gz.gpg | tar -xz"
log "$YELLOW" "Depois: cryptsetup luksHeaderRestore /dev/xxx --header-backup-file header.img"
EOF
    
    chmod +x "$BACKUP_SCRIPT"
    log "$GREEN" "Script de backup criado: $BACKUP_SCRIPT"
}

# Criar serviço systemd
create_systemd_service() {
    log "$BLUE" "Criando serviço systemd para backup automático"
    
    # Criar service
    cat > /etc/systemd/system/luks-backup.service << EOF
[Unit]
Description=Backup LUKS Headers
After=multi-user.target

[Service]
Type=oneshot
ExecStart=$BACKUP_SCRIPT
StandardOutput=journal
StandardError=journal
EOF
    
    # Criar timer
    cat > /etc/systemd/system/luks-backup.timer << EOF
[Unit]
Description=Weekly LUKS Header Backup
Persistent=true

[Timer]
OnCalendar=weekly
OnStartupSec=10min
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
    
    log "$GREEN" "Serviço systemd criado"
}

# Executar primeiro backup
run_first_backup() {
    log "$BLUE" "Executando primeiro backup"
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        USB_BACKUP=$(jq -r '.usb_backup // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
    else
        echo -e "${YELLOW}Deseja fazer backup em um dispositivo USB? [s/N]:${NC}"
        read -r usb_input
        if [[ "$usb_input" =~ ^[Ss]$ ]]; then
            echo -e "${YELLOW}Digite o dispositivo USB (ex: /dev/sdb1):${NC}"
            read -r USB_BACKUP
        else
            USB_BACKUP=""
        fi
    fi
    
    # Executar backup
    if [[ -n "$USB_BACKUP" ]]; then
        "$BACKUP_SCRIPT" "$USB_BACKUP"
    else
        "$BACKUP_SCRIPT"
    fi
}

# Habilitar timer
enable_timer() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        ENABLE_TIMER=$(jq -r '.enable_backup_timer // false' "$CONFIG_FILE" 2>/dev/null || echo "false")
    else
        echo -e "${YELLOW}Habilitar backup semanal automático? [s/N]:${NC}"
        read -r timer_input
        if [[ "$timer_input" =~ ^[Ss]$ ]]; then
            ENABLE_TIMER=true
        else
            ENABLE_TIMER=false
        fi
    fi
    
    if [[ "$ENABLE_TIMER" == "true" ]]; then
        systemctl daemon-reload
        systemctl enable luks-backup.timer
        systemctl start luks-backup.timer
        log "$GREEN" "Timer de backup habilitado (semanal)"
    else
        log "$YELLOW" "Timer de backup não habilitado"
        log "$YELLOW" "Para executar manualmente: $BACKUP_SCRIPT [dispositivo_usb]"
    fi
}

# Função principal
main() {
    setup_logging
    
    log "$BLUE" "=== FASE 6: INSTALAÇÃO DE SCRIPTS DE BACKUP ==="
    
    create_backup_script
    create_systemd_service
    run_first_backup
    enable_timer
    
    log "$GREEN" "=== FASE 6 CONCLUÍDA ==="
    log "$YELLOW" "Script de backup instalado em: $BACKUP_SCRIPT"
    log "$YELLOW" "Backups salvos em: $BACKUP_DIR"
}

main
EOF_FASE6
