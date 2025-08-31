# ============================================================================
# FILE: fase6-backup-scripts.sh
# ============================================================================
#!/bin/bash
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

# Verificar comandos necessários
check_commands() {
    local cmds=("gpg" "tar" "cryptsetup" "blkid" "mktemp" "find")
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessários não encontrados: ${missing[*]}"
        log "$YELLOW" "Instale com: pacman -S gnupg tar cryptsetup util-linux coreutils findutils"
        exit 1
    fi
    
    # Verificar jq se modo non-interactive
    if [[ "${NON_INTERACTIVE:-false}" == "true" ]]; then
        if ! command -v jq &>/dev/null; then
            log "$RED" "jq necessário para modo non-interactive!"
            exit 1
        fi
    fi
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

# Verificar comandos necessários
for cmd in gpg tar cryptsetup blkid mktemp find mount umount sync; do
    if ! command -v "$cmd" &>/dev/null; then
        log "$RED" "ERRO: Comando necessário não encontrado: $cmd"
        exit 1
    fi
done

# Criar diretório de backup
mkdir -p "$BACKUP_DIR"
cd "$BACKUP_DIR"

# Criar diretório temporário
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

log "$BLUE" "Iniciando backup de headers LUKS"

# Detectar dispositivos LUKS
LUKS_DEVICES=()
for dev in $(lsblk -rno NAME,TYPE | awk '$2=="part" {print "/dev/"$1}' | sort -u); do
    if [[ -b "$dev" ]] && cryptsetup isLuks "$dev" 2>/dev/null; then
        LUKS_DEVICES+=("$dev")
        log "$GREEN" "Dispositivo LUKS detectado: $dev"
    fi
done

# Verificar também dispositivos de disco completos (para casos especiais)
for dev in $(lsblk -rno NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}' | sort -u); do
    if [[ -b "$dev" ]] && cryptsetup isLuks "$dev" 2>/dev/null; then
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
    if ! cryptsetup luksHeaderBackup "$device" --header-backup-file "$header_file"; then
        log "$RED" "ERRO ao fazer backup de $device"
        continue
    fi
    
    # Adicionar informações do dispositivo
    {
        echo "Device: $device"
        echo "Date: $(date)"
        echo "UUID: $(blkid -s UUID -o value $device 2>/dev/null || echo 'N/A')"
        echo "---"
        cryptsetup luksDump "$device" 2>/dev/null || echo "luksDump failed"
    } > "${header_file}.info"
done

# Verificar se algum backup foi criado
if [[ $(find "$TEMP_DIR" -name "header*.img" -type f | wc -l) -eq 0 ]]; then
    log "$RED" "ERRO: Nenhum backup de header foi criado"
    exit 1
fi

# Criar arquivo tar
log "$BLUE" "Criando arquivo tar"
cd "$TEMP_DIR"
if ! tar -czf "${BACKUP_NAME}.tar.gz" header*.img header*.info 2>/dev/null; then
    log "$RED" "ERRO ao criar arquivo tar"
    exit 1
fi
cd - > /dev/null

# Criptografar com GPG
log "$BLUE" "Criptografando backup"
echo -e "${YELLOW}Digite a senha para criptografar o backup:${NC}"

# Usar --batch com passphrase via stdin para melhor controle
if ! gpg --batch --yes -c \
    --cipher-algo AES256 \
    --compress-algo none \
    --passphrase-fd 0 \
    -o "${BACKUP_NAME}.tar.gz.gpg" \
    "${TEMP_DIR}/${BACKUP_NAME}.tar.gz"; then
    log "$RED" "ERRO ao criptografar backup"
    exit 1
fi

# Copiar para USB se especificado
if [[ -n "$USB_DEVICE" ]]; then
    if [[ ! -b "$USB_DEVICE" ]]; then
        log "$RED" "ERRO: $USB_DEVICE não é um dispositivo de bloco válido"
    else
        log "$BLUE" "Copiando backup para $USB_DEVICE"
        
        # Montar USB temporariamente
        USB_MOUNT=$(mktemp -d)
        
        if mount "$USB_DEVICE" "$USB_MOUNT" 2>/dev/null; then
            # Criar diretório de backups no USB
            mkdir -p "${USB_MOUNT}/luks-backups"
            
            # Copiar backup
            if cp "${BACKUP_NAME}.tar.gz.gpg" "${USB_MOUNT}/luks-backups/"; then
                log "$GREEN" "Backup copiado para USB"
            else
                log "$RED" "ERRO ao copiar backup para USB"
            fi
            
            # Sincronizar e desmontar
            sync
            umount "$USB_MOUNT" 2>/dev/null || true
        else
            log "$RED" "ERRO: Não foi possível montar $USB_DEVICE"
        fi
        
        rmdir "$USB_MOUNT" 2>/dev/null || true
    fi
fi

# Limpar backups antigos
log "$BLUE" "Removendo backups antigos (mais de $RETENTION_DAYS dias)"
find "$BACKUP_DIR" -name "luks-headers-*.tar.gz.gpg" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

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
User=root
Environment="RETENTION_DAYS=7"
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
    
    # Determinar se fazer backup em USB
    local USB_BACKUP=""
    
    if [[ "${NON_INTERACTIVE:-false}" == "true" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            USB_BACKUP=$(jq -r '.usb_backup // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
        fi
    else
        echo -e "${YELLOW}Deseja fazer backup em um dispositivo USB? [s/N]:${NC}"
        read -r usb_input
        if [[ "$usb_input" =~ ^[Ss]$ ]]; then
            # Listar dispositivos removíveis
            echo -e "${BLUE}Dispositivos disponíveis:${NC}"
            lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E "disk|part"
            
            echo -e "${YELLOW}Digite o dispositivo USB (ex: /dev/sdb1):${NC}"
            read -r USB_BACKUP
            
            # Validar dispositivo
            if [[ -n "$USB_BACKUP" ]] && [[ ! -b "$USB_BACKUP" ]]; then
                log "$RED" "Dispositivo inválido: $USB_BACKUP"
                USB_BACKUP=""
            fi
        fi
    fi
    
    # Executar backup
    if [[ -n "$USB_BACKUP" ]]; then
        "$BACKUP_SCRIPT" "$USB_BACKUP" || log "$YELLOW" "Backup executado com avisos"
    else
        "$BACKUP_SCRIPT" || log "$YELLOW" "Backup executado com avisos"
    fi
}

# Habilitar timer
enable_timer() {
    local ENABLE_TIMER=false
    
    if [[ "${NON_INTERACTIVE:-false}" == "true" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            ENABLE_TIMER=$(jq -r '.enable_backup_timer // false' "$CONFIG_FILE" 2>/dev/null || echo "false")
        fi
    else
        echo -e "${YELLOW}Habilitar backup semanal automático? [s/N]:${NC}"
        read -r timer_input
        if [[ "$timer_input" =~ ^[Ss]$ ]]; then
            ENABLE_TIMER=true
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
    
    # Verificar se está no chroot
    if [[ ! -d /boot ]] || [[ ! -d /etc ]]; then
        log "$RED" "ERRO: Este script deve ser executado dentro do chroot!"
        log "$YELLOW" "Use: arch-chroot /mnt"
        exit 1
    fi
    
    check_commands
    create_backup_script
    create_systemd_service
    run_first_backup
    enable_timer
    
    log "$GREEN" "=== FASE 6 CONCLUÍDA ==="
    log "$YELLOW" "Script de backup instalado em: $BACKUP_SCRIPT"
    log "$YELLOW" "Backups salvos em: $BACKUP_DIR"
    log "$YELLOW" "Para backup manual: $BACKUP_SCRIPT [/dev/usbX]"
}

main "$@"
