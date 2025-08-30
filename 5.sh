#===========================================================================
# FILE: fase5-config-chroot.sh (COMPLETO)
# ============================================================================
cat << 'EOF_FASE5' > fase5-config-chroot.sh
#!/bin/bash
# fase5-config-chroot.sh - Configuração do sistema dentro do chroot
# EXECUTE ESTE SCRIPT DENTRO DO CHROOT!

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuração
SCRIPT_NAME="fase5-config-chroot"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"

# Verificar se está no chroot
if [[ ! -f /tmp/arch_setup_vars.env ]]; then
    echo -e "${RED}ERRO: Este script deve ser executado dentro do chroot!${NC}"
    echo -e "${YELLOW}Use: arch-chroot /mnt${NC}"
    exit 1
fi

# Carregar configuração
source "$ENV_FILE"

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

# Obter configuração
get_configuration() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        TIMEZONE=$(jq -r '.timezone // "America/Sao_Paulo"' "$CONFIG_FILE")
        LOCALE=$(jq -r '.locale // "pt_BR.UTF-8"' "$CONFIG_FILE")
        HOSTNAME=$(jq -r '.hostname' "$CONFIG_FILE")
        USERNAME=$(jq -r '.username' "$CONFIG_FILE")
        USER_PASSWORD=$(jq -r '.user_password' "$CONFIG_FILE")
        ROOT_PASSWORD=$(jq -r '.root_password' "$CONFIG_FILE")
        ENABLE_SELFDESTRUCT=$(jq -r '.autodestruct_enabled // false' "$CONFIG_FILE")
    else
        # Modo interativo
        echo -e "${BLUE}=== Configuração do Sistema ===${NC}"
        
        # Timezone
        echo -e "${YELLOW}Timezone (ex: America/Sao_Paulo):${NC}"
        read -r TIMEZONE
        TIMEZONE="${TIMEZONE:-America/Sao_Paulo}"
        
        # Locale
        echo -e "${YELLOW}Locale principal (ex: pt_BR.UTF-8):${NC}"
        read -r LOCALE
        LOCALE="${LOCALE:-pt_BR.UTF-8}"
        
        # Hostname
        echo -e "${YELLOW}Nome do computador (hostname):${NC}"
        read -r HOSTNAME
        
        # Usuário
        echo -e "${YELLOW}Nome de usuário principal:${NC}"
        read -r USERNAME
        
        # Senha do usuário
        while true; do
            echo -e "${YELLOW}Senha para o usuário $USERNAME:${NC}"
            read -rs USER_PASSWORD
            echo
            echo -e "${YELLOW}Confirme a senha:${NC}"
            read -rs USER_PASSWORD_CONFIRM
            echo
            
            if [[ "$USER_PASSWORD" == "$USER_PASSWORD_CONFIRM" ]]; then
                break
            else
                echo -e "${RED}As senhas não coincidem!${NC}"
            fi
        done
        
        # Senha root
        while true; do
            echo -e "${YELLOW}Senha para root:${NC}"
            read -rs ROOT_PASSWORD
            echo
            echo -e "${YELLOW}Confirme a senha:${NC}"
            read -rs ROOT_PASSWORD_CONFIRM
            echo
            
            if [[ "$ROOT_PASSWORD" == "$ROOT_PASSWORD_CONFIRM" ]]; then
                break
            else
                echo -e "${RED}As senhas não coincidem!${NC}"
            fi
        done
        
        # Autodestruição
        echo -e "${RED}ATENÇÃO: Recurso de autodestruição${NC}"
        echo -e "${YELLOW}Habilitar sistema de autodestruição? [s/N]:${NC}"
        read -r selfdestruct_input
        if [[ "$selfdestruct_input" =~ ^[Ss]$ ]]; then
            ENABLE_SELFDESTRUCT=true
            echo -e "${RED}AVISO: Sistema de autodestruição será habilitado!${NC}"
            echo -e "${YELLOW}Digite CONFIRM para confirmar:${NC}"
            read -r confirm
            if [[ "$confirm" != "CONFIRM" ]]; then
                ENABLE_SELFDESTRUCT=false
                log "$YELLOW" "Autodestruição cancelada"
            fi
        else
            ENABLE_SELFDESTRUCT=false
        fi
    fi
}

# Configurar timezone
configure_timezone() {
    log "$BLUE" "Configurando timezone: $TIMEZONE"
    
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
    hwclock --systohc
    
    log "$GREEN" "Timezone configurado"
}

# Configurar locale
configure_locale() {
    log "$BLUE" "Configurando locale: $LOCALE"
    
    # Habilitar locales
    sed -i "s/^#$LOCALE/$LOCALE/" /etc/locale.gen
    sed -i "s/^#en_US.UTF-8/en_US.UTF-8/" /etc/locale.gen
    
    # Gerar locales
    locale-gen
    
    # Configurar locale padrão
    echo "LANG=$LOCALE" > /etc/locale.conf
    
    # Configurar keymap para console
    echo "KEYMAP=br-abnt2" > /etc/vconsole.conf
    
    log "$GREEN" "Locale configurado"
}

# Configurar hostname
configure_hostname() {
    log "$BLUE" "Configurando hostname: $HOSTNAME"
    
    echo "$HOSTNAME" > /etc/hostname
    
    cat > /etc/hosts << EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $HOSTNAME.localdomain $HOSTNAME
EOF
    
    log "$GREEN" "Hostname configurado"
}

# Configurar mkinitcpio
configure_mkinitcpio() {
    log "$BLUE" "Configurando mkinitcpio"
    
    # Backup do mkinitcpio.conf original
    cp /etc/mkinitcpio.conf /etc/mkinitcpio.conf.backup
    
    # Hooks básicos
    HOOKS="base udev autodetect microcode modconf kms keyboard keymap consolefont block encrypt filesystems fsck"
    
    # Adicionar hook de autodestruição se habilitado
    if [[ "$ENABLE_SELFDESTRUCT" == "true" ]]; then
        # Criar hook de autodestruição
        create_selfdestruct_hook
        HOOKS="base udev autodetect microcode modconf kms keyboard keymap consolefont block selfdestruct encrypt filesystems fsck"
    fi
    
    # Atualizar mkinitcpio.conf
    sed -i "s/^HOOKS=.*/HOOKS=($HOOKS)/" /etc/mkinitcpio.conf
    
    # Adicionar módulos necessários
    sed -i "s/^MODULES=.*/MODULES=(btrfs)/" /etc/mkinitcpio.conf
    
    # Regenerar initramfs
    mkinitcpio -P
    
    log "$GREEN" "mkinitcpio configurado"
}

# Criar hook de autodestruição
create_selfdestruct_hook() {
    log "$YELLOW" "Criando hook de autodestruição para initramfs"
    
    # Criar hook install
    cat > /etc/initcpio/install/selfdestruct << 'EOF'
#!/bin/bash

build() {
    add_runscript
}

help() {
    cat <<HELPEOF
This hook provides self-destruct capability in early boot.
If selfdestruct=1 is passed to kernel cmdline, it will:
1. Erase LUKS headers
2. Discard all data on SSDs
3. Overwrite HDDs with random data
WARNING: This is IRREVERSIBLE!
HELPEOF
}
EOF
    
    # Criar hook runtime
    cat > /etc/initcpio/hooks/selfdestruct << 'EOF'
#!/usr/bin/ash

run_hook() {
    # Verificar se selfdestruct foi passado
    if grep -q "selfdestruct=1" /proc/cmdline; then
        echo ""
        echo "====================== WARNING ======================"
        echo "SELF-DESTRUCT SEQUENCE INITIATED!"
        echo "ALL DATA WILL BE PERMANENTLY DESTROYED!"
        echo ""
        echo "You have 10 seconds to power off the system."
        echo "====================================================="
        
        sleep 10
        
        echo "Starting destruction sequence..."
        
        # Detectar dispositivos
        for dev in /dev/nvme* /dev/sd* /dev/mmcblk*; do
            if [ -b "$dev" ]; then
                echo "Processing $dev..."
                
                # Tentar apagar headers LUKS
                cryptsetup luksErase "$dev" --batch-mode 2>/dev/null || true
                
                # Tentar discard/trim
                blkdiscard -f "$dev" 2>/dev/null || \
                dd if=/dev/urandom of="$dev" bs=1M count=100 2>/dev/null || true
            fi
        done
        
        echo "Destruction complete. System halted."
        poweroff -f
    fi
}
EOF
    
    chmod +x /etc/initcpio/install/selfdestruct
    chmod +x /etc/initcpio/hooks/selfdestruct
    
    log "$GREEN" "Hook de autodestruição criado"
}

# Configurar crypttab
configure_crypttab() {
    log "$BLUE" "Configurando /etc/crypttab"
    
    cat > /etc/crypttab << EOF
# <name>      <device>                                     <password>    <options>
EOF
    
    # Swap criptografado com chave aleatória
    if [[ -n "${SWAP_PART:-}" ]]; then
        echo "cryptswap   UUID=$SWAP_UUID    /dev/urandom    swap,cipher=aes-xts-plain64,size=512" >> /etc/crypttab
    fi
    
    # Disco auxiliar se existir
    if [[ -n "${AUX_PART:-}" ]]; then
        echo "# Disco auxiliar - entrada manual ou keyfile" >> /etc/crypttab
        echo "# cryptdata   UUID=$AUX_UUID    none    luks,timeout=10,noauto" >> /etc/crypttab
    fi
    
    log "$GREEN" "crypttab configurado"
}

# Configurar GRUB
configure_grub() {
    log "$BLUE" "Configurando GRUB"
    
    # Backup da configuração original
    cp /etc/default/grub /etc/default/grub.backup
    
    # Configurar linha de comando do kernel
    KERNEL_PARAMS="cryptdevice=UUID=$ROOT_UUID:cryptroot root=/dev/mapper/cryptroot"
    
    # Adicionar parâmetros para Btrfs
    KERNEL_PARAMS="$KERNEL_PARAMS rootflags=subvol=@"
    
    # Configurar GRUB
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$KERNEL_PARAMS\"|" /etc/default/grub
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"loglevel=3 quiet\"|" /etc/default/grub
    
    # Habilitar criptografia
    sed -i "s|^#GRUB_ENABLE_CRYPTODISK=.*|GRUB_ENABLE_CRYPTODISK=y|" /etc/default/grub
    
    # Timeout
    sed -i "s|^GRUB_TIMEOUT=.*|GRUB_TIMEOUT=5|" /etc/default/grub
    
    # Instalar GRUB
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
    else
        grub-install --target=i386-pc "$DISCO_PRINCIPAL"
    fi
    
    # Adicionar entrada de autodestruição se habilitado
    if [[ "$ENABLE_SELFDESTRUCT" == "true" ]]; then
        cat > /etc/grub.d/40_custom << 'EOF'
#!/bin/sh
exec tail -n +3 $0

menuentry "SELF-DESTRUCT - DESTROY ALL DATA" {
    insmod gzio
    insmod part_gpt
    insmod btrfs
    insmod ext2
    echo 'WARNING: This will PERMANENTLY DESTROY ALL DATA!'
    echo 'Press ESC to cancel or ENTER to continue...'
    sleep --interruptible 5
    linux /vmlinuz-linux selfdestruct=1
    initrd /initramfs-linux.img
}
EOF
        chmod +x /etc/grub.d/40_custom
    fi
    
    # Gerar configuração
    grub-mkconfig -o /boot/grub/grub.cfg
    
    log "$GREEN" "GRUB configurado e instalado"
}

# Criar usuário
create_user() {
    log "$BLUE" "Criando usuário: $USERNAME"
    
    # Criar usuário
    useradd -m -G wheel,audio,video,optical,storage -s /bin/bash "$USERNAME"
    
    # Definir senha
    echo "$USERNAME:$USER_PASSWORD" | chpasswd
    
    # Configurar sudo
    sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers
    
    # Criar diretórios do usuário
    su - "$USERNAME" -c "mkdir -p ~/Documents ~/Downloads ~/Pictures ~/Videos ~/Music"
    
    log "$GREEN" "Usuário criado"
}

# Definir senha root
set_root_password() {
    log "$BLUE" "Definindo senha root"
    
    echo "root:$ROOT_PASSWORD" | chpasswd
    
    log "$GREEN" "Senha root definida"
}

# Habilitar serviços
enable_services() {
    log "$BLUE" "Habilitando serviços essenciais"
    
    systemctl enable NetworkManager
    systemctl enable systemd-resolved
    systemctl enable fstrim.timer  # Para SSDs
    systemctl enable systemd-timesyncd
    
    log "$GREEN" "Serviços habilitados"
}

# Configuração final
final_configuration() {
    log "$BLUE" "Realizando configurações finais"
    
    # Criar diretório para montagem do disco auxiliar
    if [[ -n "${AUX_PART:-}" ]]; then
        mkdir -p /data
        chown "$USERNAME:$USERNAME" /data
    fi
    
    # Ajustar swappiness para SSD
    echo "vm.swappiness=10" > /etc/sysctl.d/99-swappiness.conf
    
    # Configurar journal para limitar tamanho
    mkdir -p /etc/systemd/journald.conf.d/
    cat > /etc/systemd/journald.conf.d/00-size-limit.conf << EOF
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
EOF
    
    log "$GREEN" "Configurações finais aplicadas"
}

# Função principal
main() {
    setup_logging
    
    log "$BLUE" "=== FASE 5: CONFIGURAÇÃO DO SISTEMA (CHROOT) ==="
    
    get_configuration
    configure_timezone
    configure_locale
    configure_hostname
    configure_mkinitcpio
    configure_crypttab
    configure_grub
    set_root_password
    create_user
    enable_services
    final_configuration
    
    log "$GREEN" "=== FASE 5 CONCLUÍDA COM SUCESSO ==="
    log "$YELLOW" "Sistema configurado!"
    log "$YELLOW" "Próximos passos opcionais:"
    log "$YELLOW" "  ./fase6-backup-scripts.sh - Instalar scripts de backup"
    log "$YELLOW" "  ./fase7-autodestruicao.sh - Configurar autodestruição adicional"
    echo
    log "$BLUE" "Quando terminar, saia do chroot e reinicie:"
    log "$GREEN" "  exit"
    log "$GREEN" "  umount -R /mnt"
    log "$GREEN" "  reboot"
}

main
EOF_FASE5

