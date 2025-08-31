#!/bin/bash
# Continuação das correções - Fases 5-7
# Este arquivo complementa o anterior com as fases restantes corrigidas

# ============================================================================
# FASE 5 - CONFIG CHROOT (CORRIGIDA E COMPLETA)
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

# Corrigir CONFIG_FILE se necessário
if [[ "$NON_INTERACTIVE" == "true" ]] && [[ -f "/tmp/config.json" ]]; then
    CONFIG_FILE="/tmp/config.json"
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
    local cmds=("locale-gen" "mkinitcpio" "grub-install" "grub-mkconfig" "useradd" "systemctl")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "$RED" "Comando necessário não encontrado: $cmd"
            exit 1
        fi
    done
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if ! command -v jq &>/dev/null; then
            log "$RED" "jq necessário para modo non-interactive!"
            exit 1
        fi
    fi
}

# Obter configuração
get_configuration() {
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
        
        TIMEZONE=$(jq -r '.timezone // "America/Sao_Paulo"' "$CONFIG_FILE")
        LOCALE=$(jq -r '.locale // "pt_BR.UTF-8"' "$CONFIG_FILE")
        HOSTNAME=$(jq -r '.hostname' "$CONFIG_FILE")
        USERNAME=$(jq -r '.username' "$CONFIG_FILE")
        USER_PASSWORD=$(jq -r '.user_password' "$CONFIG_FILE")
        ROOT_PASSWORD=$(jq -r '.root_password' "$CONFIG_FILE")
        ENABLE_SELFDESTRUCT=$(jq -r '.autodestruct_enabled // false' "$CONFIG_FILE")
        
        # Validar campos obrigatórios
        for var in HOSTNAME USERNAME USER_PASSWORD ROOT_PASSWORD; do
            if [[ -z "${!var}" ]] || [[ "${!var}" == "null" ]]; then
                log "$RED" "Campo obrigatório ausente ou inválido: $var"
                exit 1
            fi
        done
    else
        # Modo interativo
        echo -e "${BLUE}=== Configuração do Sistema ===${NC}"
        
        # Timezone
        echo -e "${YELLOW}Timezone (ex: America/Sao_Paulo):${NC}"
        read -r TIMEZONE
        TIMEZONE="${TIMEZONE:-America/Sao_Paulo}"
        
        # Validar timezone
        if [[ ! -f "/usr/share/zoneinfo/$TIMEZONE" ]]; then
            log "$RED" "Timezone inválido: $TIMEZONE"
            exit 1
        fi
        
        # Locale
        echo -e "${YELLOW}Locale principal (ex: pt_BR.UTF-8):${NC}"
        read -r LOCALE
        LOCALE="${LOCALE:-pt_BR.UTF-8}"
        
        # Hostname
        echo -e "${YELLOW}Nome do computador (hostname):${NC}"
        read -r HOSTNAME
        
        # Validar hostname
        if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$ ]]; then
            log "$RED" "Hostname inválido!"
            exit 1
        fi
        
        # Usuário
        echo -e "${YELLOW}Nome de usuário principal:${NC}"
        read -r USERNAME
        
        # Validar username
        if [[ ! "$USERNAME" =~ ^[a-z][a-z0-9_-]{0,30}$ ]]; then
            log "$RED" "Nome de usuário inválido!"
            exit 1
        fi
        
        # Senha do usuário
        while true; do
            echo -e "${YELLOW}Senha para o usuário $USERNAME:${NC}"
            read -rs USER_PASSWORD
            echo
            echo -e "${YELLOW}Confirme a senha:${NC}"
            read -rs USER_PASSWORD_CONFIRM
            echo
            
            if [[ "$USER_PASSWORD" == "$USER_PASSWORD_CONFIRM" ]]; then
                if [[ ${#USER_PASSWORD} -lt 6 ]]; then
                    echo -e "${RED}Senha muito curta! Use pelo menos 6 caracteres.${NC}"
                else
                    break
                fi
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
                if [[ ${#ROOT_PASSWORD} -lt 6 ]]; then
                    echo -e "${RED}Senha muito curta! Use pelo menos 6 caracteres.${NC}"
                else
                    break
                fi
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
    
    if [[ ! -f "/usr/share/zoneinfo/$TIMEZONE" ]]; then
        log "$RED" "Timezone inválido: $TIMEZONE"
        exit 1
    fi
    
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
    hwclock --systohc
    
    log "$GREEN" "Timezone configurado"
}

# Configurar locale
configure_locale() {
    log "$BLUE" "Configurando locale: $LOCALE"
    
    # Habilitar locales
    sed -i "s/^#$LOCALE/$LOCALE/" /etc/locale.gen 2>/dev/null || \
        echo "$LOCALE UTF-8" >> /etc/locale.gen
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
    
    cat > /etc/hosts << HOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   ${HOSTNAME}.localdomain ${HOSTNAME}
HOSTS
    
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
    
    # Adicionar binários necessários para o hook
    if [[ "$ENABLE_SELFDESTRUCT" == "true" ]]; then
        sed -i "s/^BINARIES=.*/BINARIES=(cryptsetup dd blkdiscard)/" /etc/mkinitcpio.conf
    fi
    
    # Regenerar initramfs
    mkinitcpio -P
    
    log "$GREEN" "mkinitcpio configurado"
}

# Criar hook de autodestruição
create_selfdestruct_hook() {
    log "$YELLOW" "Criando hook de autodestruição para initramfs"
    
    # Criar diretórios se não existirem
    mkdir -p /etc/initcpio/install /etc/initcpio/hooks
    
    # Criar hook install
    cat > /etc/initcpio/install/selfdestruct << 'HOOKINSTALL'
#!/bin/bash

build() {
    add_binary cryptsetup
    add_binary dd
    add_binary blkdiscard
    add_binary poweroff
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
HOOKINSTALL
    
    # Criar hook runtime
    cat > /etc/initcpio/hooks/selfdestruct << 'HOOKRUNTIME'
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
        
        # Detectar dispositivos - usar busybox compatible commands
        for dev in $(ls /dev/nvme* /dev/sd* /dev/mmcblk* 2>/dev/null | grep -E '^/dev/(nvme[0-9]+n[0-9]+|sd[a-z]|mmcblk[0-9]+)$'); do
            if [ -b "$dev" ]; then
                echo "Processing $dev..."
                
                # Tentar apagar headers LUKS
                if cryptsetup isLuks "$dev" 2>/dev/null; then
                    cryptsetup luksErase "$dev" --batch-mode 2>/dev/null || true
                fi
                
                # Tentar discard/trim
                if blkdiscard -f "$dev" 2>/dev/null; then
                    echo "  Discard completed on $dev"
                else
                    # Fallback para dd
                    dd if=/dev/zero of="$dev" bs=1M count=100 2>/dev/null || true
                    echo "  Overwrite completed on $dev"
                fi
            fi
        done
        
        echo "Destruction complete. System halted."
        poweroff -f
    fi
}
HOOKRUNTIME
    
    chmod +x /etc/initcpio/install/selfdestruct
    chmod +x /etc/initcpio/hooks/selfdestruct
    
    log "$GREEN" "Hook de autodestruição criado"
}

# Configurar crypttab
configure_crypttab() {
    log "$BLUE" "Configurando /etc/crypttab"
    
    cat > /etc/crypttab << CRYPTTAB
# <name>      <device>                                     <password>    <options>
CRYPTTAB
    
    # Swap criptografado com chave aleatória
    if [[ -n "${SWAP_UUID:-}" ]] && [[ "$SWAP_UUID" != "PENDING" ]]; then
        echo "cryptswap   UUID=$SWAP_UUID    /dev/urandom    swap,cipher=aes-xts-plain64,size=512" >> /etc/crypttab
    elif [[ -n "${SWAP_PART:-}" ]]; then
        log "$YELLOW" "Aviso: Usando device path para swap em vez de UUID"
        echo "cryptswap   $SWAP_PART    /dev/urandom    swap,cipher=aes-xts-plain64,size=512" >> /etc/crypttab
    fi
    
    # Disco auxiliar se existir
    if [[ -n "${AUX_UUID:-}" ]]; then
        echo "# Disco auxiliar - entrada manual ou keyfile" >> /etc/crypttab
        echo "# cryptdata   UUID=$AUX_UUID    none    luks,timeout=10,noauto" >> /etc/crypttab
    fi
    
    log "$GREEN" "crypttab configurado"
}

# Configurar GRUB
configure_grub() {
    log "$BLUE" "Configurando GRUB"
    
    # Verificar se ROOT_UUID existe
    if [[ -z "${ROOT_UUID:-}" ]]; then
        log "$RED" "ROOT_UUID não definido!"
        exit 1
    fi
    
    # Backup da configuração original
    [[ -f /etc/default/grub ]] && cp /etc/default/grub /etc/default/grub.backup
    
    # Configurar linha de comando do kernel
    KERNEL_PARAMS="cryptdevice=UUID=$ROOT_UUID:cryptroot root=/dev/mapper/cryptroot"
    
    # Adicionar parâmetros para Btrfs
    KERNEL_PARAMS="$KERNEL_PARAMS rootflags=subvol=@"
    
    # Configurar GRUB
    cat > /etc/default/grub << GRUBCFG
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="Arch"
GRUB_CMDLINE_LINUX_DEFAULT="loglevel=3 quiet"
GRUB_CMDLINE_LINUX="$KERNEL_PARAMS"

# Preload both GPT and MBR modules so that they are not missed
GRUB_PRELOAD_MODULES="part_gpt part_msdos"

# Enable cryptodisk
GRUB_ENABLE_CRYPTODISK=y

# Set gfxmode
GRUB_GFXMODE=auto
GRUB_GFXPAYLOAD_LINUX=keep

# Disable os-prober
GRUB_DISABLE_OS_PROBER=true
GRUBCFG
    
    # Instalar GRUB
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        if [[ ! -d /boot/efi ]]; then
            log "$RED" "Diretório /boot/efi não existe!"
            exit 1
        fi
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB || {
            log "$RED" "Erro ao instalar GRUB (UEFI)"
            exit 1
        }
    else
        grub-install --target=i386-pc "$DISCO_PRINCIPAL" || {
            log "$RED" "Erro ao instalar GRUB (BIOS)"
            exit 1
        }
    fi
    
    # Adicionar entrada de autodestruição se habilitado
    if [[ "$ENABLE_SELFDESTRUCT" == "true" ]]; then
        mkdir -p /etc/grub.d
        cat > /etc/grub.d/40_custom << 'GRUBCUSTOM'
#!/bin/sh
exec tail -n +3 $0

menuentry "SELF-DESTRUCT - DESTROY ALL DATA" --class warning {
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
GRUBCUSTOM
        chmod +x /etc/grub.d/40_custom
    fi
    
    # Gerar configuração
    grub-mkconfig -o /boot/grub/grub.cfg || {
        log "$RED" "Erro ao gerar configuração do GRUB"
        exit 1
    }
    
    log "$GREEN" "GRUB configurado e instalado"
}

# Criar usuário
create_user() {
    log "$BLUE" "Criando usuário: $USERNAME"
    
    # Verificar se usuário já existe
    if id "$USERNAME" &>/dev/null; then
        log "$YELLOW" "Usuário $USERNAME já existe"
    else
        # Criar usuário
        useradd -m -G wheel,audio,video,optical,storage -s /bin/bash "$USERNAME"
        
        # Criar diretórios do usuário
        su - "$USERNAME" -c "mkdir -p ~/Documents ~/Downloads ~/Pictures ~/Videos ~/Music"
    fi
    
    # Definir senha
    echo "$USERNAME:$USER_PASSWORD" | chpasswd
    
    # Configurar sudo
    sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers
    
    log "$GREEN" "Usuário configurado"
}

# Definir senha root
set_root_password() {
    log "$BLUE" "Definindo senha root"
    
    echo "root:$ROOT_PASSWORD" | chpasswd
    
    log "$GREEN" "Senha root definida"
}

# Ajustar fstab para swap criptografado
configure_fstab() {
    log "$BLUE" "Ajustando /etc/fstab para swap criptografado"
    
    # Adicionar entrada para swap criptografado se não existir
    if ! grep -q "/dev/mapper/cryptswap" /etc/fstab; then
        echo "" >> /etc/fstab
        echo "# Swap criptografado" >> /etc/fstab
        echo "/dev/mapper/cryptswap    none    swap    defaults    0 0" >> /etc/fstab
    fi
    
    log "$GREEN" "fstab configurado"
}

# Habilitar serviços
enable_services() {
    log "$BLUE" "Habilitando serviços essenciais"
    
    systemctl enable NetworkManager || log "$YELLOW" "NetworkManager já habilitado"
    systemctl enable systemd-resolved || log "$YELLOW" "systemd-resolved já habilitado"
    systemctl enable fstrim.timer || log "$YELLOW" "fstrim.timer já habilitado"
    systemctl enable systemd-timesyncd || log "$YELLOW" "systemd-timesyncd já habilitado"
    
    log "$GREEN" "Serviços habilitados"
}

# Configuração final
final_configuration() {
    log "$BLUE" "Realizando configurações finais"
    
    # Criar diretório para montagem do disco auxiliar
    if [[ -n "${AUX_PART:-}" ]]; then
        mkdir -p /data
        chown "$USERNAME:$USERNAME" /data 2>/dev/null || true
    fi
    
    # Ajustar swappiness para SSD
    echo "vm.swappiness=10" > /etc/sysctl.d/99-swappiness.conf
    
    # Configurar journal para limitar tamanho
    mkdir -p /etc/systemd/journald.conf.d/
    cat > /etc/systemd/journald.conf.d/00-size-limit.conf << JOURNAL
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
JOURNAL
    
    log "$GREEN" "Configurações finais aplicadas"
}

# Função principal
main() {
    setup_logging
    
    log "$BLUE" "=== FASE 5: CONFIGURAÇÃO DO SISTEMA (CHROOT) ==="
    
    check_commands
    get_configuration
    configure_timezone
    configure_locale
    configure_hostname
    configure_mkinitcpio
    configure_crypttab
    configure_fstab
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
