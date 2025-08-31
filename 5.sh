#!/bin/bash
#5 ============================================================================
# Arch Linux + XFCE4 - Script de Instalação Otimizado
# Baseado em: https://github.com/macafd/Archmonkey
# Versão simplificada e otimizada para desktop leve
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Diretórios e arquivos
LOG_DIR="/var/log/arch-setup"
CONFIG_FILE="/tmp/arch-install-config.json"
ENV_FILE="/tmp/arch_setup_vars.env"
SCRIPT_VERSION="1.0.0"

# Configurações padrão
DEFAULT_TIMEZONE="America/Sao_Paulo"
DEFAULT_LOCALE="pt_BR.UTF-8"
DEFAULT_KEYMAP="br-abnt2"
DEFAULT_HOSTNAME="archlinux"

# ============================================================================
# FUNÇÕES DE UTILIDADE
# ============================================================================

# Setup logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install-$(date '+%Y%m%d-%H%M%S').log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
}

# Função de log
log() {
    local level="$1"
    shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}"
}

# Verificar se está rodando como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "$RED" "Este script deve ser executado como root!"
        exit 1
    fi
}

# Verificar modo de boot (UEFI ou BIOS)
check_boot_mode() {
    if [[ -d /sys/firmware/efi/efivars ]]; then
        BOOT_MODE="UEFI"
        log "$GREEN" "Sistema detectado: UEFI"
    else
        BOOT_MODE="BIOS"
        log "$GREEN" "Sistema detectado: BIOS"
    fi
}

# Verificar conexão com internet
check_internet() {
    log "$BLUE" "Verificando conexão com a internet..."
    if ! ping -c 1 archlinux.org &>/dev/null; then
        log "$RED" "Sem conexão com a internet!"
        log "$YELLOW" "Configure a rede e tente novamente."
        exit 1
    fi
    log "$GREEN" "Conexão com internet OK"
}

# Verificar comandos necessários
check_commands() {
    local required_cmds=("fdisk" "mkfs.fat" "mkfs.ext4" "mount" "pacstrap" "arch-chroot" "genfstab")
    local missing_cmds=()
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log "$RED" "Comandos faltando: ${missing_cmds[*]}"
        exit 1
    fi
}

# ============================================================================
# FASE 1: PREPARAÇÃO E CONFIGURAÇÃO
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     Arch Linux + XFCE4 - Instalador Otimizado v$SCRIPT_VERSION    ║"
    echo "║                   Desktop Leve e Rápido                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Modo interativo ou não-interativo
select_mode() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "$BLUE" "Arquivo de configuração detectado. Usando modo não-interativo."
        NON_INTERACTIVE=true
        load_config_file
    else
        log "$YELLOW" "Modo de instalação:"
        echo "1) Interativo (com perguntas)"
        echo "2) Não-interativo (usar arquivo de configuração)"
        read -r -p "Escolha [1]: " mode_choice
        mode_choice=${mode_choice:-1}
        
        if [[ "$mode_choice" == "2" ]]; then
            NON_INTERACTIVE=true
            create_sample_config
            log "$RED" "Edite o arquivo $CONFIG_FILE e rode o script novamente."
            exit 0
        else
            NON_INTERACTIVE=false
        fi
    fi
}

# Criar arquivo de configuração de exemplo
create_sample_config() {
    cat > "$CONFIG_FILE" <<EOF
{
    "disk": "/dev/sda",
    "hostname": "archlinux",
    "username": "user",
    "user_password": "password",
    "root_password": "rootpassword",
    "timezone": "America/Sao_Paulo",
    "locale": "pt_BR.UTF-8",
    "keymap": "br-abnt2",
    "autologin": false,
    "swap_size": "2G",
    "packages": {
        "xfce4": ["xfce4", "xfce4-goodies", "xfce4-terminal", "xfce4-notifyd"],
        "apps": ["firefox", "nano", "htop", "neofetch", "git"],
        "multimedia": ["pulseaudio", "pavucontrol", "vlc"],
        "system": ["networkmanager", "network-manager-applet", "gvfs", "thunar-volman"]
    }
}
EOF
}

# Carregar configuração do arquivo
load_config_file() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "$RED" "Arquivo de configuração não encontrado!"
        exit 1
    fi
    
    # Validar JSON
    if ! command -v jq &>/dev/null; then
        log "$YELLOW" "Instalando jq para processar JSON..."
        pacman -Sy --noconfirm jq
    fi
    
    # Carregar variáveis
    DISK=$(jq -r '.disk' "$CONFIG_FILE")
    HOSTNAME=$(jq -r '.hostname' "$CONFIG_FILE")
    USERNAME=$(jq -r '.username' "$CONFIG_FILE")
    USER_PASSWORD=$(jq -r '.user_password' "$CONFIG_FILE")
    ROOT_PASSWORD=$(jq -r '.root_password' "$CONFIG_FILE")
    TIMEZONE=$(jq -r '.timezone // "America/Sao_Paulo"' "$CONFIG_FILE")
    LOCALE=$(jq -r '.locale // "pt_BR.UTF-8"' "$CONFIG_FILE")
    KEYMAP=$(jq -r '.keymap // "br-abnt2"' "$CONFIG_FILE")
    AUTOLOGIN=$(jq -r '.autologin // false' "$CONFIG_FILE")
    SWAP_SIZE=$(jq -r '.swap_size // "2G"' "$CONFIG_FILE")
}

# ============================================================================
# FASE 2: PARTICIONAMENTO
# ============================================================================

select_disk() {
    if [[ "$NON_INTERACTIVE" == true ]]; then
        if [[ ! -b "$DISK" ]]; then
            log "$RED" "Disco $DISK não encontrado!"
            exit 1
        fi
    else
        log "$BLUE" "Discos disponíveis:"
        lsblk -d -o NAME,SIZE,TYPE | grep disk
        
        echo -e "${YELLOW}Digite o disco para instalação (ex: /dev/sda):${NC}"
        read -r DISK
        
        if [[ ! -b "$DISK" ]]; then
            log "$RED" "Disco inválido!"
            exit 1
        fi
        
        log "$RED" "ATENÇÃO: Todos os dados em $DISK serão apagados!"
        echo -e "${YELLOW}Digite 'CONFIRMAR' para continuar:${NC}"
        read -r confirm
        if [[ "$confirm" != "CONFIRMAR" ]]; then
            log "$YELLOW" "Instalação cancelada."
            exit 0
        fi
    fi
}

partition_disk() {
    log "$BLUE" "Particionando disco $DISK..."
    
    # Limpar disco
    wipefs -af "$DISK"
    sgdisk -Z "$DISK"
    
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$CYAN" "Criando partições UEFI..."
        parted -s "$DISK" \
            mklabel gpt \
            mkpart ESP fat32 1MiB 512MiB \
            set 1 esp on \
            mkpart primary ext4 512MiB 100%
        
        # Aguardar partições
        sleep 2
        partprobe "$DISK"
        
        # Identificar partições
        if [[ "$DISK" =~ nvme ]]; then
            EFI_PART="${DISK}p1"
            ROOT_PART="${DISK}p2"
        else
            EFI_PART="${DISK}1"
            ROOT_PART="${DISK}2"
        fi
    else
        log "$CYAN" "Criando partições BIOS..."
        parted -s "$DISK" \
            mklabel msdos \
            mkpart primary ext4 1MiB 100% \
            set 1 boot on
        
        # Aguardar partições
        sleep 2
        partprobe "$DISK"
        
        # Identificar partições
        if [[ "$DISK" =~ nvme ]]; then
            ROOT_PART="${DISK}p1"
        else
            ROOT_PART="${DISK}1"
        fi
    fi
    
    log "$GREEN" "Particionamento concluído"
}

format_partitions() {
    log "$BLUE" "Formatando partições..."
    
    # Formatar partição root
    mkfs.ext4 -F "$ROOT_PART"
    
    # Formatar partição EFI se UEFI
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        mkfs.fat -F32 "$EFI_PART"
    fi
    
    log "$GREEN" "Formatação concluída"
}

mount_partitions() {
    log "$BLUE" "Montando partições..."
    
    # Montar root
    mount "$ROOT_PART" /mnt
    
    # Criar e montar EFI se UEFI
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        mkdir -p /mnt/boot/efi
        mount "$EFI_PART" /mnt/boot/efi
    fi
    
    # Criar arquivo swap
    if [[ -n "$SWAP_SIZE" ]] && [[ "$SWAP_SIZE" != "0" ]]; then
        log "$CYAN" "Criando arquivo swap de $SWAP_SIZE..."
        fallocate -l "$SWAP_SIZE" /mnt/swapfile
        chmod 600 /mnt/swapfile
        mkswap /mnt/swapfile
        swapon /mnt/swapfile
    fi
    
    log "$GREEN" "Montagem concluída"
}

# ============================================================================
# FASE 3: INSTALAÇÃO DO SISTEMA BASE
# ============================================================================

install_base_system() {
    log "$BLUE" "Instalando sistema base..."
    
    # Atualizar mirrorlist para Brasil
    log "$CYAN" "Otimizando mirrors para Brasil..."
    curl -s "https://archlinux.org/mirrorlist/?country=BR&protocol=https&use_mirror_status=on" | \
        sed -e 's/^#Server/Server/' -e '/^#/d' > /etc/pacman.d/mirrorlist
    
    # Pacotes base essenciais
    BASE_PACKAGES=(
        base
        base-devel
        linux
        linux-firmware
        linux-headers
        intel-ucode
        amd-ucode
        btrfs-progs
        e2fsprogs
        dosfstools
        grub
        efibootmgr
        networkmanager
        nano
        vim
        sudo
        git
        wget
        curl
    )
    
    # Instalar sistema base
    pacstrap /mnt "${BASE_PACKAGES[@]}"
    
    log "$GREEN" "Sistema base instalado"
}

generate_fstab() {
    log "$BLUE" "Gerando fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab
    
    # Adicionar entrada para swapfile se existir
    if [[ -f /mnt/swapfile ]]; then
        echo "/swapfile none swap defaults 0 0" >> /mnt/etc/fstab
    fi
    
    log "$GREEN" "fstab gerado"
}

# ============================================================================
# FASE 4: CONFIGURAÇÃO DO SISTEMA (CHROOT)
# ============================================================================

configure_system() {
    log "$BLUE" "Configurando sistema..."
    
    # Criar script de configuração para chroot
    cat > /mnt/configure-chroot.sh <<'CHROOT_SCRIPT'
#!/bin/bash

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${2:-$BLUE}[$(date '+%H:%M:%S')] $1${NC}"
}

# Carregar variáveis
source /tmp/arch_setup_vars.env

# Configurar timezone
log "Configurando timezone..."
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
hwclock --systohc

# Configurar locale
log "Configurando locale..."
echo "$LOCALE UTF-8" >> /etc/locale.gen
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
echo "KEYMAP=$KEYMAP" > /etc/vconsole.conf

# Configurar hostname
log "Configurando hostname..."
echo "$HOSTNAME" > /etc/hostname
cat > /etc/hosts <<EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $HOSTNAME.localdomain $HOSTNAME
EOF

# Configurar mkinitcpio
log "Configurando initramfs..."
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

# Instalar e configurar GRUB
log "Instalando GRUB..."
if [[ "$BOOT_MODE" == "UEFI" ]]; then
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
else
    grub-install --target=i386-pc "$DISK"
fi

# Otimizar GRUB para boot rápido
cat >> /etc/default/grub <<EOF

# Otimizações para boot rápido
GRUB_TIMEOUT=2
GRUB_CMDLINE_LINUX_DEFAULT="quiet loglevel=3 nowatchdog modprobe.blacklist=iTCO_wdt"
GRUB_CMDLINE_LINUX=""
EOF

grub-mkconfig -o /boot/grub/grub.cfg

# Criar usuário
log "Criando usuário $USERNAME..."
useradd -m -G wheel,audio,video,optical,storage,power -s /bin/bash "$USERNAME"
echo "$USERNAME:$USER_PASSWORD" | chpasswd
echo "root:$ROOT_PASSWORD" | chpasswd

# Configurar sudo
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

# Instalar XFCE4 e aplicações
log "Instalando XFCE4 e aplicações..." "$GREEN"
pacman -S --noconfirm \
    xorg xorg-server \
    xfce4 xfce4-goodies \
    lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings \
    firefox \
    networkmanager network-manager-applet \
    pulseaudio pavucontrol \
    gvfs gvfs-mtp thunar-volman \
    file-roller \
    ristretto \
    mousepad \
    xfce4-terminal \
    xfce4-taskmanager \
    xfce4-power-manager \
    xfce4-notifyd \
    xfce4-whiskermenu-plugin \
    ttf-liberation ttf-dejavu noto-fonts \
    papirus-icon-theme \
    htop neofetch \
    preload

# Configurar autologin se solicitado
if [[ "$AUTOLOGIN" == "true" ]]; then
    log "Configurando autologin..."
    groupadd -r autologin
    gpasswd -a "$USERNAME" autologin
    
    mkdir -p /etc/lightdm/lightdm.conf.d/
    cat > /etc/lightdm/lightdm.conf.d/autologin.conf <<EOF
[Seat:*]
autologin-user=$USERNAME
autologin-user-timeout=0
autologin-session=xfce
EOF
fi

# Otimizações do sistema
log "Aplicando otimizações..." "$YELLOW"

# Swappiness para desktop
echo "vm.swappiness=10" > /etc/sysctl.d/99-swappiness.conf
echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.d/99-swappiness.conf

# Limitar journald
mkdir -p /etc/systemd/journald.conf.d/
cat > /etc/systemd/journald.conf.d/00-journal-size.conf <<EOF
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
MaxFileSec=1month
EOF

# Desabilitar serviços desnecessários
systemctl mask lvm2-monitor.service
systemctl mask ModemManager.service

# Habilitar serviços essenciais
log "Habilitando serviços..."
systemctl enable NetworkManager
systemctl enable lightdm
systemctl enable fstrim.timer
systemctl enable preload

# Configurar XFCE4 para performance
mkdir -p /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/
cat > /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="use_compositing" type="bool" value="false"/>
    <property name="box_move" type="bool" value="false"/>
    <property name="box_resize" type="bool" value="false"/>
    <property name="scroll_workspaces" type="bool" value="false"/>
  </property>
</channel>
EOF

# Copiar configurações para o usuário
cp -r /etc/skel/.config /home/$USERNAME/
chown -R $USERNAME:$USERNAME /home/$USERNAME/.config

log "Configuração concluída!" "$GREEN"
CHROOT_SCRIPT

    # Exportar variáveis para o chroot
    cat > /mnt/tmp/arch_setup_vars.env <<EOF
TIMEZONE="$TIMEZONE"
LOCALE="$LOCALE"
KEYMAP="$KEYMAP"
HOSTNAME="$HOSTNAME"
USERNAME="$USERNAME"
USER_PASSWORD="$USER_PASSWORD"
ROOT_PASSWORD="$ROOT_PASSWORD"
BOOT_MODE="$BOOT_MODE"
DISK="$DISK"
AUTOLOGIN="$AUTOLOGIN"
EOF

    # Executar configuração no chroot
    chmod +x /mnt/configure-chroot.sh
    arch-chroot /mnt /configure-chroot.sh
    
    # Limpar
    rm /mnt/configure-chroot.sh
    rm /mnt/tmp/arch_setup_vars.env
    
    log "$GREEN" "Sistema configurado com sucesso!"
}

# ============================================================================
# FASE 5: INSTALAÇÃO DE SOFTWARE ADICIONAL (OPCIONAL)
# ============================================================================

install_additional_software() {
    if [[ "$NON_INTERACTIVE" == true ]]; then
        # Instalar pacotes adicionais do config
        if command -v jq &>/dev/null; then
            EXTRA_APPS=$(jq -r '.packages.apps[]?' "$CONFIG_FILE" 2>/dev/null | tr '\n' ' ')
            MULTIMEDIA=$(jq -r '.packages.multimedia[]?' "$CONFIG_FILE" 2>/dev/null | tr '\n' ' ')
            
            if [[ -n "$EXTRA_APPS$MULTIMEDIA" ]]; then
                log "$BLUE" "Instalando software adicional..."
                arch-chroot /mnt pacman -S --noconfirm $EXTRA_APPS $MULTIMEDIA
            fi
        fi
    else
        log "$YELLOW" "Deseja instalar software adicional? [s/N]"
        read -r install_extra
        
        if [[ "$install_extra" =~ ^[Ss]$ ]]; then
            log "$BLUE" "Categorias disponíveis:"
            echo "1) Desenvolvimento (vscode, nodejs, docker)"
            echo "2) Multimídia (vlc, gimp, audacity)"
            echo "3) Escritório (libreoffice, thunderbird)"
            echo "4) Jogos (steam, lutris)"
            echo "5) Todas as anteriores"
            echo "0) Nenhuma"
            
            read -r -p "Escolha [0]: " category
            category=${category:-0}
            
            case $category in
                1)
                    arch-chroot /mnt pacman -S --noconfirm code nodejs npm docker docker-compose
                    arch-chroot /mnt systemctl enable docker
                    ;;
                2)
                    arch-chroot /mnt pacman -S --noconfirm vlc gimp audacity
                    ;;
                3)
                    arch-chroot /mnt pacman -S --noconfirm libreoffice-fresh thunderbird
                    ;;
                4)
                    # Habilitar multilib para Steam
                    sed -i '/\[multilib\]/,/Include/s/^#//' /mnt/etc/pacman.conf
                    arch-chroot /mnt pacman -Sy
                    arch-chroot /mnt pacman -S --noconfirm steam lutris wine
                    ;;
                5)
                    sed -i '/\[multilib\]/,/Include/s/^#//' /mnt/etc/pacman.conf
                    arch-chroot /mnt pacman -Sy
                    arch-chroot /mnt pacman -S --noconfirm \
                        code nodejs npm docker docker-compose \
                        vlc gimp audacity \
                        libreoffice-fresh thunderbird \
                        steam lutris wine
                    arch-chroot /mnt systemctl enable docker
                    ;;
            esac
        fi
    fi
}

# ============================================================================
# FASE 6: FINALIZAÇÃO
# ============================================================================

create_post_install_script() {
    log "$BLUE" "Criando script pós-instalação..."
    
    cat > /mnt/home/$USERNAME/post-install.sh <<'POST_SCRIPT'
#!/bin/bash

# Script de pós-instalação para Arch Linux + XFCE4

echo "=== Script de Pós-Instalação ==="
echo ""
echo "1. Atualizando sistema..."
sudo pacman -Syu --noconfirm

echo ""
echo "2. Instalando AUR helper (yay)..."
cd /tmp
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si --noconfirm
cd ~
rm -rf /tmp/yay

echo ""
echo "3. Configurações recomendadas:"
echo "   - Configure o tema do XFCE em Configurações > Aparência"
echo "   - Configure os atalhos em Configurações > Teclado"
echo "   - Adicione widgets ao painel conforme necessário"
echo "   - Configure o Whisker Menu como menu principal"

echo ""
echo "4. Aplicações recomendadas do AUR:"
echo "   yay -S brave-bin spotify vscodium-bin"

echo ""
echo "5. Para melhor performance:"
echo "   - Desative composição em Configurações > Gerenciador de Janelas > Compositor"
echo "   - Use temas leves como Greybird ou Arc"
echo "   - Desative efeitos visuais desnecessários"

echo ""
echo "Script concluído! Aproveite seu Arch Linux otimizado!"
POST_SCRIPT

    chmod +x /mnt/home/$USERNAME/post-install.sh
    arch-chroot /mnt chown $USERNAME:$USERNAME /home/$USERNAME/post-install.sh
    
    log "$GREEN" "Script pós-instalação criado em /home/$USERNAME/post-install.sh"
}

cleanup_and_finish() {
    log "$BLUE" "Finalizando instalação..."
    
    # Desmontar partições
    umount -R /mnt 2>/dev/null || true
    
    # Mensagem final
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           INSTALAÇÃO CONCLUÍDA COM SUCESSO!               ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}Informações do sistema instalado:${NC}"
    echo -e "  Hostname: ${GREEN}$HOSTNAME${NC}"
    echo -e "  Usuário: ${GREEN}$USERNAME${NC}"
    echo -e "  Desktop: ${GREEN}XFCE4${NC}"
    echo -e "  Boot: ${GREEN}$BOOT_MODE${NC}"
    echo ""
    echo -e "${YELLOW}Próximos passos:${NC}"
    echo "1. Remova a mídia de instalação"
    echo "2. Reinicie o sistema: ${GREEN}reboot${NC}"
    echo "3. Faça login com o usuário: ${GREEN}$USERNAME${NC}"
    echo "4. Execute o script pós-instalação: ${GREEN}./post-install.sh${NC}"
    echo ""
    echo -e "${BLUE}Logs da instalação salvos em: $LOG_DIR${NC}"
    echo ""
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Preparação
    print_banner
    setup_logging
    check_root
    check_boot_mode
    check_internet
    check_commands
    
    log "$MAGENTA" "=== INICIANDO INSTALAÇÃO DO ARCH LINUX + XFCE4 ==="
    
    # Fase 1: Configuração
    select_mode
    
    if [[ "$NON_INTERACTIVE" == false ]]; then
        # Coletar informações no modo interativo
        echo -e "${YELLOW}Nome do computador (hostname) [$DEFAULT_HOSTNAME]:${NC}"
        read -r HOSTNAME
        HOSTNAME=${HOSTNAME:-$DEFAULT_HOSTNAME}
        
        echo -e "${YELLOW}Nome de usuário:${NC}"
        read -r USERNAME
        
        echo -e "${YELLOW}Senha do usuário:${NC}"
        read -rs USER_PASSWORD
        echo
        
        echo -e "${YELLOW}Senha do root:${NC}"
        read -rs ROOT_PASSWORD
        echo
        
        echo -e "${YELLOW}Timezone [$DEFAULT_TIMEZONE]:${NC}"
        read -r TIMEZONE
        TIMEZONE=${TIMEZONE:-$DEFAULT_TIMEZONE}
        
        echo -e "${YELLOW}Locale [$DEFAULT_LOCALE]:${NC}"
        read -r LOCALE
        LOCALE=${LOCALE:-$DEFAULT_LOCALE}
        
        echo -e "${YELLOW}Keymap [$DEFAULT_KEYMAP]:${NC}"
        read -r KEYMAP
        KEYMAP=${KEYMAP:-$DEFAULT_KEYMAP}
        
        echo -e "${YELLOW}Tamanho do swap (ex: 2G, 0 para não criar) [2G]:${NC}"
        read -r SWAP_SIZE
        SWAP_SIZE=${SWAP_SIZE:-2G}
        
        echo -e "${YELLOW}Habilitar autologin? [s/N]:${NC}"
        read -r autologin_choice
        if [[ "$autologin_choice" =~ ^[Ss]$ ]]; then
            AUTOLOGIN=true
        else
            AUTOLOGIN=false
        fi
    fi
    
    # Fase 2: Particionamento
    select_disk
    partition_disk
    format_partitions
    mount_partitions
    
    # Fase 3: Instalação base
    install_base_system
    generate_fstab
    
    # Fase 4: Configuração do sistema
    configure_system
    
    # Fase 5: Software adicional
    install_additional_software
    
    # Fase 6: Finalização
    create_post_install_script
    cleanup_and_finish
}

# ============================================================================
# EXECUÇÃO
# ============================================================================

# Tratamento de erros
trap 'log "$RED" "Erro na linha $LINENO. Instalação abortada."; exit 1' ERR

# Executar instalação
main "$@"