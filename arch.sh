#!/usr/bin/env bash
#
# Archmonkey - Secure Arch Linux Installer
# Versão modificada com funcionalidades avançadas de segurança e automação.
#
set -euo pipefail
IFS=$'\n\t'

# --- CORES E LOGGING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# -------------------- OPÇÕES DE CONFIGURAÇÃO --------------------
# --- GERAL ---
HOSTNAME="arch-secure"
TIMEZONE="America/Sao_Paulo"
LOCALE="pt_BR.UTF-8"
KEYMAP="br-abnt2"
USERNAME="operador"
USER_SHELL="/bin/bash"

# --- DISCOS E PARTIÇÕES ---
# AVISO: Nomes como /dev/sdX podem mudar. Use /dev/disk/by-id/... para máxima robustez.
TARGET_DISK="${TARGET_DISK:-/dev/sda}"
DATA_DISK="${DATA_DISK:-/dev/sdb}"

EFI_SIZE_MIB=512
BOOT_SIZE_MIB=1024
## AJUSTE: O swap será um arquivo, não uma partição. Definimos o tamanho aqui.
SWAP_FILE_SIZE_GB=4

# --- CRIPTOGRAFIA E LVM ---
ENABLE_DUAL_ENCRYPTION=1
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512
LUKS_KDF="argon2id"
LUKS_PBKDF_MEM=65536
LUKS_ITER_TIME=2000
PBKDF_PARALLEL=2
VG_NAME="vg_system"
LV_ROOT_NAME="lv_root"
# ## AJUSTE: Volume de swap removido do LVM.
LV_HOME_NAME="lv_home"
LV_ROOT_SIZE="30G"

# --- SEGURANÇA E AUTODESTRUIÇÃO ---
ENABLE_AUTO_DESTRUCTION=1
DESTRUCTION_WEBHOOK_URL="${DESTRUCTION_WEBHOOK_URL:-}"
REMOTE_BACKUP_URL="${REMOTE_BACKUP_URL:-}"

## MELHORIA: Opções de performance e segurança adicionais.
KERNEL_PACKAGE="linux-zen" # Use "linux" para o padrão, "linux-lts" para suporte longo, ou "linux-zen" para performance.
ENABLE_ZRAM=1              # 1 para usar ZRAM (recomendado para baixa RAM), 0 para usar swap em arquivo.
ENABLE_USBGUARD=1          # 1 para instalar e habilitar o USBGuard (requer configuração pós-instalação).

# --- PACOTES ---
EXTRA_PKGS_FILE="pkglist.txt"
EXTRA_PKGS_ENV="${EXTRA_PKGS_ENV:-}"
DESKTOP_ENVIRONMENT_PACKAGES="i3-wm i3status dmenu terminator xorg-server xorg-xinit xbindkeys zenity polkit"

# --- DEBUG ---
SHOW_PASSWORDS="${SHOW_PASSWORDS:-0}"

# --- SENHAS (podem ser passadas por variável de ambiente para automação) ---
LUKS_PASS="${LUKS_PASS:-}"
DESTRUCTION_PASS="${DESTRUCTION_PASS:-}"
ROOT_PASS="${ROOT_PASS:-}"
USER_PASS="${USER_PASS:-}"
PIN_DATA="${PIN_DATA:-}"

# -------------------- LOGGING SEGURO --------------------
if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
  LOGFILE="/dev/null"
else
  LOGFILE="/var/log/arch_install.log"
  mkdir -p /var/log
fi

if [[ "$LOGFILE" != "/dev/null" ]]; then
  >"$LOGFILE"
  chmod 600 "$LOGFILE"
fi
exec > >(tee -a "$LOGFILE") 2>&1

# -------------------- FUNÇÕES AUXILIARES --------------------
info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[AVISO]${NC} %s\n" "$*"; }
err() { printf "${RED}[ERRO]${NC} %s\n" "$*"; }
fatal() {
  err "$*"
  exit 1
}
require_root() { ((EUID == 0)) || fatal "Este script deve ser executado como root."; }

# ... (Funções show_help, secure_cleanup, mask_secret, display_passwords_for_confirmation, collect_passwords_interactive, validate_environment, setup_network_and_keys, sanitize_devices, part_suffix, partition_devices permanecem praticamente as mesmas) ...
# Apenas pequenas alterações serão feitas nas funções relevantes abaixo.

# ... (Cole aqui as funções inalteradas do seu script original para manter a completude)
# show_help, secure_cleanup, mask_secret, display_passwords_for_confirmation, collect_passwords_interactive, validate_environment, setup_network_and_keys, sanitize_devices, part_suffix, partition_devices

setup_encryption_and_lvm() {
  local p
  p=$(part_suffix "$TARGET_DISK")
  local system_partition="${TARGET_DISK}${p}3"

  info "Configurando criptografia LUKS no disco do sistema..."
  echo -n "$LUKS_PASS" | cryptsetup luksFormat \
    --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
    --pbkdf "$LUKS_KDF" --pbkdf-memory "$LUKS_PBKDF_MEM" --iter-time "$LUKS_ITER_TIME" \
    --pbkdf-parallel "$PBKDF_PARALLEL" --label "cryptroot" --batch-mode "$system_partition"

  info "Desbloqueando partição LUKS do sistema..."
  echo -n "$LUKS_PASS" | cryptsetup open "$system_partition" cryptroot

  info "Configurando LVM sobre LUKS..."
  pvcreate /dev/mapper/cryptroot
  vgcreate "$VG_NAME" /dev/mapper/cryptroot
  lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME"
  ## AJUSTE: Volume de swap removido do LVM.
  lvcreate -l '100%FREE' -n "$LV_HOME_NAME" "$VG_NAME"

  info "Formatando volumes LVM..."
  mkfs.ext4 "/dev/$VG_NAME/$LV_ROOT_NAME"
  mkfs.ext4 "/dev/$VG_NAME/$LV_HOME_NAME"
  ## AJUSTE: mkswap removido daqui.

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    local p_data
    p_data=$(part_suffix "$DATA_DISK")
    local data_partition="${DATA_DISK}${p_data}1"
    info "Configurando criptografia LUKS no disco de dados..."
    dd if=/dev/urandom of=/tmp/hd_keyfile bs=64 count=1
    chmod 600 /tmp/hd_keyfile
    cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
      --label "cryptdata" --key-file /tmp/hd_keyfile --batch-mode "$data_partition"
    info "Formatando partição de dados (ext4)..."
    cryptsetup open "$data_partition" cryptdata --key-file /tmp/hd_keyfile
    mkfs.ext4 /dev/mapper/cryptdata
    cryptsetup close cryptdata
  fi
}

mount_filesystems_for_install() {
  info "Montando sistemas de arquivos..."
  local p
  p=$(part_suffix "$TARGET_DISK")
  mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt
  mkdir -p /mnt/home
  mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home
  ## AJUSTE: swapon removido daqui. O swap será configurado dentro do chroot.
  mkdir -p /mnt/boot
  mount "${TARGET_DISK}${p}2" /mnt/boot
  if [[ "$BOOT_MODE" == "UEFI" ]]; then
    mkdir -p /mnt/boot/efi
    mount "${TARGET_DISK}${p}1" /mnt/boot/efi
  fi
  [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]] && mkdir -p /mnt/data
  info "Sistemas de arquivos montados com sucesso."
}

build_package_list() {
  ## MELHORIA: Adiciona pacotes de kernel, zram, usbguard e memwiper.
  local base_pkgs="base base-devel ${KERNEL_PACKAGE} ${KERNEL_PACKAGE}-headers linux-firmware lvm2 grub sudo nano networkmanager openssl ufw curl git"
  [[ "$BOOT_MODE" == "UEFI" ]] && base_pkgs+=" efibootmgr"

  local extra_pkgs=""
  if [[ -n "$EXTRA_PKGS_ENV" ]]; then
    info "Usando lista de pacotes da variável de ambiente EXTRA_PKGS_ENV."
    extra_pkgs="$EXTRA_PKGS_ENV"
  elif [[ -f "$EXTRA_PKGS_FILE" ]]; then
    info "Lendo lista de pacotes de $EXTRA_PKGS_FILE."
    extra_pkgs=$(cat "$EXTRA_PKGS_FILE" | grep -v '^#' | tr '\n' ' ')
  fi

  local security_pkgs="mokutil sbctl memwiper"
  [[ "$ENABLE_USBGUARD" -eq 1 ]] && security_pkgs+=" usbguard"
  
  local perf_pkgs=""
  [[ "$ENABLE_ZRAM" -eq 1 ]] && perf_pkgs+=" zram-generator"
    
  echo "$base_pkgs $DESKTOP_ENVIRONMENT_PACKAGES $security_pkgs $perf_pkgs $extra_pkgs"
}

# ... (install_base_system e prepare_for_chroot permanecem os mesmos) ...

configure_system_chroot() {
  info "Criando script de configuração para o chroot..."
  cat >/mnt/chroot-config.sh <<CHROOT_SCRIPT
#!/usr/bin/env bash
set -euo pipefail

# --- Variáveis e Funções ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info_chroot() { printf "${BLUE}[CHROOT]${NC} %s\n" "\$*"; }
warn_chroot() { printf "${YELLOW}[CHROOT-AVISO]${NC} %s\n" "\$*"; }

# Recebe argumentos do script principal
HOSTNAME="\$1"
TIMEZONE="\$2"
LOCALE="\$3"
KEYMAP="\$4"
USERNAME="\$5"
USER_SHELL="\$6"
VG_NAME="\$7"
BOOT_MODE="\$8"
TARGET_DISK="\$9"
KERNEL_PACKAGE="${KERNEL_PACKAGE}"
ENABLE_ZRAM="${ENABLE_ZRAM}"
SWAP_FILE_SIZE_GB="${SWAP_FILE_SIZE_GB}"
ENABLE_USBGUARD="${ENABLE_USBGUARD}"

# --- Configuração Básica ---
info_chroot "Configurando fuso horário, locale e teclado..."
ln -sf "/usr/share/zoneinfo/\$TIMEZONE" /etc/localtime
hwclock --systohc
sed -i "s/^#\$LOCALE/\$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=\$LOCALE" > /etc/locale.conf
echo "KEYMAP=\$KEYMAP" > /etc/vconsole.conf
echo "\$HOSTNAME" > /etc/hostname
echo "127.0.0.1	localhost" >> /etc/hosts
echo "::1		localhost" >> /etc/hosts
echo "127.0.1.1	\$HOSTNAME.localdomain \$HOSTNAME" >> /etc/hosts

# --- Usuários e Senhas ---
info_chroot "Configurando senhas de root e usuário..."
echo "root:\$(cat /root/.pwroot)" | chpasswd
useradd -m -s "\$USER_SHELL" -G wheel "\$USERNAME"
echo "\$USERNAME:\$(cat /root/.pwuser)" | chpasswd
rm /root/.pwroot /root/.pwuser
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers
## MELHORIA: Log de comandos executados com sudo para auditoria.
echo "Defaults log_input, log_output" >> /etc/sudoers

# --- Bootloader (mkinitcpio e GRUB) ---
info_chroot "Configurando mkinitcpio e GRUB..."
## AJUSTE: 'kms' movido para antes de 'filesystems' para um boot gráfico mais rápido.
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect kms modconf keyboard keymap consolefont block encrypt lvm2 filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P "\$KERNEL_PACKAGE"

LUKS_UUID=\$(cat /root/luks_uuid)
ROOT_DEVICE_PATH="/dev/\$VG_NAME/lv_root"
## MELHORIA: Parâmetros de segurança adicionados ao kernel.
## lockdown=confidentiality: Bloqueia acesso de userland à memória do kernel.
## ibt=off: Desativa Indirect Branch Tracking, necessário para compatibilidade com alguns bootloaders/cenários.
## slab_nomerge: Aumenta a segurança contra heap overflows.
GRUB_SECURITY_PARAMS="lockdown=confidentiality ibt=off slab_nomerge"
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet \$GRUB_SECURITY_PARAMS\"|" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=\$LUKS_UUID:cryptroot root=\$ROOT_DEVICE_PATH\"|" /etc/default/grub
sed -i 's/^#GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub
## MELHORIA: Oculta o menu do GRUB para dificultar a manipulação do boot.
echo "GRUB_TIMEOUT=0" >> /etc/default/grub
echo "GRUB_TIMEOUT_STYLE=hidden" >> /etc/default/grub

info_chroot "Instalando GRUB para modo \$BOOT_MODE..."
if [[ "\$BOOT_MODE" == "UEFI" ]]; then
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable
else # Legacy
  grub-install --target=i386-pc "\$TARGET_DISK"
fi
grub-mkconfig -o /boot/grub/grub.cfg

# --- Hardening do Sistema ---
info_chroot "Aplicando configurações de hardening..."
# sysctl
cat > /etc/sysctl.d/99-hardening.conf << EOF
# IPV4 networking hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
# Hide kernel pointers
kernel.kptr_restrict = 1
# Desativar BPF JIT para usuários não privilegiados
kernel.unprivileged_bpf_disabled = 1
EOF
# Kernel Modules
cat > /etc/modprobe.d/security.conf << EOF
# Disable uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
# Disable uncommon network protocols
install dccp /bin/true
install sctp /bin/true
EOF
# Permissões
chmod 600 /boot/grub/grub.cfg
chmod 700 /root

## MELHORIA: Configura o escalonador de I/O para SSDs.
info_chroot "Configurando escalonador de I/O para SSDs..."
cat > /etc/udev/rules.d/60-ioschedulers.rules << EOF
# Set scheduler for non-rotating storage
ACTION=="add|change", KERNEL=="sd[a-z]|nvme[0-n]1", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
EOF

## MELHORIA: Configura swap (ZRAM ou arquivo).
if [[ "\$ENABLE_ZRAM" -eq 1 ]]; then
    info_chroot "Configurando ZRAM..."
    cat > /etc/systemd/zram-generator.conf << EOF
[zram0]
zram-size = ram / 2
compression-algorithm = zstd
EOF
else
    info_chroot "Configurando arquivo de swap..."
    dd if=/dev/zero of=/swapfile bs=1G count=\$SWAP_FILE_SIZE_GB status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    echo '/swapfile none swap defaults 0 0' >> /etc/fstab
fi

# --- Firewall (UFW) ---
info_chroot "Configurando firewall (UFW)..."
ufw default deny incoming
ufw default allow outgoing
ufw enable

# --- Secure Boot ---
# ... (Seção Secure Boot permanece a mesma) ...

# --- Autodestruição e Atalhos ---
# ... (Seção Autodestruição permanece a mesma) ...

# --- Verificação de Integridade de Pacotes ---
# ... (Seção de Verificação de Integridade permanece a mesma) ...

# --- Limpeza Final ---
info_chroot "Limpando arquivos temporários do chroot..."
rm -f /root/luks_uuid /root/data_uuid /tmp/pacman_check.log 2>/dev/null || true

# --- Habilitar Serviços ---
info_chroot "Habilitando serviços do sistema..."
systemctl enable NetworkManager.service
systemctl enable fstrim.timer
systemctl enable ufw.service

## MELHORIA: Habilita serviço de limpeza de memória e USBGuard.
info_chroot "Configurando serviços de segurança adicionais..."
cat > /etc/systemd/system/secure-wipe-memory.service << WIPE_SERVICE
[Unit]
Description=Wipe RAM to mitigate cold boot attacks
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target kexec.target

[Service]
Type=oneshot
ExecStart=/usr/bin/memwiper -s
StandardInput=null
StandardOutput=null
StandardError=null

[Install]
WantedBy=shutdown.target reboot.target halt.target kexec.target
WIPE_SERVICE
systemctl enable secure-wipe-memory.service

if [[ "\$ENABLE_USBGUARD" -eq 1 ]]; then
    info_chroot "Habilitando USBGuard..."
    # Gera um conjunto de regras inicial permitindo os dispositivos atualmente conectados.
    usbguard generate-policy > /etc/usbguard/rules.conf
    chmod 600 /etc/usbguard/rules.conf
    chown root:root /etc/usbguard/rules.conf
    systemctl enable usbguard.service
    warn_chroot "USBGuard foi habilitado. Dispositivos USB novos serão bloqueados por padrão."
    warn_chroot "Para autorizar um novo dispositivo, use 'sudo usbguard allow-device <id>'."
fi

info_chroot "Configuração do chroot concluída."
CHROOT_SCRIPT

  chmod +x /mnt/chroot-config.sh
  info "Executando script de configuração dentro do chroot..."
  arch-chroot /mnt /chroot-config.sh \
    "$HOSTNAME" "$TIMEZONE" "$LOCALE" "$KEYMAP" "$USERNAME" \
    "$USER_SHELL" "$VG_NAME" "$BOOT_MODE" "$TARGET_DISK"
  rm /mnt/chroot-config.sh
}

# ... (As funções install_helper_scripts, sanitize_log, final_cleanup, confirm_continue e main permanecem as mesmas) ...
# ... (Cole aqui as funções inalteradas do seu script original para manter a completude)

# --- Função main para executar o script ---
main() {
  if [[ $# -gt 0 ]] && [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
  fi

  confirm_continue
  validate_environment
  collect_passwords_interactive
  setup_network_and_keys
  sanitize_devices
  partition_devices
  setup_encryption_and_lvm
  mount_filesystems_for_install
  install_base_system
  prepare_for_chroot
  configure_system_chroot
  install_helper_scripts
  sanitize_log
  final_cleanup

  echo
  echo "=================================================="
  echo -e "${GREEN}🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! 🎉${NC}"
  echo "=================================================="
  echo -e "  • Hostname:      ${GREEN}$HOSTNAME${NC}"
  echo -e "  • Usuário:       ${GREEN}$USERNAME${NC}"
  echo -e "  • Kernel:        ${GREEN}$KERNEL_PACKAGE${NC}"
  echo -e "  • Modo de Boot:  ${GREEN}$BOOT_MODE${NC}"
  echo ""
  echo -e "${YELLOW}📋 NOTAS E COMANDOS PÓS-BOOT:${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "  • Desbloquear HD dados: ${BLUE}sudo unlock-data${NC}"
  fi
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo -e "  • Auto-destruição (Terminal): ${RED}sudo crypto-destroy${NC}"
    echo -e "  • Auto-destruição (Atalho):   ${RED}Ctrl+Alt+Shift+F12${NC}"
  fi
  if [[ "$ENABLE_USBGUARD" -eq 1 ]]; then
      echo -e "  • ${YELLOW}USBGuard está ativo. Para autorizar um novo dispositivo USB, conecte-o e execute:${NC}"
      echo -e "    ${BLUE}sudo usbguard list-devices${NC} (para ver o ID)"
      echo -e "    ${BLUE}sudo usbguard allow-device <ID>${NC}"
  fi
  echo ""
  echo -e "${GREEN}✅ Sistema pronto para reinicialização!${NC}"
  echo -e "Execute: ${BLUE}reboot${NC}"
  echo
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
