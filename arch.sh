#!/usr/bin/env bash
#
# instalador-arch-corrigido-progreso.sh
# Versão revisada do instalador Arch (para rodar no Arch Live).
# Inclui helper de auto-destruição com estimador de progresso/ETA.
#
set -euo pipefail
IFS=$'\n\t'

# -------------------- OPÇÕES --------------------
# Defina SHOW_PASSWORDS=1 para visualizar senhas ao digitar (útil para confirmar)
# ATENÇÃO: quando SHOW_PASSWORDS=1 o script evita gravar log em /var/log
SHOW_PASSWORDS="${SHOW_PASSWORDS:-0}"

# Ajuste os discos aqui (ou exporte antes de rodar)
TARGET_DISK="${TARGET_DISK:-/dev/sda}"
DATA_DISK="${DATA_DISK:-/dev/sdb}"

EFI_SIZE_MIB=512
BOOT_SIZE_MIB=1024
SWAP_SIZE_GB=4

ENABLE_DUAL_ENCRYPTION=1
ENABLE_AUTO_DESTRUCTION=1

HOSTNAME="arch-secure"
TIMEZONE="America/Sao_Paulo"
LOCALE="pt_BR.UTF-8"
KEYMAP="br-abnt2"
USERNAME="operador"
USER_SHELL="/bin/bash"

LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512
LUKS_KDF="argon2id"
LUKS_PBKDF_MEM=65536
LUKS_ITER_TIME=2000
PBKDF_PARALLEL=2

VG_NAME="vg_system"
LV_ROOT_NAME="lv_root"
LV_SWAP_NAME="lv_swap"
LV_HOME_NAME="lv_home"
LV_ROOT_SIZE="30G"

# Senhas podem ser passadas por variável de ambiente para automação
LUKS_PASS="${LUKS_PASS:-}"
DESTRUCTION_PASS="${DESTRUCTION_PASS:-}"
ROOT_PASS="${ROOT_PASS:-}"
USER_PASS="${USER_PASS:-}"
PIN_DATA="${PIN_DATA:-}"

# -------------------- Logging seguro --------------------
if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
  LOGFILE="/dev/null"
else
  LOGFILE="/var/log/install-secure-arch.log"
fi

if [[ "$LOGFILE" != "/dev/null" ]]; then
  touch "$LOGFILE"
  chmod 600 "$LOGFILE"
fi
exec > >(tee -a "$LOGFILE") 2>&1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info(){ printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn(){ printf "${YELLOW}[AVISO]${NC} %s\n" "$*"; }
err(){ printf "${RED}[ERRO]${NC} %s\n" "$*"; }
fatal(){ err "$*"; exit 1; }
require_root(){ (( EUID == 0 )) || fatal "Execute o script como root."; }

part_suffix(){ local disk="$1"; [[ "$disk" =~ nvme|mmcblk ]] && echo "p" || echo ""; }

check_memory_for_pbkdf() {
  local mem_kb mem_gb
  mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  mem_gb=$((mem_kb / 1024 / 1024))
  if [[ $mem_gb -lt 2 ]]; then
    warn "Sistema com pouca RAM (${mem_gb}GB). Parâmetros PBKDF podem ser muito agressivos."
  fi
}

# -------------------- Segurança (limpeza) --------------------
secure_cleanup() {
  unset LUKS_PASS DESTRUCTION_PASS ROOT_PASS USER_PASS PIN_DATA || true
  for f in /tmp/hd_keyfile /tmp/destruction_key /tmp/destruction_data_key /tmp/.pwroot /tmp/.pwuser /tmp/destruction_hash; do
    [[ -f "$f" ]] && shred -u -n 3 "$f" 2>/dev/null || rm -f "$f" 2>/dev/null || true
  done
  unset HISTFILE 2>/dev/null || true
  history -c 2>/dev/null || true
}
trap secure_cleanup EXIT INT TERM

mask_secret() {
  # Se SHOW_PASSWORDS=1 -> mostra texto claro; caso contrário, mascara
  local s="$1"
  if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
    echo "$s"
    return
  fi
  local n=${#s}
  if (( n == 0 )); then
    echo "[0 caracteres] [vazio]"
  else
    local stars=""
    for ((i=0;i< n && i<6;i++)); do stars+="*"; done
    echo "[${n} caracteres] ${stars}"
  fi
}

display_passwords_for_confirmation() {
  echo
  echo "=================================================="
  echo "${GREEN}CONFIRMAÇÃO DE SENHAS:${NC}"
  echo "=================================================="
  echo "Senha LUKS (principal): $(mask_secret "$LUKS_PASS")"
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo "Senha AUTO-DESTRUIÇÃO: $(mask_secret "$DESTRUCTION_PASS")"
  fi
  echo "Senha root: $(mask_secret "$ROOT_PASS")"
  echo "Senha usuário ($USERNAME): $(mask_secret "$USER_PASS")"
  echo "PIN HD dados: $(mask_secret "$PIN_DATA")"
  echo "=================================================="
  echo
  if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
    read -rp "As senhas exibidas estão corretas? (s/N): " confirm
  else
    read -rp "${YELLOW}As senhas estão corretas? (s/N): ${NC}" confirm
  fi
  [[ "$confirm" == "s" || "$confirm" == "S" ]]
}

collect_passwords_interactive() {
  info "Coleta de senhas (será feita de forma interativa)."
  # Se vierem por env e já preenchidas, pedir confirmação
  if [[ -n "$LUKS_PASS" && -n "$ROOT_PASS" && -n "$USER_PASS" && ( "$ENABLE_DUAL_ENCRYPTION" -eq 0 || -n "$PIN_DATA" ) ]]; then
    if display_passwords_for_confirmation; then
      info "Senhas recebidas via variáveis de ambiente e confirmadas."
      return 0
    fi
  fi

  while true; do
    echo
    if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
      read -rp "Senha LUKS (principal): " LUKS_PASS
      read -rp "Confirme LUKS: " tmp
    else
      read -rsp "Senha LUKS (principal): " LUKS_PASS; echo
      read -rsp "Confirme LUKS: " tmp; echo
    fi
    [[ "$LUKS_PASS" == "$tmp" && -n "$LUKS_PASS" ]] || { warn "LUKS: senhas não coincidem ou vazia"; continue; }

    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
        read -rp "Senha AUTO-DESTRUIÇÃO (mínimo 8 caracteres): " DESTRUCTION_PASS
        read -rp "Confirme destruição: " tmp
      else
        read -rsp "Senha AUTO-DESTRUIÇÃO (mínimo 8 caracteres): " DESTRUCTION_PASS; echo
        read -rsp "Confirme destruição: " tmp; echo
      fi
      [[ "$DESTRUCTION_PASS" == "$tmp" && ${#DESTRUCTION_PASS} -ge 8 ]] || { warn "Destruição: senhas não coincidem ou muito curta"; continue; }
    fi

    if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
      read -rp "Senha root: " ROOT_PASS
      read -rp "Confirme root: " tmp
    else
      read -rsp "Senha root: " ROOT_PASS; echo
      read -rsp "Confirme root: " tmp; echo
    fi
    [[ "$ROOT_PASS" == "$tmp" && -n "$ROOT_PASS" ]] || { warn "Root: senhas não coincidem ou vazia"; continue; }

    if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
      read -rp "Senha do usuário $USERNAME: " USER_PASS
      read -rp "Confirme senha do usuário: " tmp
    else
      read -rsp "Senha do usuário $USERNAME: " USER_PASS; echo
      read -rsp "Confirme senha do usuário: " tmp; echo
    fi
    [[ "$USER_PASS" == "$tmp" && -n "$USER_PASS" ]] || { warn "Usuário: senhas não coincidem ou vazia"; continue; }

    if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
      if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
        read -rp "PIN para desbloquear HD (dados): " PIN_DATA
        read -rp "Confirme PIN: " tmp
      else
        read -rsp "PIN para desbloquear HD (dados): " PIN_DATA; echo
        read -rsp "Confirme PIN: " tmp; echo
      fi
      [[ "$PIN_DATA" == "$tmp" && -n "$PIN_DATA" ]] || { warn "PIN: não coincidem ou vazio"; continue; }
    fi

    if display_passwords_for_confirmation; then
      break
    fi

    LUKS_PASS=""; DESTRUCTION_PASS=""; ROOT_PASS=""; USER_PASS=""; PIN_DATA=""
  done

  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    printf '%s' "$DESTRUCTION_PASS" | sha256sum | awk '{print $1}' > /tmp/destruction_hash
    chmod 600 /tmp/destruction_hash
  fi

  info "Senhas coletadas e confirmadas."
}

check_required_tools() {
  local missing_tools=()
  local musts=(cryptsetup sgdisk mkfs.ext4 mkfs.fat pacstrap genfstab arch-chroot partprobe wipefs dd pvcreate vgcreate lvcreate mkinitcpio grub-install grub-mkconfig openssl blockdev)
  for tool in "${musts[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    fatal "Ferramentas necessárias não encontradas: ${missing_tools[*]}. Instale-as no ambiente live antes de rodar."
  fi
}

validate_environment() {
  require_root
  info "Validando ambiente..."
  check_required_tools
  check_memory_for_pbkdf
  [[ -d /sys/firmware/efi/efivars ]] || fatal "Sistema não iniciado em modo UEFI."
  [[ -b "$TARGET_DISK" ]] || fatal "TARGET_DISK $TARGET_DISK não encontrado."
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then [[ -b "$DATA_DISK" ]] || fatal "DATA_DISK $DATA_DISK não encontrado."; fi
  loadkeys "$KEYMAP" || warn "Falha ao carregar keymap"
  info "Ambiente validado."
}

setup_network() {
  info "Configurando rede..."
  for ifacepath in /sys/class/net/en* /sys/class/net/eth*; do
    [[ -d "$ifacepath" ]] || continue
    interface=$(basename "$ifacepath")
    if [[ "$interface" != "lo" ]]; then
      ip link set "$interface" up 2>/dev/null || true
      info "Interface $interface ativada"
    fi
  done
  sleep 3
  if command -v dhcpcd >/dev/null 2>&1; then
    timeout 15 dhcpcd --noarp --timeout 10 2>/dev/null || warn "DHCP (dhcpcd) falhou"
  fi
  if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
    info "Conectividade OK"
    timedatectl set-ntp true 2>/dev/null || warn "Falha ao sincronizar relógio"
    return 0
  else
    warn "Sem conectividade. Instalação continuará apenas com pacotes locais."
    return 1
  fi
}

sanitize_devices() {
  warn "Sanitizando dispositivos (desmontando e limpando assinaturas)..."
  umount -R /mnt 2>/dev/null || true
  swapoff -a 2>/dev/null || true

  for device in "$TARGET_DISK" "$DATA_DISK"; do
    [[ -b "$device" ]] || continue
    info "wipefs em $device..."
    wipefs -af "$device" 2>/dev/null || true
  done

  if command -v blkdiscard >/dev/null 2>&1; then
    for device in "$TARGET_DISK" "$DATA_DISK"; do
      [[ -b "$device" ]] || continue
      blkdiscard "$device" 2>/dev/null || warn "blkdiscard falhou em $device"
    done
  else
    warn "blkdiscard indisponível — sobrescrevendo cabeçalhos (10MB)"
    for device in "$TARGET_DISK" "$DATA_DISK"; do
      [[ -b "$device" ]] || continue
      dd if=/dev/zero of="$device" bs=1M count=10 status=none 2>/dev/null || true
    done
  fi
  sync
  partprobe "$TARGET_DISK" 2>/dev/null || true
  partprobe "$DATA_DISK" 2>/dev/null || true
  info "Sanitização concluída."
}

partition_devices() {
  info "Criando tabela GPT e partições."
  sgdisk --zap-all "$TARGET_DISK" || fatal "Falha ao zerar GPT do $TARGET_DISK"
  sgdisk -n 1:2048:+${EFI_SIZE_MIB}MiB -t 1:ef00 -c 1:"EFI System" \
         -n 2:0:+${BOOT_SIZE_MIB}MiB  -t 2:8300  -c 2:"Boot" \
         -n 3:0:0 -t 3:8300 -c 3:"Linux LUKS" \
         "$TARGET_DISK" || fatal "Falha ao criar partições no $TARGET_DISK"

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    sgdisk --zap-all "$DATA_DISK" || fatal "Falha ao zerar GPT do $DATA_DISK"
    sgdisk -n 1:2048:0 -t 1:8300 -c 1:"Data LUKS" "$DATA_DISK" || fatal "Falha ao criar partições no $DATA_DISK"
  fi

  sleep 1
  P_SUFFIX="$(part_suffix "$TARGET_DISK")"
  EFI_PART="${TARGET_DISK}${P_SUFFIX}1"
  BOOT_PART="${TARGET_DISK}${P_SUFFIX}2"
  LUKS_PART="${TARGET_DISK}${P_SUFFIX}3"
  [[ -b "$EFI_PART" && -b "$BOOT_PART" && -b "$LUKS_PART" ]] || fatal "Partições não criadas corretamente."

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_SUFFIX="$(part_suffix "$DATA_DISK")"
    DATA_PART="${DATA_DISK}${DATA_SUFFIX}1"
    [[ -b "$DATA_PART" ]] || fatal "Partição de dados não criada."
  fi

  info "Particionamento OK."
}

setup_encryption_and_lvm() {
  info "Configurando LUKS2 e LVM."
  P_SUFFIX="$(part_suffix "$TARGET_DISK")"
  EFI_PART="${TARGET_DISK}${P_SUFFIX}1"
  BOOT_PART="${TARGET_DISK}${P_SUFFIX}2"
  LUKS_PART="${TARGET_DISK}${P_SUFFIX}3"

  mkfs.ext4 -F -L "BOOT" "$BOOT_PART" || fatal "mkfs /boot falhou"
  mkfs.fat -F32 "$EFI_PART" || fatal "mkfs /efi falhou"

  wipefs -af "$LUKS_PART" 2>/dev/null || true
  dd if=/dev/zero of="$LUKS_PART" bs=1M count=4 status=none 2>/dev/null || true
  sync

  # Formata LUKS lendo a senha via stdin
  info "Formatando LUKS (TARGET_DISK)..."
  if ! printf '%s' "$LUKS_PASS" | cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
       --hash sha512 --pbkdf "$LUKS_KDF" --pbkdf-parallel "$PBKDF_PARALLEL" --pbkdf-memory "$LUKS_PBKDF_MEM" \
       --iter-time "$LUKS_ITER_TIME" --key-file=- "$LUKS_PART" 2>/dev/null; then
    warn "luksFormat falhou com parâmetros principais; tentando parâmetros conservadores..."
    cryptsetup luksFormat --type luks2 "$LUKS_PART" 2>/dev/null || fatal "luksFormat falhou"
  fi

  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    printf '%s' "$DESTRUCTION_PASS" > /tmp/destruction_key
    chmod 600 /tmp/destruction_key
    printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$LUKS_PART" /tmp/destruction_key - 2>/dev/null || warn "luksAddKey (destruição) falhou"
    shred -u /tmp/destruction_key 2>/dev/null || rm -f /tmp/destruction_key
  fi

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_SUFFIX="$(part_suffix "$DATA_DISK")"
    DATA_PART="${DATA_DISK}${DATA_SUFFIX}1"
    wipefs -af "$DATA_PART" 2>/dev/null || true
    dd if=/dev/urandom of=/tmp/hd_keyfile bs=1024 count=4 status=none
    chmod 600 /tmp/hd_keyfile

    cryptsetup luksFormat --type luks2 "$DATA_PART" /tmp/hd_keyfile 2>/dev/null || warn "luksFormat (data) falhou"
    printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" /tmp/hd_keyfile - 2>/dev/null || warn "luksAddKey (data) falhou"

    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      printf '%s' "$DESTRUCTION_PASS" > /tmp/destruction_data_key
      chmod 600 /tmp/destruction_data_key
      printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" /tmp/destruction_data_key - 2>/dev/null || warn "luksAddKey destr (data) falhou"
      shred -u /tmp/destruction_data_key 2>/dev/null || rm -f /tmp/destruction_data_key
    fi
  fi

  # Abre cryptroot
  printf '%s' "$LUKS_PASS" | cryptsetup open --key-file=- "$LUKS_PART" cryptroot || fatal "cryptsetup open cryptroot falhou"
  pvcreate /dev/mapper/cryptroot || fatal "pvcreate falhou"
  vgcreate "$VG_NAME" /dev/mapper/cryptroot || fatal "vgcreate falhou"
  lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME" || fatal "lvcreate root falhou"
  lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME" || fatal "lvcreate swap falhou"
  lvcreate -l 100%FREE -n "$LV_HOME_NAME" "$VG_NAME" || fatal "lvcreate home falhou"

  mkfs.ext4 -F -L "ROOT" "/dev/$VG_NAME/$LV_ROOT_NAME" || fatal "mkfs root falhou"
  mkfs.ext4 -F -L "HOME" "/dev/$VG_NAME/$LV_HOME_NAME" || fatal "mkfs home falhou"
  mkswap -L "SWAP" "/dev/$VG_NAME/$LV_SWAP_NAME" || fatal "mkswap falhou"
  swapon "/dev/$VG_NAME/$LV_SWAP_NAME" || warn "swapon falhou"

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    cryptsetup open "$DATA_PART" cryptdata --key-file /tmp/hd_keyfile || warn "cryptsetup open cryptdata falhou"
    mkfs.ext4 -F -L "DATA" /dev/mapper/cryptdata || warn "mkfs cryptdata falhou"
  fi

  LUKS_UUID=$(blkid -s UUID -o value "$LUKS_PART" || true)
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(blkid -s UUID -o value "$DATA_PART" || true)
  fi

  info "Criptografia e LVM prontos."
}

mount_filesystems_for_install() {
  info "Montando sistemas de arquivos..."
  mkdir -p /mnt
  mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt || fatal "Falha ao montar root"
  mkdir -p /mnt/boot /mnt/boot/efi /mnt/home
  mount "$BOOT_PART" /mnt/boot || fatal "Falha ao montar /boot"
  mount "$EFI_PART" /mnt/boot/efi || fatal "Falha ao montar /boot/efi"
  mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home || fatal "Falha ao montar /home"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    mkdir -p /mnt/home/dados
    mount /dev/mapper/cryptdata /mnt/home/dados || warn "Falha ao montar /home/dados"
  fi
  info "Montagem concluída."
}

install_base_and_prepare() {
  info "Instalando pacotes base"
  base_packages=( base base-devel linux linux-firmware lvm2 cryptsetup reflector nano sudo openssh networkmanager )

  if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
    pacstrap /mnt "${base_packages[@]}" --noconfirm || warn "pacstrap retornou aviso/erro"
  else
    pacstrap /mnt "${base_packages[@]}" --noconfirm || warn "pacstrap sem rede pode falhar se pacotes ausentes"
  fi

  genfstab -U /mnt > /mnt/etc/fstab

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    cat >> /mnt/etc/fstab <<EOF
/dev/mapper/cryptdata /home/dados ext4 defaults,noatime 0 2
EOF
  fi

  echo "$LUKS_UUID" > /mnt/root/luks_uuid
  echo "$TARGET_DISK" > /mnt/root/target_disk
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "$DATA_UUID" > /mnt/root/data_uuid
  fi

  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 && -f /tmp/destruction_hash ]]; then
    cp /tmp/destruction_hash /mnt/etc/secure-destruction.hash
    chmod 600 /mnt/etc/secure-destruction.hash
  fi

  info "Base instalada."
}

prepare_keyfile_encrypted_by_pin() {
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    mkdir -p /mnt/etc/cryptsetup-keys.d
    if [[ -f /tmp/hd_keyfile ]]; then
      if printf '%s' "$PIN_DATA" | openssl enc -aes-256-cbc -pbkdf2 -salt -iter 100000 -pass stdin \
        -in /tmp/hd_keyfile -out /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc 2>/dev/null; then
        chmod 600 /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc || true
        shred -u /tmp/hd_keyfile 2>/dev/null || rm -f /tmp/hd_keyfile
        info "Keyfile protegido por PIN instalado."
      else
        warn "Falha ao encriptar hd_keyfile com PIN"
      fi
    fi
  fi
}

prepare_pw_files_for_chroot() {
  printf 'root:%s\n' "$ROOT_PASS" > /mnt/root/.pwroot
  chmod 600 /mnt/root/.pwroot
  printf '%s:%s\n' "$USERNAME" "$USER_PASS" > /mnt/root/.pwuser
  chmod 600 /mnt/root/.pwuser
  info "Arquivos temporários de senha criados (serão removidos dentro do chroot)."
}

configure_chroot() {
  info "Entrando no chroot para configurações finais..."
  arch-chroot /mnt /usr/bin/env bash <<'CHROOT'
set -euo pipefail
ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
hwclock --systohc
sed -i 's/^#\(pt_BR.UTF-8[[:space:]]\+UTF-8\)/\1/' /etc/locale.gen || true
locale-gen
echo "LANG=pt_BR.UTF-8" > /etc/locale.conf
echo "KEYMAP=br-abnt2" > /etc/vconsole.conf

echo "arch-secure" > /etc/hostname
cat > /etc/hosts <<HOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   arch-secure.localdomain arch-secure
HOSTS

if [[ -f /root/.pwroot ]]; then
  chpasswd < /root/.pwroot || true
  shred -u /root/.pwroot || rm -f /root/.pwroot
fi
if [[ -f /root/.pwuser ]]; then
  useradd -m -G wheel,audio,video,storage -s /bin/bash operador || true
  chpasswd < /root/.pwuser || true
  shred -u /root/.pwuser || rm -f /root/.pwuser
fi

echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/wheel
chmod 440 /etc/sudoers.d/wheel

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true

if grep -q '^HOOKS=' /etc/mkinitcpio.conf; then
  sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf block encrypt lvm2 filesystems keyboard fsck)/' /etc/mkinitcpio.conf || true
else
  echo 'HOOKS=(base udev autodetect modconf block encrypt lvm2 filesystems keyboard fsck)' >> /etc/mkinitcpio.conf
fi
mkinitcpio -P || true

systemctl enable NetworkManager || true
systemctl enable sshd || true

pacman -Sy --noconfirm grub efibootmgr --needed || true

if [[ -f /root/luks_uuid ]]; then
  LUKS_UUID=$(cat /root/luks_uuid)
  sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=${LUKS_UUID}:cryptroot root=/dev/vg_system/lv_root\"|" /etc/default/grub || true
fi

if [[ -f /root/target_disk ]]; then
  TARGET_DISK=$(cat /root/target_disk)
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH "$TARGET_DISK" || true
  grub-mkconfig -o /boot/grub/grub.cfg || true
fi

if [[ -f /etc/secure-destruction.hash ]]; then
  mkdir -p /etc/secure
  mv /etc/secure-destruction.hash /etc/secure/destruction.hash || true
  chmod 600 /etc/secure/destruction.hash || true
fi

rm -f /root/luks_uuid /root/target_disk /root/data_uuid 2>/dev/null || true

if command -v aide >/dev/null 2>&1; then
  aide --init 2>/dev/null || true
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
fi

echo -e "export TMOUT=600\nreadonly TMOUT\nexport HISTFILESIZE=0\nexport HISTSIZE=0" > /etc/profile.d/autologout.sh
chmod 644 /etc/profile.d/autologout.sh
CHROOT
  info "Configuração chroot concluída."
}

install_unlock_and_destroy_helpers() {
  info "Instalando helpers para desbloqueio e destruição."
  mkdir -p /mnt/usr/local/bin
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(cat /mnt/root/data_uuid 2>/dev/null || true)
    cat > /mnt/usr/local/bin/unlock-data.sh <<'UNLOCK'
#!/usr/bin/env bash
set -euo pipefail
read -rsp "Digite o PIN para desbloquear o HD: " pin; echo
ENC="/etc/cryptsetup-keys.d/hd_keyfile.enc"
TMPK="/tmp/hd_keyfile.$$"
if [[ ! -f "$ENC" ]]; then echo "Arquivo encriptado não encontrado: $ENC"; exit 1; fi
printf '%s' "$pin" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass stdin -in "$ENC" -out "$TMPK" 2>/dev/null || {
  echo "PIN incorreto ou falha ao decifrar"; exit 1;
}
chmod 600 "$TMPK"
cryptsetup open "/dev/disk/by-uuid/REPLACE_DATA_UUID" cryptdata --key-file "$TMPK" || {
  shred -u "$TMPK"; exit 1;
}
shred -u "$TMPK" || rm -f "$TMPK"
echo "HD desbloqueado: /dev/mapper/cryptdata"
mount /dev/mapper/cryptdata /home/dados 2>/dev/null || echo "Montagem automática falhou; monte manualmente."
UNLOCK
    # substitui placeholder pela UUID real (se existir)
    if [[ -n "$DATA_UUID" ]]; then
      sed -i "s/REPLACE_DATA_UUID/${DATA_UUID}/g" /mnt/usr/local/bin/unlock-data.sh || true
    fi
    chmod 755 /mnt/usr/local/bin/unlock-data.sh
  fi

  # crypto-destroy com estimador de progresso
  cat > /mnt/usr/local/bin/crypto-destroy <<'DEST'
#!/bin/bash
set -euo pipefail

HASH_FILE="/etc/secure/destruction.hash"
[[ -f "$HASH_FILE" ]] || { echo "ERRO: Arquivo de hash não encontrado"; exit 1; }
read -rsp "Senha de destruição: " pass; echo
input_hash=$(printf '%s' "$pass" | sha256sum | awk '{print $1}')
stored_hash=$(cat "$HASH_FILE")
[[ "$input_hash" == "$stored_hash" ]] || { echo "Senha incorreta"; exit 1; }
echo "Senha válida. Iniciando destruição..."

wipe_with_progress() {
  local dev="$1"
  if [[ ! -b "$dev" ]]; then
    echo "Dispositivo não encontrado: $dev"
    return 1
  fi

  # tenta luksErase se o device for LUKS e o comando disponível
  if command -v cryptsetup >/dev/null 2>&1; then
    echo "Tentando cryptsetup luksErase --batch-mode em $dev (se aplicável)..."
    cryptsetup luksErase --batch-mode "$dev" 2>/dev/null || true
  fi

  # tenta blkdiscard — se funcionar, é instantâneo
  if command -v blkdiscard >/dev/null 2>&1; then
    echo "Usando blkdiscard em $dev..."
    if blkdiscard "$dev" >/dev/null 2>&1; then
      echo "blkdiscard: 100% concluído."
      return 0
    else
      echo "blkdiscard não suportado no dispositivo ou falhou, indo para sobrescrita."
    fi
  fi

  # sobrescrita com progresso estimado
  echo "Obtendo tamanho total de $dev..."
  total_bytes=$(blockdev --getsize64 "$dev" 2>/dev/null || echo 0)
  if [[ "$total_bytes" -le 0 ]]; then
    echo "Falha ao obter tamanho do dispositivo, usando dd simples (sem ETA)..."
    dd if=/dev/urandom of="$dev" bs=1M status=progress || true
    return $?
  fi

  CHUNK=$((4*1024*1024))   # 4 MiB por iteração
  total_mb=$((total_bytes / 1024 / 1024))
  written=0
  i=0
  start_ts=$(date +%s)

  echo "Iniciando sobrescrita de $dev ($total_mb MiB) em blocos de $((CHUNK/1024/1024))MiB..."
  # Loop escrevendo um bloco por vez usando dd com seek
  while (( written < total_bytes )); do
    # write one chunk at position i (seek counts blocos de CHUNK)
    dd if=/dev/urandom of="$dev" bs="$CHUNK" count=1 seek="$i" oflag=direct conv=notrunc status=none 2>/dev/null || true

    written=$(( (i+1) * CHUNK ))
    if (( written > total_bytes )); then
      written=$total_bytes
    fi

    now_ts=$(date +%s)
    elapsed=$(( now_ts - start_ts ))
    if (( elapsed <= 0 )); then elapsed=1; fi
    speed_bps=$(( written / elapsed ))            # bytes por segundo
    remaining=$(( total_bytes - written ))
    if (( speed_bps > 0 )); then
      eta_sec=$(( remaining / speed_bps ))
    else
      eta_sec=$(( remaining / (1024*1024) + 1 ))  # fallback
    fi

    percent=$(( written * 100 / total_bytes ))
    written_mb=$(( written / 1024 / 1024 ))

    printf "\rApagando %s: %3d%% — %d/%d MiB — ETA %02d:%02d " "$dev" "$percent" "$written_mb" "$total_mb" $((eta_sec/60)) $((eta_sec%60))
    i=$((i+1))
  done
  printf "\nApagamento de %s concluído.\n" "$dev"

  sync
  return 0
}

{
  # tenta descobrir partições LUKS ativas
  TARGET_LUKS_PART=$(cryptsetup status cryptroot 2>/dev/null | awk '/device:/ {print $2}' || true)
  if [[ -z "$TARGET_LUKS_PART" ]]; then TARGET_LUKS_PART="/dev/sda3"; fi

  DATA_LUKS_PART=$(cryptsetup status cryptdata 2>/dev/null | awk '/device:/ {print $2}' || true)

  echo "Iniciando rotina de destruição segura..."
  # destrói dados do disco do sistema
  if [[ -n "$TARGET_LUKS_PART" ]]; then
    echo "Destruindo $TARGET_LUKS_PART ..."
    wipe_with_progress "$TARGET_LUKS_PART"
  fi

  # destrói disco de dados se existir
  if [[ -n "$DATA_LUKS_PART" ]]; then
    echo "Destruindo $DATA_LUKS_PART ..."
    wipe_with_progress "$DATA_LUKS_PART"
  fi

  # se os caminhos forem dispositivos brutos (fallback), também tentar sobrescrever
  if [[ -b "/dev/sda" && "$TARGET_LUKS_PART" != "/dev/sda" ]]; then
    echo "Também sobrescrevendo /dev/sda por precaução..."
    wipe_with_progress "/dev/sda"
  fi
  if [[ -b "/dev/sdb" && "$DATA_LUKS_PART" != "/dev/sdb" ]]; then
    echo "Também sobrescrevendo /dev/sdb por precaução..."
    wipe_with_progress "/dev/sdb"
  fi

  echo "Destruição concluída. Sincronizando e desligando..."
  sync
  poweroff -f
} &

echo "Processo de destruição iniciado em background."
DEST
  chmod 700 /mnt/usr/local/bin/crypto-destroy

  info "Helpers instalados."
}

verify_installation() {
  info "Verificando arquivos críticos..."
  [[ -e /mnt/etc/fstab ]] || warn "/etc/fstab ausente"
  [[ -e /mnt/boot/grub/grub.cfg ]] || warn "grub.cfg ausente"
  [[ -e /mnt/usr/local/bin/crypto-destroy ]] || warn "crypto-destroy ausente"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    [[ -e /mnt/usr/local/bin/unlock-data.sh ]] || warn "unlock-data.sh ausente"
    [[ -e /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc ]] || warn "hd_keyfile.enc ausente"
  fi
  info "Verificação concluída."
}

final_cleanup() {
  info "Limpeza final e desmontagem."
  rm -f /tmp/destruction_hash 2>/dev/null || true
  umount -R /mnt 2>/dev/null || true
  cryptsetup luksClose cryptdata 2>/dev/null || true || true
  cryptsetup luksClose cryptroot 2>/dev/null || true || true
  vgchange -an "$VG_NAME" 2>/dev/null || true
  swapoff -a 2>/dev/null || true
  sync
  unset HISTFILE 2>/dev/null || true
  history -c 2>/dev/null || true
  info "Limpeza final concluída."
}

confirm_continue() {
  echo
  warn "!!! Este script é destrutivo e apagará dados nos dispositivos configurados !!!"
  read -rp "Se você entendeu e deseja prosseguir digite 'CONFIRMO': " c
  [[ "$c" == "CONFIRMO" ]] || fatal "Abortado pelo usuário."
}

main() {
  require_root
  confirm_continue
  validate_environment
  collect_passwords_interactive
  HAS_INTERNET=false
  if setup_network; then
    HAS_INTERNET=true
  fi
  sanitize_devices
  partition_devices
  setup_encryption_and_lvm
  mount_filesystems_for_install
  install_base_and_prepare
  prepare_keyfile_encrypted_by_pin
  prepare_pw_files_for_chroot
  configure_chroot
  install_unlock_and_destroy_helpers
  verify_installation
  final_cleanup

  echo
  echo "=================================================="
  echo "${GREEN}INSTALAÇÃO CONCLUÍDA${NC}"
  echo "=================================================="
  echo "  - Hostname: ${HOSTNAME}"
  echo "  - Usuário: ${USERNAME}"
  echo "  - Disco sistema: ${TARGET_DISK} (LUKS2 + LVM)"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "  - Disco dados: ${DATA_DISK} (LUKS2 + keyfile protegido por PIN)"
  fi
  echo "  - Conectividade: $([ "$HAS_INTERNET" = true ] && echo "OK" || echo "SEM INTERNET")"
  echo ""
  echo "${YELLOW}COMANDOS PÓS-BOOT:${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "  - Desbloquear HD dados: sudo /usr/local/bin/unlock-data.sh"
  fi
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo "  - Auto-destruição: sudo /usr/local/bin/crypto-destroy"
  fi
  echo ""
  info "Sistema pronto para reinicialização."
  info "Execute: reboot"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
