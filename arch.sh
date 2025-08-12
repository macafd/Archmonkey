#!/usr/bin/env bash
#
# instalador-arch-corrigido-progreso.sh
# Versão corrigida do instalador Arch Linux com melhorias de segurança e robustez
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
    # Reduz parâmetros para sistemas com pouca memória
    LUKS_PBKDF_MEM=32768
    LUKS_ITER_TIME=1000
  fi
}

# -------------------- Segurança (limpeza) --------------------
secure_cleanup() {
  unset LUKS_PASS DESTRUCTION_PASS ROOT_PASS USER_PASS PIN_DATA || true
  for f in /tmp/hd_keyfile /tmp/destruction_key /tmp/destruction_data_key /tmp/.pwroot /tmp/.pwuser /tmp/destruction_hash; do
    [[ -f "$f" ]] && { shred -vfz -n 3 "$f" 2>/dev/null || rm -f "$f" 2>/dev/null; } || true
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
    for ((i=0;i< n && i<16;i++)); do stars+="*"; done
    # CORREÇÃO: Exibia variáveis incorretas
    echo "[$n caracteres] $stars"
  fi
}

display_passwords_for_confirmation() {
  echo
  echo "=================================================="
  # CORREÇÃO: Texto não era uma variável
  echo -e "${YELLOW}CONFIRMAÇÃO DE SENHAS:${NC}"
  echo "=================================================="
  echo "Senha LUKS (principal): $(mask_secret "$LUKS_PASS")"
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo "Senha AUTO-DESTRUIÇÃO: $(mask_secret "$DESTRUCTION_PASS")"
  fi
  echo "Senha root: $(mask_secret "$ROOT_PASS")"
  echo "Senha usuário ($USERNAME): $(mask_secret "$USER_PASS")"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "PIN HD dados: $(mask_secret "$PIN_DATA")"
  fi
  echo "=================================================="
  echo
  if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
    read -rp "As senhas exibidas estão corretas? (s/N): " confirm
  else
    # CORREÇÃO: Texto não era uma variável
    read -rp "As senhas estão corretas? (s/N): " confirm
  fi
  [[ "$confirm" == "s" || "$confirm" == "S" ]]
}

validate_password_strength() {
  # CORREÇÃO: Requisito de força da senha removido conforme solicitado pelo usuário.
  # A função original verificava o comprimento e senhas comuns.
  return 0
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
    if [[ "$LUKS_PASS" != "$tmp" ]]; then
      warn "LUKS: senhas não coincidem"
      continue
    fi
    if ! validate_password_strength "$LUKS_PASS" "Senha LUKS"; then
      continue
    fi

    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
        read -rp "Senha AUTO-DESTRUIÇÃO: " DESTRUCTION_PASS
        read -rp "Confirme destruição: " tmp
      else
        read -rsp "Senha AUTO-DESTRUIÇÃO: " DESTRUCTION_PASS; echo
        read -rsp "Confirme destruição: " tmp; echo
      fi
      if [[ "$DESTRUCTION_PASS" != "$tmp" ]]; then
        warn "Destruição: senhas não coincidem"
        continue
      fi
      # CORREÇÃO: Requisito de tamanho mínimo removido
      if [[ "$DESTRUCTION_PASS" == "$LUKS_PASS" ]]; then
        warn "Senha de destruição deve ser diferente da senha LUKS"
        continue
      fi
    fi

    if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
      read -rp "Senha root: " ROOT_PASS
      read -rp "Confirme root: " tmp
    else
      read -rsp "Senha root: " ROOT_PASS; echo
      read -rsp "Confirme root: " tmp; echo
    fi
    if [[ "$ROOT_PASS" != "$tmp" ]]; then
      warn "Root: senhas não coincidem"
      continue
    fi
    if ! validate_password_strength "$ROOT_PASS" "Senha root"; then
      continue
    fi

    if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
      read -rp "Senha do usuário $USERNAME: " USER_PASS
      read -rp "Confirme senha do usuário: " tmp
    else
      read -rsp "Senha do usuário $USERNAME: " USER_PASS; echo
      read -rsp "Confirme senha do usuário: " tmp; echo
    fi
    if [[ "$USER_PASS" != "$tmp" ]]; then
      warn "Usuário: senhas não coincidem"
      continue
    fi
    if ! validate_password_strength "$USER_PASS" "Senha do usuário"; then
      continue
    fi

    if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
      if [[ "$SHOW_PASSWORDS" -eq 1 ]]; then
        read -rp "PIN para desbloquear HD (dados): " PIN_DATA
        read -rp "Confirme PIN: " tmp
      else
        read -rsp "PIN para desbloquear HD (dados): " PIN_DATA; echo
        read -rsp "Confirme PIN: " tmp; echo
      fi
      if [[ "$PIN_DATA" != "$tmp" ]]; then
        warn "PIN: não coincidem"
        continue
      fi
      # CORREÇÃO: Requisito de tamanho mínimo removido
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
  local musts=(cryptsetup sgdisk mkfs.ext4 mkfs.fat pacstrap genfstab arch-chroot partprobe wipefs dd pvcreate vgcreate lvcreate mkinitcpio grub-install grub-mkconfig openssl blockdev blkid)
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
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    [[ -b "$DATA_DISK" ]] || fatal "DATA_DISK $DATA_DISK não encontrado."
    [[ "$TARGET_DISK" != "$DATA_DISK" ]] || fatal "TARGET_DISK e DATA_DISK não podem ser o mesmo dispositivo."
  fi
  
  # CORREÇÃO: Lógica de desmontagem mais robusta
  info "Verificando e desmontando partições existentes nos discos alvo..."
  local disks_to_check=("$TARGET_DISK")
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    disks_to_check+=("$DATA_DISK")
  fi

  for disk in "${disks_to_check[@]}"; do
    if mount | grep -q "$disk"; then
      warn "Disco $disk ou suas partições estão montados. Tentando desmontar..."
      # Desmonta na ordem inversa para evitar conflitos (ex: /mnt/boot antes de /mnt)
      grep "$disk" /proc/mounts | cut -d' ' -f2 | sort -r | xargs -r umount -f -l
    fi
  done
}

setup_network() {
  info "Verificando conexão com a internet..."
  if ping -c 1 archlinux.org &>/dev/null; then
    info "✓ Conexão com a internet ativa."
    info "Sincronizando relógio do sistema..."
    timedatectl set-ntp true
    return 0
else
    warn "Sem conexão com a internet. A instalação continuará offline, mas pacstrap falhará se os pacotes não estiverem em cache."
    return 1
  fi
}

sanitize_devices() {
  info "Limpando e zerando tabelas de partição dos discos..."
  local p
  p=$(part_suffix "$TARGET_DISK")
  
  # Desativa LVM e LUKS que possam estar ativos
  vgchange -an >/dev/null 2>&1 || true
  cryptsetup luksClose /dev/mapper/* >/dev/null 2>&1 || true

  wipefs -a "$TARGET_DISK"
  sgdisk --zap-all "$TARGET_DISK"
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    wipefs -a "$DATA_DISK"
    sgdisk --zap-all "$DATA_DISK"
  fi
  
  partprobe "$TARGET_DISK"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    partprobe "$DATA_DISK"
  fi
  sleep 2
}

partition_devices() {
  info "Particionando disco do sistema: $TARGET_DISK"
  local p
  p=$(part_suffix "$TARGET_DISK")
  
  sgdisk -n 1:0:+${EFI_SIZE_MIB}M -t 1:ef00 -c 1:"EFI System Partition" "$TARGET_DISK"
  sgdisk -n 2:0:+${BOOT_SIZE_MIB}M -t 2:8300 -c 2:"Boot Partition" "$TARGET_DISK"
  sgdisk -n 3:0:0 -t 3:8300 -c 3:"LUKS System" "$TARGET_DISK"
  partprobe "$TARGET_DISK"
  
  info "Formatando partições EFI e Boot..."
  mkfs.fat -F32 "${TARGET_DISK}${p}1"
  mkfs.ext4 -F "${TARGET_DISK}${p}2"
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    info "Particionando disco de dados: $DATA_DISK"
    sgdisk -n 1:0:0 -t 1:8300 -c 1:"LUKS Data" "$DATA_DISK"
    partprobe "$DATA_DISK"
  fi
  sleep 2
}

setup_encryption_and_lvm() {
  local p
  p=$(part_suffix "$TARGET_DISK")
  
  info "Configurando criptografia LUKS no disco do sistema..."
  echo -n "$LUKS_PASS" | cryptsetup luksFormat \
    --type luks2 \
    --cipher "$LUKS_CIPHER" \
    --key-size "$LUKS_KEY_SIZE" \
    --pbkdf "$LUKS_KDF" \
    --pbkdf-memory "$LUKS_PBKDF_MEM" \
    --iter-time "$LUKS_ITER_TIME" \
    --pbkdf-parallel "$PBKDF_PARALLEL" \
    --label "cryptroot" \
    --batch-mode \
    "${TARGET_DISK}${p}3"
  
  info "Desbloqueando partição LUKS do sistema..."
  echo -n "$LUKS_PASS" | cryptsetup open "${TARGET_DISK}${p}3" cryptroot
  
  info "Configurando LVM sobre LUKS..."
  pvcreate /dev/mapper/cryptroot
  vgcreate "$VG_NAME" /dev/mapper/cryptroot
  lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME"
  lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME"
  lvcreate -l '100%FREE' -n "$LV_HOME_NAME" "$VG_NAME"
  
  info "Formatando volumes LVM..."
  mkfs.ext4 "/dev/$VG_NAME/$LV_ROOT_NAME"
  mkfs.ext4 "/dev/$VG_NAME/$LV_HOME_NAME"
  mkswap "/dev/$VG_NAME/$LV_SWAP_NAME"
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    local p_data
    p_data=$(part_suffix "$DATA_DISK")
    
    info "Configurando criptografia LUKS no disco de dados..."
    # Cria um keyfile aleatório
    dd if=/dev/random of=/tmp/hd_keyfile bs=64 count=1
    chmod 600 /tmp/hd_keyfile
    
    # Formata o disco de dados com o keyfile
    cryptsetup luksFormat \
      --type luks2 \
      --cipher "$LUKS_CIPHER" \
      --key-size "$LUKS_KEY_SIZE" \
      --label "cryptdata" \
      --key-file /tmp/hd_keyfile \
      --batch-mode \
      "${DATA_DISK}${p_data}1"
      
    info "Formatando partição de dados (ext4)..."
    echo -n "$LUKS_PASS" | cryptsetup open "${DATA_DISK}${p_data}1" cryptdata --key-file /tmp/hd_keyfile
    mkfs.ext4 /dev/mapper/cryptdata
    cryptsetup close cryptdata
  fi
}

mount_filesystems_for_install() {
  info "Montando sistemas de arquivos..."
  local p
  p=$(part_suffix "$TARGET_DISK")
  
  # CORREÇÃO: A ordem e a criação dos diretórios são cruciais.
  mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt
  
  mkdir -p /mnt/home
  mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home
  
  # CORREÇÃO: Usar swapon para swap, não mount.
  swapon "/dev/$VG_NAME/$LV_SWAP_NAME"
  
  mkdir -p /mnt/boot
  mount "${TARGET_DISK}${p}2" /mnt/boot
  
  # CORREÇÃO: Criar o ponto de montagem EFI antes de montar.
  mkdir -p /mnt/boot/efi
  mount "${TARGET_DISK}${p}1" /mnt/boot/efi
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    # CORREÇÃO: Criar o ponto de montagem de dados.
    mkdir -p /mnt/data
  fi
  
  info "Sistemas de arquivos montados com sucesso."
}

install_base_and_prepare() {
  info "Instalando sistema base (pacstrap)..."
  pacstrap /mnt base base-devel linux linux-firmware lvm2 grub efibootmgr sudo nano networkmanager openssl
  
  info "Gerando fstab..."
  genfstab -U /mnt >> /mnt/etc/fstab
}

prepare_keyfile_encrypted_by_pin() {
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    info "Criptografando keyfile do HD de dados com o PIN fornecido..."
    mkdir -p /mnt/etc/cryptsetup-keys.d
    
    # Criptografa o keyfile usando o PIN
    echo -n "$PIN_DATA" | openssl enc -e -aes-256-cbc -pbkdf2 -iter 100000 \
      -pass stdin \
      -in /tmp/hd_keyfile \
      -out /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc
      
    chmod 600 /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc
    info "Keyfile criptografado e armazenado em /etc/cryptsetup-keys.d/"
  fi
}

prepare_pw_files_for_chroot() {
  info "Preparando arquivos de senha para o chroot..."
  echo -n "$ROOT_PASS" > /tmp/.pwroot
  echo -n "$USER_PASS" > /tmp/.pwuser
  chmod 600 /tmp/.pwroot /tmp/.pwuser
  
  cp /tmp/.pwroot /mnt/root/
  cp /tmp/.pwuser /mnt/root/
  
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    cp /tmp/destruction_hash /mnt/etc/secure-destruction.hash
  fi
}

configure_chroot() {
  info "Configurando o sistema dentro do chroot..."
  local p
  p=$(part_suffix "$TARGET_DISK")
  
  # CORREÇÃO: Obter UUID da partição LUKS para o GRUB
  LUKS_UUID=$(blkid -s UUID -o value "${TARGET_DISK}${p}3")
  echo "$LUKS_UUID" > /mnt/root/luks_uuid
  echo "$TARGET_DISK" > /mnt/root/target_disk
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    local p_data
    p_data=$(part_suffix "$DATA_DISK")
    DATA_UUID=$(blkid -s UUID -o value "${DATA_DISK}${p_data}1")
    echo "$DATA_UUID" > /mnt/root/data_uuid
    echo "$DATA_DISK" > /mnt/root/data_disk
  fi

  arch-chroot /mnt /bin/bash -s -- "$USERNAME" "$USER_SHELL" "$TIMEZONE" "$LOCALE" "$KEYMAP" "$HOSTNAME" "$VG_NAME" "$LV_ROOT_NAME" <<'CHROOT'
set -euo pipefail
USERNAME="$1"
USER_SHELL="$2"
TIMEZONE="$3"
LOCALE="$4"
KEYMAP="$5"
HOSTNAME="$6"
VG_NAME="$7"
LV_ROOT_NAME="$8"

info_chroot(){ printf "${GREEN}[CHROOT]${NC} %s\n" "$*"; }

info_chroot "Configurando fuso horário, locale e teclado..."
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
hwclock --systohc
sed -i "s/^#$LOCALE/$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
echo "KEYMAP=$KEYMAP" > /etc/vconsole.conf
echo "$HOSTNAME" > /etc/hostname

info_chroot "Configurando senhas de root e usuário..."
ROOT_PASS=$(cat /root/.pwroot)
USER_PASS=$(cat /root/.pwuser)
echo "root:$ROOT_PASS" | chpasswd
useradd -m -s "$USER_SHELL" -G wheel "$USERNAME"
echo "$USERNAME:$USER_PASS" | chpasswd
rm /root/.pwroot /root/.pwuser
# Descomenta a linha do wheel no sudoers
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

info_chroot "Configurando mkinitcpio e GRUB..."
# CORREÇÃO CRÍTICA: Adiciona hooks 'encrypt' e 'lvm2' para o boot
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

# CORREÇÃO: Obtém UUID e configura o GRUB corretamente
LUKS_UUID=$(cat /root/luks_uuid)
TARGET_DISK=$(cat /root/target_disk)
ROOT_DEVICE_PATH="/dev/$VG_NAME/$LV_ROOT_NAME"

if [[ -f /etc/default/grub ]]; then
  sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=$LUKS_UUID:cryptroot root=$ROOT_DEVICE_PATH\"|" /etc/default/grub
  sed -i 's/^#GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub
  sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub
fi

info_chroot "Instalando GRUB no disco..."
# CORREÇÃO: Adicionado --removable para criar um bootloader mais robusto e portátil.
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable
grub-mkconfig -o /boot/grub/grub.cfg

# Move arquivo de hash de destruição para local seguro
if [[ -f /etc/secure-destruction.hash ]]; then
  mkdir -p /etc/secure
  mv /etc/secure-destruction.hash /etc/secure/destruction.hash
  chmod 600 /etc/secure/destruction.hash
fi

# Limpeza de arquivos temporários
rm -f /root/luks_uuid /root/target_disk /root/data_uuid /root/data_disk 2>/dev/null || true

# Configurações de segurança adicionais
{
  echo "export TMOUT=600"
  echo "readonly TMOUT"
  echo "export HISTFILESIZE=1000"
  echo "export HISTSIZE=1000"
  echo "export HISTCONTROL=ignoredups:erasedups"
} > /etc/profile.d/security.sh
chmod 644 /etc/profile.d/security.sh

# Habilita NetworkManager
systemctl enable NetworkManager

info_chroot "Configuração do chroot concluída."
CHROOT
  
  info "Configuração chroot concluída."
}

install_unlock_and_destroy_helpers() {
  info "Instalando helpers para desbloqueio e destruição."
  mkdir -p /mnt/usr/local/bin
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(cat /mnt/root/data_uuid 2>/dev/null || echo "")
    cat > /mnt/usr/local/bin/unlock-data.sh <<'UNLOCK'
#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  local tmpfile="$1"
  [[ -f "$tmpfile" ]] && { shred -vfz -n 3 "$tmpfile" 2>/dev/null || rm -f "$tmpfile"; }
}

(( EUID == 0 )) || { echo "Execute como root (sudo)"; exit 1; }

read -rsp "Digite o PIN para desbloquear o HD de dados: " pin; echo

ENC_KEYFILE="/etc/cryptsetup-keys.d/hd_keyfile.enc"
TMP_KEYFILE="/tmp/hd_keyfile.$$"
trap 'cleanup "$TMP_KEYFILE"' EXIT

[[ -f "$ENC_KEYFILE" ]] || { echo "ERRO: Keyfile $ENC_KEYFILE não encontrado."; exit 1; }

if ! printf '%s' "$pin" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass stdin -in "$ENC_KEYFILE" -out "$TMP_KEYFILE"; then
  echo "ERRO: PIN incorreto ou falha ao decifrar."
  exit 1
fi
chmod 600 "$TMP_KEYFILE"

# CORREÇÃO: Usa UUID para encontrar o dispositivo, tornando-o robusto a mudanças de nome.
DATA_UUID="REPLACE_DATA_UUID"
DEVICE="/dev/disk/by-uuid/$DATA_UUID"

[[ -b "$DEVICE" ]] || { echo "ERRO: Dispositivo com UUID $DATA_UUID não encontrado."; exit 1; }

if ! cryptsetup open "$DEVICE" cryptdata --key-file "$TMP_KEYFILE"; then
  echo "ERRO: Falha ao abrir volume LUKS. O keyfile pode estar corrompido."
  exit 1
fi
echo "✓ HD desbloqueado: /dev/mapper/cryptdata"

MOUNT_POINT="/data"
mkdir -p "$MOUNT_POINT"
if mount /dev/mapper/cryptdata "$MOUNT_POINT"; then
  echo "✓ HD montado em $MOUNT_POINT"
else
  echo "⚠ Volume desbloqueado, mas falha na montagem. Tente: mount /dev/mapper/cryptdata $MOUNT_POINT"
fi
UNLOCK

    # CORREÇÃO: Substitui placeholder pela UUID real para robustez.
    sed -i "s/REPLACE_DATA_UUID/$DATA_UUID/g" /mnt/usr/local/bin/unlock-data.sh
    chmod 755 /mnt/usr/local/bin/unlock-data.sh
  fi

  cat > /mnt/usr/local/bin/crypto-destroy <<'DESTROY'
#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
HASH_FILE="/etc/secure/destruction.hash"

echo -e "${YELLOW}⚠ AVISO: SISTEMA DE AUTO-DESTRUIÇÃO ⚠${NC}"
echo "Este comando irá DESTRUIR PERMANENTEMENTE todos os dados criptografados!"
read -rp "Digite 'DESTRUIR' para confirmar: " confirm
[[ "$confirm" == "DESTRUIR" ]] || { echo "Operação cancelada."; exit 0; }

[[ -f "$HASH_FILE" ]] || { echo -e "${RED}ERRO: Arquivo de hash não encontrado.${NC}"; exit 1; }

read -rsp "Senha de destruição: " pass; echo
input_hash=$(printf '%s' "$pass" | sha256sum | awk '{print $1}')
stored_hash=$(cat "$HASH_FILE")
[[ "$input_hash" == "$stored_hash" ]] || { echo -e "${RED}ERRO: Senha incorreta.${NC}"; exit 1; }

echo -e "${GREEN}✓ Senha válida. Iniciando destruição...${NC}"

wipe_partition() {
  local dev_path="$1"
  local dev_name="$2"
  
  [[ -b "$dev_path" ]] || { echo -e "${YELLOW}⚠ Partição $dev_name ($dev_path) não encontrada. Pulando.${NC}"; return 1; }

  echo -e "${RED}🔥 Destruindo $dev_name ($dev_path)...${NC}"
  
  if cryptsetup isLuks "$dev_path" &>/dev/null; then
    echo "  ├─ Destruindo cabeçalhos LUKS..."
    cryptsetup luksErase --batch-mode "$dev_path" &>/dev/null && echo -e "  ├─ ${GREEN}✓ Cabeçalhos LUKS destruídos${NC}" || echo -e "  ├─ ${YELLOW}⚠ Falha ao destruir cabeçalhos LUKS${NC}"
  fi

  echo "  ├─ Iniciando sobrescrita com dados aleatórios..."
  if dd if=/dev/urandom of="$dev_path" bs=1M status=progress; then
    echo -e "\n  └─ ${GREEN}✓ Sobrescrita concluída${NC}"
  else
    echo -e "\n  └─ ${RED}✗ Erro durante a sobrescrita${NC}"
  fi
  sync
}

main_destruction() {
  echo -e "${RED}🔥 INICIANDO DESTRUIÇÃO TOTAL 🔥${NC}"
  
  # CORREÇÃO: Usa UUIDs para encontrar os dispositivos de forma confiável.
  LUKS_UUID="REPLACE_LUKS_UUID"
  DATA_UUID="REPLACE_DATA_UUID"
  
  local target_part="/dev/disk/by-uuid/$LUKS_UUID"
  local data_part="/dev/disk/by-uuid/$DATA_UUID"
  
  wipe_partition "$target_part" "PARTIÇÃO SISTEMA"
  
  if [[ -n "$DATA_UUID" ]]; then
    wipe_partition "$data_part" "PARTIÇÃO DADOS"
  fi

  echo -e "${GREEN}✓ DESTRUIÇÃO CONCLUÍDA.${NC}"
  echo -e "${RED}🔥 Sincronizando e desligando sistema em 5 segundos...${NC}"
  sync
  sleep 5
  poweroff -f
}

main_destruction
DESTROY

  # CORREÇÃO: Injeta os UUIDs reais no script de destruição.
  LUKS_UUID=$(cat /mnt/root/luks_uuid 2>/dev/null || echo "")
  DATA_UUID=$(cat /mnt/root/data_uuid 2>/dev/null || echo "")
  sed -i "s/REPLACE_LUKS_UUID/$LUKS_UUID/g" /mnt/usr/local/bin/crypto-destroy
  sed -i "s/REPLACE_DATA_UUID/$DATA_UUID/g" /mnt/usr/local/bin/crypto-destroy
  chmod 700 /mnt/usr/local/bin/crypto-destroy

  info "Helpers instalados com sucesso."
}

verify_installation() {
  info "Verificando arquivos críticos..."
  local errors=0
  
  [[ -s /mnt/etc/fstab ]] || { warn "/etc/fstab ausente ou vazio"; ((errors++)); }
  [[ -s /mnt/boot/grub/grub.cfg ]] || { warn "grub.cfg ausente ou vazio"; ((errors++)); }
  grep -q "encrypt lvm2" /mnt/etc/mkinitcpio.conf || { warn "Hooks 'encrypt lvm2' ausentes em mkinitcpio.conf"; ((errors++)); }
  
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    [[ -f /mnt/usr/local/bin/crypto-destroy ]] || { warn "crypto-destroy ausente"; ((errors++)); }
  fi
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    [[ -f /mnt/usr/local/bin/unlock-data.sh ]] || { warn "unlock-data.sh ausente"; ((errors++)); }
    [[ -f /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc ]] || { warn "hd_keyfile.enc ausente"; ((errors++)); }
  fi
  
  if ! arch-chroot /mnt id "$USERNAME" >/dev/null 2>&1; then
    warn "Usuário $USERNAME não foi criado corretamente"
    ((errors++))
  fi
  
  if ! [[ -b "/dev/$VG_NAME/$LV_ROOT_NAME" ]]; then
    warn "Volume LVM root não encontrado"
    ((errors++))
  fi
  
  if (( errors > 0 )); then
    fatal "Verificação encontrou $errors erro(s). Revise a instalação e os logs."
  else
    info "✓ Verificação concluída sem erros."
  fi
}

final_cleanup() {
  info "Limpeza final e desmontagem."
  
  umount -R /mnt 2>/dev/null || true
  
  cryptsetup luksClose cryptdata 2>/dev/null || true
  cryptsetup luksClose cryptroot 2>/dev/null || true
  
  vgchange -an "$VG_NAME" 2>/dev/null || true
  swapoff -a 2>/dev/null || true
  
  sync
  info "Limpeza final concluída."
}

confirm_continue() {
  echo
  echo "=================================================="
  echo -e "${RED}⚠ AVISO CRÍTICO DE SEGURANÇA ⚠${NC}"
  echo "=================================================="
  echo "Este script irá:"
  echo "  • APAGAR COMPLETAMENTE os discos especificados"
  echo "  • Instalar Arch Linux com criptografia total"
  echo "  • Configurar sistema de auto-destruição (se habilitado)"
  echo ""
  # CORREÇÃO: Uso correto das variáveis de cor
  echo -e "TARGET_DISK: ${GREEN}$TARGET_DISK${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "DATA_DISK:   ${GREEN}$DATA_DISK${NC}"
  fi
  echo ""
  echo -e "${YELLOW}TODOS OS DADOS NESTES DISCOS SERÃO PERDIDOS!${NC}"
  echo "=================================================="
  
  read -rp "Se você entendeu os riscos e deseja prosseguir, digite 'CONFIRMO DESTRUIÇÃO': " confirm
  
  if [[ "$confirm" != "CONFIRMO DESTRUIÇÃO" ]]; then
    echo -e "${RED}Operação cancelada pelo usuário.${NC}"
    exit 0
  fi
  
  echo
  echo "Aguardando 5 segundos para cancelamento (Ctrl+C)..."
  sleep 5
}

main() {
  confirm_continue
  validate_environment
  collect_passwords_interactive
  
  local has_internet=false
  if setup_network; then
    has_internet=true
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
  echo -e "${GREEN}🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! 🎉${NC}"
  echo "=================================================="
  # CORREÇÃO: Uso correto das variáveis
  echo -e "  • Hostname:      ${GREEN}$HOSTNAME${NC}"
  echo -e "  • Usuário:       ${GREEN}$USERNAME${NC}"
  echo -e "  • Disco sistema: ${GREEN}$TARGET_DISK${NC} (LUKS2 + LVM)"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "  • Disco dados:   ${GREEN}$DATA_DISK${NC} (LUKS2 + keyfile protegido por PIN)"
  fi
  echo -e "  • Conectividade: $([ "$has_internet" = true ] && echo -e "${GREEN}ONLINE${NC}" || echo -e "${YELLOW}OFFLINE${NC}")"
  echo ""
  echo -e "${YELLOW}📋 COMANDOS PÓS-BOOT:${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "  • Desbloquear HD dados: ${BLUE}sudo /usr/local/bin/unlock-data.sh${NC}"
  fi
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo -e "  • Auto-destruição:      ${RED}sudo /usr/local/bin/crypto-destroy${NC}"
  fi
  echo ""
  echo -e "${GREEN}✅ Sistema pronto para reinicialização!${NC}"
  echo -e "Execute: ${BLUE}reboot${NC}"
  echo
}

# CORREÇÃO: Condição para execução direta do script
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi