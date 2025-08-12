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
    for ((i=0;i< n && i<6;i++)); do stars+="*"; done
    echo "[${n} caracteres] ${stars}"
  fi
}

display_passwords_for_confirmation() {
  echo
  echo "=================================================="
  echo -e "${GREEN}CONFIRMAÇÃO DE SENHAS:${NC}"
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
    read -rp "${YELLOW}As senhas estão corretas? (s/N): ${NC}" confirm
  fi
  [[ "$confirm" == "s" || "$confirm" == "S" ]]
}

validate_password_strength() {
  local password="$1"
  local password_name="$2"
  local min_length=8
  
  # Verifica comprimento mínimo
  if [[ ${#password} -lt $min_length ]]; then
    warn "$password_name deve ter pelo menos $min_length caracteres"
    return 1
  fi
  
  # Verifica se não é uma senha comum
  local common_passwords=("12345678" "password" "qwerty123" "admin123" "123456789")
  for common in "${common_passwords[@]}"; do
    if [[ "$password" == "$common" ]]; then
      warn "$password_name é muito comum e insegura"
      return 1
    fi
  done
  
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
        read -rp "Senha AUTO-DESTRUIÇÃO (mínimo 12 caracteres): " DESTRUCTION_PASS
        read -rp "Confirme destruição: " tmp
      else
        read -rsp "Senha AUTO-DESTRUIÇÃO (mínimo 12 caracteres): " DESTRUCTION_PASS; echo
        read -rsp "Confirme destruição: " tmp; echo
      fi
      if [[ "$DESTRUCTION_PASS" != "$tmp" ]]; then
        warn "Destruição: senhas não coincidem"
        continue
      fi
      if [[ ${#DESTRUCTION_PASS} -lt 12 ]]; then
        warn "Senha de destruição deve ter pelo menos 12 caracteres"
        continue
      fi
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
      if [[ ${#PIN_DATA} -lt 6 ]]; then
        warn "PIN deve ter pelo menos 6 caracteres"
        continue
      fi
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
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    [[ -b "$DATA_DISK" ]] || fatal "DATA_DISK $DATA_DISK não encontrado."
    [[ "$TARGET_DISK" != "$DATA_DISK" ]] || fatal "TARGET_DISK e DATA_DISK não podem ser o mesmo dispositivo."
  fi
  
  # Verifica se os discos não estão montados
  if mount | grep -q "$TARGET_DISK"; then
    warn "TARGET_DISK $TARGET_DISK ou suas partições estão montados. Tentando desmontar..."
    umount -f "${TARGET_DISK}"* 2>/dev/null || true
  fi
  
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]] && mount | grep -q "$DATA_DISK"; then
    warn "DATA_DISK $DATA_DISK ou suas partições estão montados. Tentando desmontar..."
    umount -f "${DATA_DISK}"* 2>/dev/null || true
  fi
  
  loadkeys "$KEYMAP" || warn "Falha ao carregar keymap"
  info "Ambiente validado."
}

setup_network() {
  info "Configurando rede..."
  
  # Para para serviços de rede conflitantes
  systemctl stop NetworkManager 2>/dev/null || true
  systemctl stop systemd-networkd 2>/dev/null || true
  
  for ifacepath in /sys/class/net/en* /sys/class/net/eth*; do
    [[ -d "$ifacepath" ]] || continue
    interface=$(basename "$ifacepath")
    if [[ "$interface" != "lo" ]]; then
      ip link set "$interface" up 2>/dev/null || true
      info "Interface $interface ativada"
    fi
  done
  sleep 3
  
  # Tenta DHCP com timeout mais conservador
  if command -v dhcpcd >/dev/null 2>&1; then
    timeout 20 dhcpcd --noarp --timeout 15 2>/dev/null || warn "DHCP (dhcpcd) falhou"
  elif command -v dhclient >/dev/null 2>&1; then
    timeout 20 dhclient 2>/dev/null || warn "DHCP (dhclient) falhou"
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

  # Fecha volumes LUKS e LVM existentes
  cryptsetup luksClose cryptdata 2>/dev/null || true
  cryptsetup luksClose cryptroot 2>/dev/null || true
  vgchange -an "$VG_NAME" 2>/dev/null || true

  for device in "$TARGET_DISK" "$DATA_DISK"; do
    [[ -b "$device" ]] || continue
    info "wipefs em $device..."
    wipefs -af "$device" 2>/dev/null || true
    
    # Limpa partições específicas também
    for part in "${device}"*; do
      [[ -b "$part" ]] && wipefs -af "$part" 2>/dev/null || true
    done
  done

  if command -v blkdiscard >/dev/null 2>&1; then
    for device in "$TARGET_DISK" "$DATA_DISK"; do
      [[ -b "$device" ]] || continue
      info "Executando blkdiscard em $device..."
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
  sleep 2
  partprobe "$TARGET_DISK" 2>/dev/null || true
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    partprobe "$DATA_DISK" 2>/dev/null || true
  fi
  info "Sanitização concluída."
}

partition_devices() {
  info "Criando tabela GPT e partições."
  sgdisk --zap-all "$TARGET_DISK" || fatal "Falha ao zerar GPT do $TARGET_DISK"
  
  # Aguarda um pouco para garantir que o kernel reconheça as mudanças
  sleep 2
  
  sgdisk -n 1:2048:+${EFI_SIZE_MIB}MiB -t 1:ef00 -c 1:"EFI System" \
       -n 2:0:+${BOOT_SIZE_MIB}MiB  -t 2:8300 -c 2:"Boot" \
       -n 3:0:0 -t 3:8300 -c 3:"Linux LUKS" \
       "$TARGET_DISK" || fatal "Falha ao criar partições no $TARGET_DISK"

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    sgdisk --zap-all "$DATA_DISK" || fatal "Falha ao zerar GPT do $DATA_DISK"
    sleep 2
    sgdisk -n 1:2048:0 -t 1:8300 -c 1:"Data LUKS" "$DATA_DISK" || fatal "Falha ao criar partições no $DATA_DISK"
  fi

  sleep 3
  partprobe "$TARGET_DISK" 2>/dev/null || true
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    partprobe "$DATA_DISK" 2>/dev/null || true
  fi
  
  P_SUFFIX="$(part_suffix "$TARGET_DISK")"
  EFI_PART="${TARGET_DISK}${P_SUFFIX}1"
  BOOT_PART="${TARGET_DISK}${P_SUFFIX}2"
  LUKS_PART="${TARGET_DISK}${P_SUFFIX}3"
  
  # Aguarda até as partições estarem disponíveis
  local timeout=10
  while [[ $timeout -gt 0 ]] && [[ ! -b "$EFI_PART" || ! -b "$BOOT_PART" || ! -b "$LUKS_PART" ]]; do
    sleep 1
    ((timeout--))
  done
  
  [[ -b "$EFI_PART" && -b "$BOOT_PART" && -b "$LUKS_PART" ]] || fatal "Partições não criadas corretamente."

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_SUFFIX="$(part_suffix "$DATA_DISK")"
    DATA_PART="${DATA_DISK}${DATA_SUFFIX}1"
    
    timeout=10
    while [[ $timeout -gt 0 ]] && [[ ! -b "$DATA_PART" ]]; do
      sleep 1
      ((timeout--))
    done
    
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

  # Formata sistemas de arquivos não criptografados
  mkfs.fat -F32 -n "EFI" "$EFI_PART" || fatal "mkfs /efi falhou"
  mkfs.ext4 -F -L "BOOT" "$BOOT_PART" || fatal "mkfs /boot falhou"

  # Prepara partição LUKS
  wipefs -af "$LUKS_PART" 2>/dev/null || true
  dd if=/dev/zero of="$LUKS_PART" bs=1M count=10 status=none 2>/dev/null || true
  sync

  # Formata LUKS lendo a senha via stdin
  info "Formatando LUKS (TARGET_DISK)..."
  if ! printf '%s' "$LUKS_PASS" | cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
      --hash sha512 --pbkdf "$LUKS_KDF" --pbkdf-parallel "$PBKDF_PARALLEL" --pbkdf-memory "$LUKS_PBKDF_MEM" \
      --iter-time "$LUKS_ITER_TIME" --key-file=- "$LUKS_PART" --batch-mode; then
    warn "luksFormat falhou com parâmetros otimizados; tentando parâmetros conservadores..."
    if ! printf '%s' "$LUKS_PASS" | cryptsetup luksFormat --type luks2 --key-file=- "$LUKS_PART" --batch-mode; then
      fatal "luksFormat falhou completamente"
    fi
  fi

  # Adiciona chave de auto-destruição se habilitada
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    printf '%s' "$DESTRUCTION_PASS" > /tmp/destruction_key
    chmod 600 /tmp/destruction_key
    if ! printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$LUKS_PART" /tmp/destruction_key --key-file=-; then
      warn "luksAddKey (destruição) falhou"
    fi
    shred -vfz -n 3 /tmp/destruction_key 2>/dev/null || rm -f /tmp/destruction_key
  fi

  # Configura segundo disco se habilitado
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_SUFFIX="$(part_suffix "$DATA_DISK")"
    DATA_PART="${DATA_DISK}${DATA_SUFFIX}1"
    wipefs -af "$DATA_PART" 2>/dev/null || true
    
    # Gera keyfile aleatório para o disco de dados
    dd if=/dev/urandom of=/tmp/hd_keyfile bs=1024 count=4 status=none
    chmod 600 /tmp/hd_keyfile

    if ! cryptsetup luksFormat --type luks2 "$DATA_PART" /tmp/hd_keyfile --batch-mode; then
      warn "luksFormat (data) falhou"
    fi
    
    # Adiciona senha principal ao disco de dados
    if ! printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" --key-file=-; then
      warn "luksAddKey (data) falhou"
    fi

    # Adiciona chave de destruição ao disco de dados
    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      printf '%s' "$DESTRUCTION_PASS" > /tmp/destruction_data_key
      chmod 600 /tmp/destruction_data_key
      if ! printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" /tmp/destruction_data_key --key-file=-; then
        warn "luksAddKey destruição (data) falhou"
      fi
      shred -vfz -n 3 /tmp/destruction_data_key 2>/dev/null || rm -f /tmp/destruction_data_key
    fi
  fi

  # Abre volume LUKS principal
  printf '%s' "$LUKS_PASS" | cryptsetup open --key-file=- "$LUKS_PART" cryptroot || fatal "cryptsetup open cryptroot falhou"
  
  # Configura LVM
  pvcreate /dev/mapper/cryptroot || fatal "pvcreate falhou"
  vgcreate "$VG_NAME" /dev/mapper/cryptroot || fatal "vgcreate falhou"
  lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME" || fatal "lvcreate root falhou"
  lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME" || fatal "lvcreate swap falhou"
  lvcreate -l 100%FREE -n "$LV_HOME_NAME" "$VG_NAME" || fatal "lvcreate home falhou"

  # Formata volumes LVM
  mkfs.ext4 -F -L "ROOT" "/dev/$VG_NAME/$LV_ROOT_NAME" || fatal "mkfs root falhou"
  mkfs.ext4 -F -L "HOME" "/dev/$VG_NAME/$LV_HOME_NAME" || fatal "mkfs home falhou"
  mkswap -L "SWAP" "/dev/$VG_NAME/$LV_SWAP_NAME" || fatal "mkswap falhou"
  swapon "/dev/$VG_NAME/$LV_SWAP_NAME" || warn "swapon falhou"

  # Abre disco de dados se habilitado
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    if ! cryptsetup open "$DATA_PART" cryptdata --key-file /tmp/hd_keyfile; then
      warn "cryptsetup open cryptdata falhou"
    else
      mkfs.ext4 -F -L "DATA" /dev/mapper/cryptdata || warn "mkfs cryptdata falhou"
    fi
  fi

  # Obtém UUIDs para configuração posterior
  LUKS_UUID=$(blkid -s UUID -o value "$LUKS_PART" 2>/dev/null || echo "")
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(blkid -s UUID -o value "$DATA_PART" 2>/dev/null || echo "")
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
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]] && [[ -b /dev/mapper/cryptdata ]]; then
    mkdir -p /mnt/data
    mount /dev/mapper/cryptdata /mnt/data || warn "Falha ao montar /data"
  fi
  info "Montagem concluída."
}

install_base_and_prepare() {
  info "Instalando pacotes base"
  base_packages=( base base-devel linux linux-firmware lvm2 cryptsetup reflector nano sudo openssh networkmanager grub efibootmgr )

  # Atualiza mirrors se tiver internet
  if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
    info "Atualizando mirrors..."
    reflector --country Brazil --age 6 --protocol https --sort rate --save /etc/pacman.d/mirrorlist || warn "reflector falhou"
    pacman -Sy --noconfirm || warn "pacman -Sy falhou"
  fi
  
  pacstrap /mnt "${base_packages[@]}" --noconfirm || fatal "pacstrap falhou. Verifique a conexão ou pacotes no ISO."

  genfstab -U /mnt > /mnt/etc/fstab

  # Adiciona entrada para disco de dados no fstab se habilitado
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "# Disco de dados criptografado" >> /mnt/etc/fstab
    echo "/dev/mapper/cryptdata /data ext4 defaults,noatime 0 2" >> /mnt/etc/fstab
  fi

  # Salva informações importantes para uso no chroot
  echo "$LUKS_UUID" > /mnt/root/luks_uuid
  echo "$TARGET_DISK" > /mnt/root/target_disk
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "$DATA_UUID" > /mnt/root/data_uuid
    echo "$DATA_DISK" > /mnt/root/data_disk
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
        -in /tmp/hd_keyfile -out /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc; then
        chmod 600 /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc || true
        shred -vfz -n 3 /tmp/hd_keyfile 2>/dev/null || rm -f /tmp/hd_keyfile
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
  # CORREÇÃO: Passando variáveis para o chroot de forma segura
  arch-chroot /mnt /usr/bin/env \
    TIMEZONE="$TIMEZONE" \
    LOCALE="$LOCALE" \
    KEYMAP="$KEYMAP" \
    HOSTNAME="$HOSTNAME" \
    USERNAME="$USERNAME" \
    USER_SHELL="$USER_SHELL" \
    VG_NAME="$VG_NAME" \
    LV_ROOT_NAME="$LV_ROOT_NAME" \
    bash <<'CHROOT'
set -euo pipefail

info(){ printf "\033[0;34m[INFO-CHROOT]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[AVISO-CHROOT]\033[0m %s\n" "$*"; }

# Configurações de localização
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime || warn "Falha ao definir timezone"
hwclock --systohc || warn "Falha ao sincronizar hardware clock"

# Configuração de locale
sed -i "s/^#\($LOCALE.*\)/\1/" /etc/locale.gen
echo "$LOCALE UTF-8" >> /etc/locale.gen
locale-gen || warn "Falha ao gerar locales"
echo "LANG=$LOCALE" > /etc/locale.conf

# Configuração de teclado
echo "KEYMAP=$KEYMAP" > /etc/vconsole.conf

# Configuração de rede
echo "$HOSTNAME" > /etc/hostname
cat > /etc/hosts <<HOSTS
127.0.0.1  localhost
::1        localhost
127.0.1.1  $HOSTNAME.localdomain $HOSTNAME
HOSTS

# Configuração de usuários
if [[ -f /root/.pwroot ]]; then
  if chpasswd < /root/.pwroot; then
    info "Senha root configurada"
  else
    warn "Falha ao configurar senha root"
  fi
  shred -vfz -n 3 /root/.pwroot 2>/dev/null || rm -f /root/.pwroot
fi

if [[ -f /root/.pwuser ]]; then
  if ! id "$USERNAME" >/dev/null 2>&1; then
    useradd -m -G wheel,audio,video,storage -s "$USER_SHELL" "$USERNAME" || warn "Falha ao criar usuário"
  fi
  if chpasswd < /root/.pwuser; then
    info "Senha do usuário configurada"
  else
    warn "Falha ao configurar senha do usuário"
  fi
  shred -vfz -n 3 /root/.pwuser 2>/dev/null || rm -f /root/.pwuser
fi

# Configuração sudo
echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/wheel
chmod 440 /etc/sudoers.d/wheel

# Configuração SSH mais segura
if [[ -f /etc/ssh/sshd_config ]]; then
  sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
fi

# Configuração mkinitcpio
# A ordem dos hooks é crucial: block, encrypt e lvm2 devem vir antes de filesystems.
if [[ -f /etc/mkinitcpio.conf ]]; then
  sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf block encrypt lvm2 filesystems keyboard fsck)/' /etc/mkinitcpio.conf
  mkinitcpio -P || warn "mkinitcpio falhou"
fi

# Habilita serviços
systemctl enable NetworkManager || warn "Falha ao habilitar NetworkManager"
systemctl enable sshd || warn "Falha ao habilitar sshd"

# Instalação e configuração do GRUB
if [[ -f /root/luks_uuid && -f /root/target_disk ]]; then
  LUKS_UUID=$(cat /root/luks_uuid)
  TARGET_DISK=$(cat /root/target_disk)
  
  # Configuração do GRUB
  if [[ -f /etc/default/grub ]]; then
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=${LUKS_UUID}:cryptroot root=/dev/${VG_NAME}/${LV_ROOT_NAME}\"|" /etc/default/grub
    sed -i 's/^#GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub
    sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub
  fi
  
  # Instala GRUB
  # CORREÇÃO: Adicionado --removable para criar um bootloader mais robusto e portátil.
  # O bootloader será instalado em /boot/efi/EFI/BOOT/BOOTX64.EFI, o caminho de fallback padrão.
  if grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable --force "$TARGET_DISK"; then
    info "GRUB instalado com sucesso"
  else
    warn "Falha na instalação do GRUB"
  fi
  
  if grub-mkconfig -o /boot/grub/grub.cfg; then
    info "Configuração do GRUB gerada"
  else
    warn "Falha ao gerar configuração do GRUB"
  fi
fi

# Move arquivo de hash de destruição para local seguro
if [[ -f /etc/secure-destruction.hash ]]; then
  mkdir -p /etc/secure
  mv /etc/secure-destruction.hash /etc/secure/destruction.hash || true
  chmod 600 /etc/secure/destruction.hash || true
fi

# Limpeza de arquivos temporários
rm -f /root/luks_uuid /root/target_disk /root/data_uuid /root/data_disk 2>/dev/null || true

# Configurações de segurança adicionais
{
  echo "export TMOUT=600"
  echo "readonly TMOUT"
  echo "export HISTFILESIZE=100"
  echo "export HISTSIZE=100"
  echo "export HISTCONTROL=ignoredups:erasedups"
} > /etc/profile.d/security.sh
chmod 644 /etc/profile.d/security.sh

info "Configuração do chroot concluída"
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
    sed -i "s/REPLACE_DATA_UUID/${DATA_UUID}/g" /mnt/usr/local/bin/unlock-data.sh
    chmod 755 /mnt/usr/local/bin/unlock-data.sh
  fi

  cat > /mnt/usr/local/bin/crypto-destroy <<'DESTROY'
#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
HASH_FILE="/etc/secure/destruction.hash"

echo -e "${RED}⚠ AVISO: SISTEMA DE AUTO-DESTRUIÇÃO ⚠${NC}"
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

  echo -e "${YELLOW}🔥 Destruindo $dev_name ($dev_path)...${NC}"
  
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

# CORREÇÃO: Executa em primeiro plano para garantir a conclusão e feedback.
main_destruction
DESTROY

  # CORREÇÃO: Injeta os UUIDs reais no script de destruição.
  LUKS_UUID=$(cat /mnt/root/luks_uuid 2>/dev/null || echo "")
  DATA_UUID=$(cat /mnt/root/data_uuid 2>/dev/null || echo "")
  sed -i "s/REPLACE_LUKS_UUID/${LUKS_UUID}/g" /mnt/usr/local/bin/crypto-destroy
  sed -i "s/REPLACE_DATA_UUID/${DATA_UUID}/g" /mnt/usr/local/bin/crypto-destroy
  chmod 700 /mnt/usr/local/bin/crypto-destroy

  info "Helpers instalados com sucesso."
}

verify_installation() {
  info "Verificando arquivos críticos..."
  local errors=0
  
  [[ -s /mnt/etc/fstab ]] || { warn "/etc/fstab ausente ou vazio"; ((errors++)); }
  [[ -s /mnt/boot/grub/grub.cfg ]] || { warn "grub.cfg ausente ou vazio"; ((errors++)); }
  
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
  echo "  • Configurar sistema de auto-destruição"
  echo ""
  echo -e "TARGET_DISK: ${YELLOW}$TARGET_DISK${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "DATA_DISK: ${YELLOW}$DATA_DISK${NC}"
  fi
  echo ""
  echo -e "${RED}TODOS OS DADOS NESTES DISCOS SERÃO PERDIDOS!${NC}"
  echo "=================================================="
  
  read -rp "Se você entendeu os riscos e deseja prosseguir, digite 'CONFIRMO DESTRUIÇÃO': " confirm
  
  if [[ "$confirm" != "CONFIRMO DESTRUIÇÃO" ]]; then
    echo -e "${GREEN}Operação cancelada pelo usuário.${NC}"
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
  echo -e "  • Hostname: ${YELLOW}$HOSTNAME${NC}"
  echo -e "  • Usuário: ${YELLOW}$USERNAME${NC}"
  echo -e "  • Disco sistema: ${YELLOW}$TARGET_DISK${NC} (LUKS2 + LVM)"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "  • Disco dados: ${YELLOW}$DATA_DISK${NC} (LUKS2 + keyfile protegido por PIN)"
  fi
  echo -e "  • Conectividade: $([ "$has_internet" = true ] && echo -e "${GREEN}ONLINE${NC}" || echo -e "${YELLOW}OFFLINE${NC}")"
  echo ""
  echo -e "${BLUE}📋 COMANDOS PÓS-BOOT:${NC}"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo -e "  • Desbloquear HD dados: ${YELLOW}sudo /usr/local/bin/unlock-data.sh${NC}"
  fi
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo -e "  • Auto-destruição: ${RED}sudo /usr/local/bin/crypto-destroy${NC}"
  fi
  echo ""
  echo -e "${GREEN}✅ Sistema pronto para reinicialização!${NC}"
  echo -e "${YELLOW}Execute: ${NC}reboot"
  echo
}

# Executa função principal se script for chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi