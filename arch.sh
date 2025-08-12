#!/usr/bin/env bash
#
# install-secure-arch-consolidated.sh
#
# Instalação segura do Arch Linux (consolidado e otimizado)
# - Combina os dois scripts anteriores e aplica hardening e correções de segurança.
# - NÃO usa USB seguro. Usa PIN para proteger keyfile do HD de dados.
# - Possui mecanismo de AUTO-DESTRUIÇÃO acionado via senha (hash verificado).
# - Otimizado para uso com cabo de rede no Arch Live
#
# !!! ATENÇÃO: DESTRUTIVO. TESTE EM VM ANTES DE RODAR EM HARDWARE REAL !!!
#
set -euo pipefail
IFS=$'\n\t'

# -------------------- Segurança inicial --------------------
# Evita criação de arquivos world-readable por acidente.
umask 077

# Configura log seguro
LOGFILE="/var/log/install-secure-arch.log"
touch "$LOGFILE"
chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1  # Redireciona toda saída para o log

# Cores para saída (não sensíveis)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info(){ printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn(){ printf "${YELLOW}[AVISO]${NC} %s\n" "$*"; }
err(){ printf "${RED}[ERRO]${NC} %s\n" "$*"; }
fatal(){ err "$*"; exit 1; }
require_root(){ (( EUID == 0 )) || fatal "Execute o script como root."; }

# Suporta nvme e mmcblk (p suffix necessário)
part_suffix(){ local disk="$1"; [[ "$disk" =~ nvme|mmcblk ]] && echo "p" || echo ""; }

# Verifica se temos RAM suficiente para parâmetros PBKDF2 altos
check_memory_for_pbkdf() {
  local mem_kb
  mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local mem_gb=$((mem_kb / 1024 / 1024))
  
  if [[ $mem_gb -lt 2 ]]; then
    warn "Sistema com pouca RAM (${mem_gb}GB). Parâmetros PBKDF podem ser muito altos."
    warn "Considere reduzir LUKS_PBKDF_MEM se houver problemas de performance."
  fi
}

# -------------------- Configuração (edite com cuidado) --------------------
# Dispositivos
TARGET_DISK="${TARGET_DISK:-/dev/sda}"   # disco do sistema (UEFI + sistema)
DATA_DISK="${DATA_DISK:-/dev/sdb}"       # disco de dados (opcional)

# Tamanho das partições
EFI_SIZE_MIB=512
BOOT_SIZE_MIB=1024
SWAP_SIZE_GB=4

# Segurança
ENABLE_DUAL_ENCRYPTION=1
ENABLE_TPM2=0            # desabilitado neste script (usamos PIN)
ENABLE_SECURE_BOOT=0     # se quiser, integrar sbctl/sbsign depois
ENABLE_AUTO_DESTRUCTION=1

# Sistema
HOSTNAME="arch-secure"
TIMEZONE="America/Sao_Paulo"
LOCALE="pt_BR.UTF-8"
KEYMAP="br-abnt2"
USERNAME="operador"
USER_SHELL="/bin/bash"
FILESYSTEM="lvm+ext4"    # btrfs | ext4 | lvm+ext4

# LUKS parameters
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

# -------------------- Variáveis sensíveis (NÃO exportar) --------------------
LUKS_PASS=""
DESTRUCTION_PASS=""
ROOT_PASS=""
USER_PASS=""
GRUB_PASS=""
PIN_DATA=""

# -------------------- Cleanup seguro (trap) --------------------
secure_cleanup() {
  # Remove variáveis sensíveis e shred arquivos temporários
  unset LUKS_PASS DESTRUCTION_PASS ROOT_PASS USER_PASS GRUB_PASS PIN_DATA || true
  shred -u -n 3 /tmp/hd_keyfile 2>/dev/null || rm -f /tmp/hd_keyfile 2>/dev/null || true
  shred -u -n 3 /tmp/.pwroot 2>/dev/null || rm -f /tmp/.pwroot 2>/dev/null || true
  shred -u -n 3 /tmp/.pwuser 2>/dev/null || rm -f /tmp/.pwuser 2>/dev/null || true
  shred -u -n 3 /mnt/root/luks_uuid 2>/dev/null || true
  shred -u -n 3 /mnt/root/target_disk 2>/dev/null || true
  shred -u -n 3 /mnt/root/data_uuid 2>/dev/null || true
  # Limpa histórico bash para evitar vazamento de senhas
  unset HISTFILE 2>/dev/null || true
  history -c 2>/dev/null || true
}
trap secure_cleanup EXIT INT TERM

# -------------------- Funções básicas --------------------
confirm_continue() {
  echo
  warn "!!! Este script é destrutivo e apagará dados nos dispositivos configurados !!!"
  read -rp "Se você entendeu e deseja prosseguir digite 'CONFIRMO': " c
  [[ "$c" == "CONFIRMO" ]] || fatal "Abortado pelo usuário."
}

# Função para exibir senhas de forma segura para confirmação
display_passwords_for_confirmation() {
  echo
  echo "=================================================="
  echo "${GREEN}CONFIRMAÇÃO DE SENHAS COLETADAS:${NC}"
  echo "=================================================="
  echo "Senha LUKS (principal): [${#LUKS_PASS} caracteres] ${LUKS_PASS}"
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    echo "Senha AUTO-DESTRUIÇÃO: [${#DESTRUCTION_PASS} caracteres] ${DESTRUCTION_PASS}"
  fi
  echo "Senha root: [${#ROOT_PASS} caracteres] ${ROOT_PASS}"
  echo "Senha usuário ($USERNAME): [${#USER_PASS} caracteres] ${USER_PASS}"
  echo "PIN HD dados: [${#PIN_DATA} caracteres] ${PIN_DATA}"
  echo "=================================================="
  echo
  read -rp "${YELLOW}As senhas estão corretas? (s/N): ${NC}" confirm
  if [[ "$confirm" != "s" && "$confirm" != "S" ]]; then
    warn "Coletando senhas novamente..."
    return 1
  fi
  return 0
}

collect_passwords_interactive() {
  info "Coleta de senhas (não serão salvas em arquivos)."
  while true; do
    echo
    read -rsp "${BLUE}Senha LUKS (principal): ${NC}" LUKS_PASS; echo
    read -rsp "${BLUE}Confirme LUKS: ${NC}" tmp; echo
    [[ "$LUKS_PASS" == "$tmp" && -n "$LUKS_PASS" ]] || { warn "LUKS: senhas não coincidem ou vazia"; continue; }

    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      read -rsp "${BLUE}Senha AUTO-DESTRUIÇÃO (mínimo 8 caracteres): ${NC}" DESTRUCTION_PASS; echo
      read -rsp "${BLUE}Confirme destruição: ${NC}" tmp; echo
      [[ "$DESTRUCTION_PASS" == "$tmp" && ${#DESTRUCTION_PASS} -ge 8 ]] || { warn "Destruição: senhas não coincidem ou muito curta"; continue; }
    fi

    read -rsp "${BLUE}Senha root: ${NC}" ROOT_PASS; echo
    read -rsp "${BLUE}Confirme root: ${NC}" tmp; echo
    [[ "$ROOT_PASS" == "$tmp" && -n "$ROOT_PASS" ]] || { warn "Root: senhas não coincidem ou vazia"; continue; }

    read -rsp "${BLUE}Senha do usuário $USERNAME: ${NC}" USER_PASS; echo
    read -rsp "${BLUE}Confirme senha do usuário: ${NC}" tmp; echo
    [[ "$USER_PASS" == "$tmp" && -n "$USER_PASS" ]] || { warn "Usuário: senhas não coincidem ou vazia"; continue; }

    read -rsp "${BLUE}PIN para desbloquear HD (dados): ${NC}" PIN_DATA; echo
    read -rsp "${BLUE}Confirme PIN: ${NC}" tmp; echo
    [[ "$PIN_DATA" == "$tmp" && -n "$PIN_DATA" ]] || { warn "PIN: não coincidem ou vazio"; continue; }

    # Exibe senhas para confirmação
    if display_passwords_for_confirmation; then
      break
    fi
    # Se não confirmou, limpa variáveis e reinicia
    LUKS_PASS=""; DESTRUCTION_PASS=""; ROOT_PASS=""; USER_PASS=""; PIN_DATA=""
  done
  
  # Criar hash da senha de destruição para uso posterior
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    DESTRUCTION_HASH=$(printf '%s' "$DESTRUCTION_PASS" | sha256sum | awk '{print $1}')
    echo "$DESTRUCTION_HASH" > /tmp/destruction_hash
    chmod 600 /tmp/destruction_hash
  fi
  
  info "${GREEN}Senhas coletadas e confirmadas com sucesso.${NC}"
}

# Verifica se as ferramentas necessárias estão disponíveis
check_required_tools() {
  local missing_tools=()
  
  # Ferramentas críticas
  for tool in cryptsetup sgdisk mkfs.ext4 mkfs.fat pacstrap genfstab arch-chroot; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    fatal "Ferramentas necessárias não encontradas: ${missing_tools[*]}"
  fi
  
  # LVM tools
  for tool in pvcreate vgcreate lvcreate; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    fatal "Ferramentas LVM não encontradas: ${missing_tools[*]}. Execute: pacman -Sy lvm2"
  fi
  
  info "Todas as ferramentas necessárias estão disponíveis."
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

# Função otimizada para verificação de rede (cabo ethernet)
setup_network() {
  info "Configurando rede para cabo ethernet..."
  
  # Ativar interfaces ethernet
  for iface in /sys/class/net/en* /sys/class/net/eth*; do
    if [[ -d "$iface" ]]; then
      interface=$(basename "$iface")
      if [[ "$interface" != "lo" ]]; then
        ip link set "$interface" up 2>/dev/null || true
        info "Interface $interface ativada"
      fi
    fi
  done
  
  # Aguardar link e obter IP via DHCP
  info "Aguardando conexão ethernet..."
  sleep 3
  
  # Se dhcpcd estiver disponível, tentar; senão usar systemd-networkd/resolved
  if command -v dhcpcd >/dev/null 2>&1; then
    timeout 15 dhcpcd --noarp --timeout 10 2>/dev/null || warn "DHCP (dhcpcd) falhou"
  else
    warn "dhcpcd não encontrado, tentando systemd-networkd/systemd-resolved"
    # habilita e inicia serviços temporariamente
    systemctl start systemd-networkd.service systemd-resolved.service 2>/dev/null || warn "Falha ao iniciar systemd-networkd/resolved"
  fi

  # Teste simples de conectividade
  if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
    info "${GREEN}Conectividade OK${NC}"
    # Sincronizar relógio
    timedatectl set-ntp true 2>/dev/null || warn "Falha ao sincronizar relógio"
    return 0
  else
    warn "${YELLOW}Sem conectividade. Instalação continuará apenas com pacotes locais.${NC}"
    return 1
  fi
}

optimize_mirrors() {
  info "Atualizando keyring e otimizando mirrors."
  pacman -Sy --noconfirm archlinux-keyring >/dev/null 2>&1 || warn "Falha ao atualizar keyring"
  if command -v reflector >/dev/null 2>&1; then
    reflector --country Brazil --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist || warn "reflector falhou"
    pacman -Sy --noconfirm || warn "pacman -Sy falhou"
  else
    warn "Reflector não instalado. Usando mirrors padrão."
  fi
}

# -------------------- Sanitização de discos --------------------
sanitize_devices() {
  warn "Sanitizando dispositivos (pode demorar)."
  # desmonta
  umount -R /mnt 2>/dev/null || true
  swapoff -a 2>/dev/null || true
  umount "${TARGET_DISK}"* 2>/dev/null || true
  umount "${DATA_DISK}"* 2>/dev/null || true

  # preferir blkdiscard para SSD; fallback para dd (apenas início para acelerar)
  if blkdiscard "$TARGET_DISK" >/dev/null 2>&1; then
    info "blkdiscard aplicado em $TARGET_DISK"
  else
    warn "blkdiscard indisponível para $TARGET_DISK — sobrescrevendo início (100MB)"
    dd if=/dev/urandom of="$TARGET_DISK" bs=1M count=100 status=progress || true
  fi

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    if blkdiscard "$DATA_DISK" >/dev/null 2>&1; then
      info "blkdiscard aplicado em $DATA_DISK"
    else
      warn "blkdiscard indisponível para $DATA_DISK — sobrescrevendo início (100MB)"
      dd if=/dev/urandom of="$DATA_DISK" bs=1M count=100 status=progress || true
    fi
  fi
  info "Sanitização inicial concluída."
}

# -------------------- Particionamento --------------------
partition_devices() {
  info "Criando tabela GPT e partições."
  wipefs -a "$TARGET_DISK" || true
  sgdisk --zap-all "$TARGET_DISK" || true
  sgdisk -n 1:2048:+${EFI_SIZE_MIB}MiB -t 1:ef00 -c 1:"EFI System" "$TARGET_DISK"
  sgdisk -n 2:0:+${BOOT_SIZE_MIB}MiB -t 2:8300 -c 2:"Boot" "$TARGET_DISK"
  sgdisk -n 3:0:0 -t 3:8300 -c 3:"Linux LUKS" "$TARGET_DISK"

  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    wipefs -a "$DATA_DISK" || true
    sgdisk --zap-all "$DATA_DISK" || true
    sgdisk -n 1:2048:0 -t 1:8300 -c 1:"Data LUKS" "$DATA_DISK"
  fi

  sync
  partprobe "$TARGET_DISK" || true
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then partprobe "$DATA_DISK" || true; fi
  sleep 2
  info "Particionamento concluído."
}

# -------------------- Criptografia, LVM e filesystems --------------------
setup_encryption_and_lvm() {
  info "Configurando LUKS2 e LVM"

  P_SUFFIX="$(part_suffix "$TARGET_DISK")"
  EFI_PART="${TARGET_DISK}${P_SUFFIX}1"
  BOOT_PART="${TARGET_DISK}${P_SUFFIX}2"
  LUKS_PART="${TARGET_DISK}${P_SUFFIX}3"

  # FORMATA /boot e /efi
  mkfs.ext4 -F -L "BOOT" "$BOOT_PART" || fatal "mkfs /boot falhou"
  mkfs.fat -F32 "$EFI_PART" || fatal "mkfs /efi falhou"

  # FORMAT LUKS para sistema (passphrase por stdin)
  printf '%s' "$LUKS_PASS" | cryptsetup luksFormat "$LUKS_PART" \
    --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
    --hash sha512 --pbkdf "$LUKS_KDF" --pbkdf-parallel "$PBKDF_PARALLEL" \
    --pbkdf-memory "$LUKS_PBKDF_MEM" --iter-time "$LUKS_ITER_TIME" - || fatal "luksFormat falhou"

  # Adiciona senha de auto-destruição (keyslot adicional) - método mais robusto
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
    # Cria arquivo temporário para a senha de destruição
    echo -n "$DESTRUCTION_PASS" > /tmp/destruction_key
    chmod 600 /tmp/destruction_key
    
    # Usa arquivo temporário para adicionar chave
    printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$LUKS_PART" /tmp/destruction_key - || warn "luksAddKey para destruição falhou"
    
    # Remove arquivo temporário imediatamente
    shred -u /tmp/destruction_key || rm -f /tmp/destruction_key
  fi

  # Se habilitado, criptografa o disco de dados com keyfile
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_SUFFIX="$(part_suffix "$DATA_DISK")"
    DATA_PART="${DATA_DISK}${DATA_SUFFIX}1"

    # criar hd_keyfile temporário
    dd if=/dev/urandom of=/tmp/hd_keyfile bs=1024 count=4 status=none
    chmod 600 /tmp/hd_keyfile

    # LUKS format para data usando keyfile
    cryptsetup luksFormat "$DATA_PART" --type luks2 --cipher "$LUKS_CIPHER" --key-size $LUKS_KEY_SIZE \
      --pbkdf $LUKS_KDF --pbkdf-memory $LUKS_PBKDF_MEM --iter-time $LUKS_ITER_TIME /tmp/hd_keyfile || fatal "luksFormat data falhou"

    # adicionar passphrase e destruição ao LUKS do data - método mais robusto
    printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" /tmp/hd_keyfile - || warn "luksAddKey (data) falhou"
    
    # Criar arquivo temporário para senha de destruição do data disk
    if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 ]]; then
      echo -n "$DESTRUCTION_PASS" > /tmp/destruction_data_key
      chmod 600 /tmp/destruction_data_key
      printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey "$DATA_PART" /tmp/destruction_data_key - || warn "luksAddKey destr (data) falhou"
      shred -u /tmp/destruction_data_key || rm -f /tmp/destruction_data_key
    fi
  fi

  # Abre o container LUKS do sistema
  printf '%s' "$LUKS_PASS" | cryptsetup open "$LUKS_PART" cryptroot - || fatal "cryptsetup open cryptroot falhou"

  # LVM
  pvcreate /dev/mapper/cryptroot || fatal "pvcreate falhou"
  vgcreate "$VG_NAME" /dev/mapper/cryptroot || fatal "vgcreate falhou"
  lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME" || fatal "lvcreate root falhou"
  lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME" || fatal "lvcreate swap falhou"
  lvcreate -l 100%FREE -n "$LV_HOME_NAME" "$VG_NAME" || fatal "lvcreate home falhou"

  # Format volumes
  mkfs.ext4 -L "ROOT" "/dev/$VG_NAME/$LV_ROOT_NAME" || fatal "mkfs root falhou"
  mkfs.ext4 -L "HOME" "/dev/$VG_NAME/$LV_HOME_NAME" || fatal "mkfs home falhou"
  mkswap -L "SWAP" "/dev/$VG_NAME/$LV_SWAP_NAME" || fatal "mkswap falhou"
  swapon "/dev/$VG_NAME/$LV_SWAP_NAME" || warn "swapon falhou"

  # Se data criptografado: abrir com keyfile temporário (falha aqui é crítico)
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    if ! cryptsetup open "$DATA_PART" cryptdata --key-file /tmp/hd_keyfile; then
      fatal "cryptsetup open cryptdata falhou (necessário para preparar data)"
    fi
    mkfs.ext4 -L "DATA" /dev/mapper/cryptdata || fatal "mkfs cryptdata falhou"
  fi

  # Salvar UUIDs para uso posterior
  LUKS_UUID=$(blkid -s UUID -o value "${LUKS_PART}")
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(blkid -s UUID -o value "${DATA_PART}")
  fi

  info "Criptografia e LVM prontos."
}

mount_filesystems_for_install() {
  info "Montando sistemas de arquivos para instalação"
  mkdir -p /mnt
  mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt
  
  # Criar diretórios antes de montar
  mkdir -p /mnt/home /mnt/boot /mnt/boot/efi /mnt/home/dados
  
  mount "$BOOT_PART" /mnt/boot
  mount "$EFI_PART" /mnt/boot/efi
  mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    mount /dev/mapper/cryptdata /mnt/home/dados || warn "Falha ao montar dados"
  fi
}

install_base_and_prepare() {
  info "Instalando sistema base e pacotes essenciais"
  
  # Pacotes essenciais mesmo sem internet
  base_packages=(
    base base-devel linux-hardened linux-firmware lvm2 cryptsetup 
    reflector nano sudo openssh networkmanager
  )
  
  # Tenta instalar pacotes adicionais se tiver internet
  if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
    pacstrap /mnt "${base_packages[@]}" intel-ucode amd-ucode --noconfirm || 
      warn "Alguns pacotes podem ter falhado, continuando..."
  else
    pacstrap /mnt "${base_packages[@]}" --noconfirm || 
      warn "Alguns pacotes podem ter falhado, continuando..."
  fi

  # genfstab (usa UUIDs)
  genfstab -U /mnt > /mnt/etc/fstab

  # Adiciona entry para cryptdata
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(blkid -s UUID -o value "${DATA_PART}")
    cat >> /mnt/etc/fstab <<EOF
# Data cryptmapped mounted to /home/dados
/dev/mapper/cryptdata /home/dados ext4 defaults,noatime 0 2
EOF
  fi

  # Salvar UUIDs para chroot
  echo "$LUKS_UUID" > /mnt/root/luks_uuid
  echo "$TARGET_DISK" > /mnt/root/target_disk
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "$DATA_UUID" > /mnt/root/data_uuid
  fi

  # Transferir hash de destruição
  if [[ "$ENABLE_AUTO_DESTRUCTION" -eq 1 && -f /tmp/destruction_hash ]]; then
    cp /tmp/destruction_hash /mnt/etc/secure-destruction.hash
    chmod 600 /mnt/etc/secure-destruction.hash
  fi

  info "Base instalada e fstab gerado."
}

# -------------------- Protege o keyfile do data com PIN --------------------
prepare_keyfile_encrypted_by_pin() {
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    info "Protegendo hd_keyfile com PIN (openssl PBKDF2)."
    mkdir -p /mnt/etc/cryptsetup-keys.d
    # Encripta o keyfile temporário
    if ! printf '%s' "$PIN_DATA" | openssl enc -aes-256-cbc -pbkdf2 -salt -iter 100000 -pass stdin \
      -in /tmp/hd_keyfile -out /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc 2>/dev/null; then
      warn "Falha ao encriptar hd_keyfile com PIN"
    fi
    chmod 600 /mnt/etc/cryptsetup-keys.d/hd_keyfile.enc || true
    # Remove keyfile temporário
    shred -u /tmp/hd_keyfile 2>/dev/null || rm -f /tmp/hd_keyfile
    info "Keyfile protegido e instalado em /etc/cryptsetup-keys.d/hd_keyfile.enc."
  fi
}

# -------------------- Configuração dentro do chroot --------------------
prepare_pw_files_for_chroot() {
  # Usar memória em vez de arquivos temporários sempre que possível
  # Apenas criar arquivos temporários quando necessário para chpasswd
  printf 'root:%s\n' "$ROOT_PASS" > /mnt/root/.pwroot
  chmod 600 /mnt/root/.pwroot
  printf '%s:%s\n' "$USERNAME" "$USER_PASS" > /mnt/root/.pwuser
  chmod 600 /mnt/root/.pwuser
  info "Arquivos temporários de senha criados (serão removidos após uso)."
}

configure_chroot() {
  info "Entrando no chroot para configurações finais..."
  arch-chroot /mnt /usr/bin/env bash <<'CHROOT'
set -euo pipefail

# Timezone, locale
ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
hwclock --systohc
sed -i '/^#pt_BR.UTF-8/s/^#//' /etc/locale.gen
locale-gen
echo "LANG=pt_BR.UTF-8" > /etc/locale.conf
echo "KEYMAP=br-abnt2" > /etc/vconsole.conf

# Hostname and hosts
echo "arch-secure" > /etc/hostname
cat > /etc/hosts <<HOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   arch-secure.localdomain arch-secure
HOSTS

# Set passwords from secure files
if [[ -f /root/.pwroot ]]; then
  chpasswd < /root/.pwroot || true
  shred -u /root/.pwroot || rm -f /root/.pwroot
fi
if [[ -f /root/.pwuser ]]; then
  useradd -m -G wheel,audio,video,storage -s /bin/bash operador || true
  chpasswd < /root/.pwuser || true
  shred -u /root/.pwuser || rm -f /root/.pwuser
fi

# Sudo wheel
echo '%wheel ALL=(ALL) ALL' > /etc/sudoers.d/wheel
chmod 440 /etc/sudoers.d/wheel

# mkinitcpio - hooks encrypt e lvm2
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf block encrypt lvm2 filesystems keyboard fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

# Instalar pacotes de segurança (se conectado)
if timeout 5 ping -c1 8.8.8.8 >/dev/null 2>&1; then
  pacman -Sy --noconfirm networkmanager openssh nftables audit aide --needed || true
else
  pacman -S --noconfirm networkmanager openssh --needed || true
fi

# Habilitar serviços
systemctl enable NetworkManager
systemctl enable sshd
systemctl enable nftables 2>/dev/null || true
systemctl enable auditd 2>/dev/null || true

# GRUB
pacman -Sy --noconfirm grub efibootmgr --needed
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub

# Configurar linha de comando do kernel - substituir em vez de append para evitar duplicação
LUKS_UUID=$(cat /root/luks_uuid)
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=${LUKS_UUID}:cryptroot root=/dev/vg_system/lv_root\"|" /etc/default/grub

# Instalar GRUB
TARGET_DISK=$(cat /root/target_disk)
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH "$TARGET_DISK"
grub-mkconfig -o /boot/grub/grub.cfg

# Salvar hash de destruição
if [[ -f /etc/secure-destruction.hash ]]; then
  mkdir -p /etc/secure
  mv /etc/secure-destruction.hash /etc/secure/destruction.hash
  chmod 600 /etc/secure/destruction.hash
fi

# Limpar arquivos temporários
rm -f /root/luks_uuid /root/target_disk /root/data_uuid

# Inicializar AIDE database (se disponível)
if command -v aide >/dev/null 2>&1; then
  aide --init 2>/dev/null || true
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
fi

CHROOT
  info "Configuração chroot concluída."
}

# -------------------- Helpers instalados no sistema final --------------------
install_unlock_and_destroy_helpers() {
  info "Instalando helpers para desbloqueio e destruição."

  # Criar diretório antes de escrever helpers
  mkdir -p /mnt/usr/local/bin

  # unlock-data.sh - descriptografa hd_keyfile.enc usando PIN
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    DATA_UUID=$(cat /mnt/root/data_uuid)
    cat > /mnt/usr/local/bin/unlock-data.sh <<UNLOCK
#!/usr/bin/env bash
set -euo pipefail
read -rsp "Digite o PIN para desbloquear o HD: " pin; echo
ENC="/etc/cryptsetup-keys.d/hd_keyfile.enc"
TMPK="/tmp/hd_keyfile.\$\$"
if [[ ! -f "\$ENC" ]]; then echo "Arquivo encriptado não encontrado: \$ENC"; exit 1; fi
printf '%s' "\$pin" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass stdin -in "\$ENC" -out "\$TMPK" 2>/dev/null || {
  echo "PIN incorreto ou falha no decifrar"; exit 1;
}
chmod 600 "\$TMPK"
cryptsetup open "/dev/disk/by-uuid/${DATA_UUID}" cryptdata --key-file "\$TMPK" || {
  shred -u "\$TMPK"; exit 1;
}
shred -u "\$TMPK" || rm -f "\$TMPK"
echo "HD desbloqueado: /dev/mapper/cryptdata"
mount /dev/mapper/cryptdata /home/dados 2>/dev/null || echo "Montagem automática falhou; monte manualmente."
UNLOCK
    chmod 755 /mnt/usr/local/bin/unlock-data.sh
  fi

  # crypto-destroy - verifica senha e destrói headers LUKS
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
{
  # Obter dispositivos de destruição
  TARGET_LUKS_PART=$(cryptsetup status cryptroot 2>/dev/null | grep device | awk '{print $2}')
  [[ -n "$TARGET_LUKS_PART" ]] || TARGET_LUKS_PART="/dev/sda3"
  
  DATA_LUKS_PART=$(cryptsetup status cryptdata 2>/dev/null | grep device | awk '{print $2}')
  [[ -n "$DATA_LUKS_PART" ]] || DATA_LUKS_PART="/dev/sdb1"

  # Apagar headers LUKS
  cryptsetup luksErase --batch-mode "$TARGET_LUKS_PART" 2>/dev/null || true
  [[ -n "$DATA_LUKS_PART" ]] && cryptsetup luksErase --batch-mode "$DATA_LUKS_PART" 2>/dev/null || true

  # Sobrescrever áreas críticas
  dd if=/dev/urandom of="$TARGET_LUKS_PART" bs=1M count=100 status=progress 2>/dev/null || true
  [[ -n "$DATA_LUKS_PART" ]] && dd if=/dev/urandom of="$DATA_LUKS_PART" bs=1M count=100 status=progress 2>/dev/null || true

  sync
  echo "Destruição concluída. Sistema será desligado."
  poweroff -f
} &
echo "Processo de destruição iniciado (executando em background)."
DEST
  chmod 700 /mnt/usr/local/bin/crypto-destroy

  # emergency wrapper
  cat > /mnt/usr/local/bin/emergency-destruction-gui <<'WRAP'
#!/usr/bin/env bash
echo "=== EMERGÊNCIA: AUTO-DESTRUIÇÃO ==="
echo "Esta ação irá DESTRUIR PERMANENTEMENTE todos os dados criptografados!"
echo "Certifique-se de que realmente deseja continuar."
echo
sudo /usr/local/bin/crypto-destroy
WRAP
  chmod 750 /mnt/usr/local/bin/emergency-destruction-gui

  info "Helpers de desbloqueio e destruição instalados."
}

# -------------------- Verificações finais e limpeza --------------------
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
  
  # Remover arquivos temporários sensíveis
  rm -f /tmp/destruction_hash 2>/dev/null || true
  
  # Desmontagem segura
  umount -R /mnt 2>/dev/null || true
  cryptsetup luksClose cryptdata 2>/dev/null || true
  cryptsetup luksClose cryptroot 2>/dev/null || true
  vgchange -an "$VG_NAME" 2>/dev/null || true
  swapoff -a 2>/dev/null || true
  sync
  
  # Limpar histórico bash
  unset HISTFILE 2>/dev/null || true
  history -c 2>/dev/null || true
  
  info "Limpeza final concluída."
}

# -------------------- Ordem de execução --------------------
main() {
  require_root
  confirm_continue
  validate_environment
  collect_passwords_interactive
  
  # Verificar conectividade (otimizada)
  HAS_INTERNET=false
  if setup_network; then
    HAS_INTERNET=true
    optimize_mirrors
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
  echo "${GREEN}INSTALAÇÃO ARCH LINUX SEGURA CONCLUÍDA${NC}"
  echo "=================================================="
  echo "  - Hostname: ${HOSTNAME}"
  echo "  - Usuário: ${USERNAME}"
  echo "  - Disco sistema: ${TARGET_DISK} (LUKS2 + LVM)"
  if [[ "$ENABLE_DUAL_ENCRYPTION" -eq 1 ]]; then
    echo "  - Disco dados: ${DATA_DISK} (LUKS2 + keyfile protegido por PIN)"
  fi
  echo "  - Kernel: linux-hardened"
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
  echo "${GREEN}SEGURANÇA IMPLEMENTADA:${NC}"
  echo "  ✓ LUKS2 com Argon2id"
  echo "  ✓ LVM sobre criptografia"
  echo "  ✓ Keyfile protegido por PIN"
  echo "  ✓ Mecanismo de auto-destruição"
  echo "  ✓ Kernel hardened"
  echo "  ✓ Senhas nunca salvas em arquivos"
  echo "=================================================="
  echo ""
  warn "IMPORTANTE: Anote suas senhas e PIN em local seguro!"
  warn "Sem elas, os dados serão irrecuperáveis."
  echo ""
  info "${GREEN}Sistema pronto para reinicialização.${NC}"
  info "Execute: reboot"
}

# Executar apenas se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
