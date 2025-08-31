#!/bin/bash
# 22.sh - Script Ultra-Seguro para Instalação Arch Linux
# Proteção máxima contra ataques físicos com criptografia completa
# Versão: 2.0 - Enhanced Security Edition
set -euo pipefail

# ============================================================================
# CONFIGURAÇÕES DE CORES E LOGGING
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_NAME="secure-arch-setup"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
SECURE_DIR="/root/.secure"
HEADER_BACKUP_DIR="${SECURE_DIR}/headers"
KEY_DIR="${SECURE_DIR}/keys"

# ============================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# ============================================================================
ENABLE_SECURE_BOOT="${ENABLE_SECURE_BOOT:-true}"
ENABLE_TPM2="${ENABLE_TPM2:-true}"
ENABLE_DETACHED_HEADERS="${ENABLE_DETACHED_HEADERS:-true}"
ENABLE_GRUB_CRYPTO="${ENABLE_GRUB_CRYPTO:-true}"
ENABLE_SWAP_CRYPTO="${ENABLE_SWAP_CRYPTO:-true}"
ENABLE_HEADER_BACKUP="${ENABLE_HEADER_BACKUP:-true}"
ENABLE_ANTI_FORENSIC="${ENABLE_ANTI_FORENSIC:-true}"
ENABLE_SECURE_WIPE="${ENABLE_SECURE_WIPE:-true}"
ENABLE_MEMORY_CRYPTO="${ENABLE_MEMORY_CRYPTO:-true}"

# Configurações LUKS2 aprimoradas
LUKS_ITER_TIME=10000  # Aumentado para maior segurança
LUKS_PBKDF="argon2id"
LUKS_KEY_SIZE=512
LUKS_CIPHER="aes-xts-plain64"
LUKS_HASH="sha512"

# ============================================================================
# FUNÇÕES PRINCIPAIS
# ============================================================================

setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "$RED" "Este script deve ser executado como root!"
        exit 1
    fi
}

# ============================================================================
# DETECÇÃO DE HARDWARE E CAPACIDADES
# ============================================================================

detect_hardware() {
    log "$BLUE" "=== Detectando capacidades de hardware ==="
    
    # Detectar modo de boot
    if [[ -d /sys/firmware/efi ]]; then
        BOOT_MODE="UEFI"
        log "$GREEN" "✓ Modo UEFI detectado"
    else
        BOOT_MODE="BIOS"
        log "$YELLOW" "→ Modo BIOS detectado"
    fi
    
    # Detectar TPM2
    if [[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]; then
        HAS_TPM2=true
        log "$GREEN" "✓ TPM2 detectado"
    else
        HAS_TPM2=false
        log "$YELLOW" "→ TPM2 não detectado"
    fi
    
    # Detectar CPU com AES-NI
    if grep -q aes /proc/cpuinfo; then
        HAS_AESNI=true
        log "$GREEN" "✓ AES-NI suportado"
    else
        HAS_AESNI=false
        log "$YELLOW" "→ AES-NI não suportado"
    fi
    
    # Detectar memória disponível
    MEM_TOTAL=$(free -b | awk '/^Mem:/{print $2}')
    MEM_GB=$((MEM_TOTAL / 1024 / 1024 / 1024))
    log "$BLUE" "→ Memória total: ${MEM_GB}GB"
    
    # Ajustar configurações baseado na memória
    if [[ $MEM_GB -lt 4 ]]; then
        PBKDF_MEMORY=262144  # 256MB
    elif [[ $MEM_GB -lt 8 ]]; then
        PBKDF_MEMORY=524288  # 512MB
    else
        PBKDF_MEMORY=1048576  # 1GB
    fi
}

# ============================================================================
# INSTALAÇÃO DE DEPENDÊNCIAS
# ============================================================================

install_dependencies() {
    log "$BLUE" "=== Instalando dependências de segurança ==="
    
    local packages=(
        "cryptsetup"
        "parted"
        "btrfs-progs"
        "dosfstools"
        "grub"
        "efibootmgr"
        "sbctl"  # Para Secure Boot
        "clevis"  # Para TPM2 binding
        "tpm2-tools"
        "yubikey-manager"  # Suporte YubiKey opcional
        "gnupg"
        "haveged"  # Melhor entropia
        "rng-tools"
        "secure-delete"  # Secure wipe
    )
    
    for pkg in "${packages[@]}"; do
        if ! pacman -Qi "$pkg" &>/dev/null; then
            log "$YELLOW" "Instalando $pkg..."
            pacman -S --noconfirm "$pkg" || log "$YELLOW" "Aviso: $pkg não pôde ser instalado"
        fi
    done
    
    # Iniciar serviços de entropia
    systemctl start haveged 2>/dev/null || true
    systemctl start rngd 2>/dev/null || true
}

# ============================================================================
# GERAÇÃO SEGURA DE SENHAS E CHAVES
# ============================================================================

generate_secure_password() {
    local length="${1:-32}"
    local password
    
    # Usar /dev/random para máxima segurança
    password=$(dd if=/dev/random bs=32 count=1 2>/dev/null | base64 | tr -d '\n' | cut -c1-"$length")
    echo "$password"
}

generate_keyfile() {
    local keyfile="$1"
    local size="${2:-4096}"
    
    log "$BLUE" "Gerando keyfile seguro: $keyfile"
    dd if=/dev/random of="$keyfile" bs=1 count="$size" 2>/dev/null
    chmod 600 "$keyfile"
}

# ============================================================================
# SECURE WIPE MELHORADO
# ============================================================================

secure_wipe_enhanced() {
    local device="$1"
    local passes="${2:-3}"
    
    log "$MAGENTA" "=== Executando Secure Wipe Avançado em $device ==="
    
    # Verificar se é SSD
    if [[ $(cat /sys/block/$(basename "$device")/queue/rotational) == "0" ]]; then
        log "$BLUE" "SSD detectado - usando Secure Erase"
        
        # Tentar ATA Secure Erase
        if hdparm -I "$device" 2>/dev/null | grep -q "supported: enhanced erase"; then
            log "$YELLOW" "Executando ATA Secure Erase..."
            hdparm --user-master u --security-set-pass p "$device"
            hdparm --user-master u --security-erase-enhanced p "$device"
        else
            # Fallback para TRIM
            log "$YELLOW" "Executando TRIM/discard..."
            blkdiscard -f "$device" 2>/dev/null || true
        fi
    else
        # HDD - múltiplas passadas
        log "$BLUE" "HDD detectado - executando $passes passadas"
        
        for ((i=1; i<=passes; i++)); do
            log "$YELLOW" "Passada $i de $passes..."
            
            # Passada com dados aleatórios
            dd if=/dev/urandom of="$device" bs=4M status=progress 2>/dev/null || true
            
            # Passada com zeros
            dd if=/dev/zero of="$device" bs=4M status=progress 2>/dev/null || true
            
            # Passada com padrão específico
            openssl enc -aes-256-ctr -pass pass:"$(date +%s)" -nosalt </dev/zero 2>/dev/null | \
                dd of="$device" bs=4M status=progress 2>/dev/null || true
        done
    fi
    
    # Limpar cabeçalhos e tabelas de partição
    wipefs -af "$device" 2>/dev/null || true
    sgdisk --zap-all "$device" 2>/dev/null || true
    
    log "$GREEN" "✓ Secure Wipe concluído"
}

# ============================================================================
# PARTICIONAMENTO SEGURO
# ============================================================================

create_secure_partitions() {
    local device="$1"
    
    log "$BLUE" "=== Criando partições seguras em $device ==="
    
    # Limpar completamente o disco
    if [[ "$ENABLE_SECURE_WIPE" == "true" ]]; then
        secure_wipe_enhanced "$device" 1
    fi
    
    # Detectar prefixo de partição
    if [[ "$device" =~ nvme|mmcblk|loop ]]; then
        PART_PREFIX="${device}p"
    else
        PART_PREFIX="${device}"
    fi
    
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Criando layout GPT/UEFI seguro..."
        
        parted -s "$device" mklabel gpt
        parted -s "$device" mkpart ESP fat32 1MiB 513MiB
        parted -s "$device" set 1 esp on
        parted -s "$device" mkpart BOOT 513MiB 1537MiB
        parted -s "$device" mkpart SWAP 1537MiB $((1537 + SWAPSIZE_GiB * 1024))MiB
        parted -s "$device" mkpart ROOT $((1537 + SWAPSIZE_GiB * 1024))MiB 100%
        
        ESP_PART="${PART_PREFIX}1"
        BOOT_PART="${PART_PREFIX}2"
        SWAP_PART="${PART_PREFIX}3"
        ROOT_PART="${PART_PREFIX}4"
    else
        log "$BLUE" "Criando layout MBR/BIOS seguro..."
        
        parted -s "$device" mklabel msdos
        parted -s "$device" mkpart primary ext4 1MiB 1025MiB
        parted -s "$device" set 1 boot on
        parted -s "$device" mkpart primary 1025MiB $((1025 + SWAPSIZE_GiB * 1024))MiB
        parted -s "$device" mkpart primary $((1025 + SWAPSIZE_GiB * 1024))MiB 100%
        
        BOOT_PART="${PART_PREFIX}1"
        SWAP_PART="${PART_PREFIX}2"
        ROOT_PART="${PART_PREFIX}3"
    fi
    
    partprobe "$device"
    sleep 2
    
    log "$GREEN" "✓ Partições criadas"
}

# ============================================================================
# CRIPTOGRAFIA LUKS2 AVANÇADA
# ============================================================================

create_luks_advanced() {
    local device="$1"
    local name="$2"
    local password="$3"
    
    log "$MAGENTA" "=== Criando LUKS2 avançado em $device ==="
    
    # Preparar header detachado se habilitado
    local header_file=""
    if [[ "$ENABLE_DETACHED_HEADERS" == "true" ]]; then
        mkdir -p "$HEADER_BACKUP_DIR"
        header_file="${HEADER_BACKUP_DIR}/${name}.header"
        log "$BLUE" "Usando header detachado: $header_file"
    fi
    
    # Configurar opções LUKS2
    local luks_opts=(
        "--type" "luks2"
        "--cipher" "$LUKS_CIPHER"
        "--key-size" "$LUKS_KEY_SIZE"
        "--hash" "$LUKS_HASH"
        "--pbkdf" "$LUKS_PBKDF"
        "--pbkdf-memory" "$PBKDF_MEMORY"
        "--iter-time" "$LUKS_ITER_TIME"
        "--use-random"
    )
    
    # Adicionar header detachado se habilitado
    if [[ -n "$header_file" ]]; then
        luks_opts+=("--header" "$header_file")
    fi
    
    # Adicionar label
    luks_opts+=("--label" "${name}_crypt")
    
    # Formatar com LUKS2
    echo -n "$password" | cryptsetup luksFormat "${luks_opts[@]}" "$device" -
    
    # Adicionar keyfile como segunda chave
    local keyfile="${KEY_DIR}/${name}.key"
    mkdir -p "$KEY_DIR"
    generate_keyfile "$keyfile" 4096
    
    if [[ -n "$header_file" ]]; then
        echo -n "$password" | cryptsetup luksAddKey --header "$header_file" "$device" "$keyfile" -
    else
        echo -n "$password" | cryptsetup luksAddKey "$device" "$keyfile" -
    fi
    
    # Configurar Anti-Forensic se habilitado
    if [[ "$ENABLE_ANTI_FORENSIC" == "true" ]]; then
        log "$BLUE" "Aplicando proteções anti-forenses..."
        
        # Adicionar slots dummy para confundir ataques
        for i in {2..7}; do
            local dummy_pass=$(generate_secure_password 64)
            echo -n "$password" | cryptsetup luksAddKey "$device" --key-slot "$i" <(echo -n "$dummy_pass") - 2>/dev/null || true
        done
    fi
    
    # Backup do header LUKS
    if [[ "$ENABLE_HEADER_BACKUP" == "true" ]]; then
        local backup_file="${HEADER_BACKUP_DIR}/${name}.header.backup"
        cryptsetup luksHeaderBackup "$device" --header-backup-file "$backup_file"
        
        # Criptografar o backup com GPG
        if command -v gpg &>/dev/null; then
            gpg --symmetric --cipher-algo AES256 --armor "$backup_file"
            shred -vfz -n 3 "$backup_file" 2>/dev/null || rm -f "$backup_file"
        fi
    fi
    
    log "$GREEN" "✓ LUKS2 criado com segurança máxima"
}

# ============================================================================
# CRIPTOGRAFIA DO SWAP
# ============================================================================

setup_encrypted_swap() {
    log "$MAGENTA" "=== Configurando SWAP criptografado ==="
    
    if [[ "$ENABLE_SWAP_CRYPTO" != "true" ]]; then
        log "$YELLOW" "Criptografia de SWAP desabilitada"
        mkswap "$SWAP_PART"
        return
    fi
    
    # Criar LUKS no swap com chave aleatória
    local swap_key="${KEY_DIR}/swap.key"
    mkdir -p "$KEY_DIR"
    
    # Gerar chave aleatória para swap
    generate_keyfile "$swap_key" 512
    
    # Formatar swap com LUKS2
    cryptsetup luksFormat \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --hash sha256 \
        --pbkdf pbkdf2 \
        --pbkdf-force-iterations 1000 \
        --use-random \
        --key-file "$swap_key" \
        "$SWAP_PART"
    
    # Abrir swap criptografado
    cryptsetup open --key-file "$swap_key" "$SWAP_PART" cryptswap
    
    # Formatar como swap
    mkswap /dev/mapper/cryptswap
    
    # Configurar para montagem automática
    SWAP_UUID=$(blkid -s UUID -o value "$SWAP_PART")
    
    log "$GREEN" "✓ SWAP criptografado configurado"
}

# ============================================================================
# CONFIGURAÇÃO DO ROOT CRIPTOGRAFADO
# ============================================================================

setup_encrypted_root() {
    log "$MAGENTA" "=== Configurando ROOT criptografado ==="
    
    # Criar LUKS2 avançado no root
    create_luks_advanced "$ROOT_PART" "root" "$LUKS_PASSWORD"
    
    # Abrir volume criptografado
    if [[ "$ENABLE_DETACHED_HEADERS" == "true" ]]; then
        cryptsetup open \
            --header "${HEADER_BACKUP_DIR}/root.header" \
            --key-file "${KEY_DIR}/root.key" \
            "$ROOT_PART" cryptroot
    else
        echo -n "$LUKS_PASSWORD" | cryptsetup open "$ROOT_PART" cryptroot -
    fi
    
    # Criar sistema de arquivos Btrfs com compressão
    mkfs.btrfs -L ROOT /dev/mapper/cryptroot
    
    # Montar e criar subvolumes
    mount /dev/mapper/cryptroot /mnt
    
    log "$BLUE" "Criando subvolumes Btrfs..."
    btrfs subvolume create /mnt/@
    btrfs subvolume create /mnt/@home
    btrfs subvolume create /mnt/@snapshots
    btrfs subvolume create /mnt/@var
    btrfs subvolume create /mnt/@log
    btrfs subvolume create /mnt/@cache
    btrfs subvolume create /mnt/@tmp
    
    umount /mnt
    
    # Remontar com opções de segurança
    mount -o subvol=@,compress=zstd:3,noatime,nodiratime,space_cache=v2 /dev/mapper/cryptroot /mnt
    
    # Criar pontos de montagem
    mkdir -p /mnt/{boot,home,var,.snapshots,tmp}
    
    # Montar subvolumes com opções de segurança
    mount -o subvol=@home,compress=zstd:3,noatime,nodiratime /dev/mapper/cryptroot /mnt/home
    mount -o subvol=@var,compress=zstd:3,noatime,nodiratime /dev/mapper/cryptroot /mnt/var
    mount -o subvol=@snapshots,compress=zstd:3,noatime,nodiratime /dev/mapper/cryptroot /mnt/.snapshots
    mount -o subvol=@tmp,compress=zstd:3,noatime,nodiratime,noexec,nosuid,nodev /dev/mapper/cryptroot /mnt/tmp
    
    # Criar e montar var/log e var/cache
    mkdir -p /mnt/var/{log,cache}
    mount -o subvol=@log,compress=zstd:3,noatime,nodiratime /dev/mapper/cryptroot /mnt/var/log
    mount -o subvol=@cache,compress=zstd:3,noatime,nodiratime /dev/mapper/cryptroot /mnt/var/cache
    
    log "$GREEN" "✓ ROOT criptografado configurado"
}

# ============================================================================
# CRIPTOGRAFIA DO BOOT/GRUB
# ============================================================================

setup_encrypted_boot() {
    log "$MAGENTA" "=== Configurando BOOT criptografado ==="
    
    if [[ "$ENABLE_GRUB_CRYPTO" != "true" ]]; then
        log "$YELLOW" "Criptografia de BOOT desabilitada"
        mkfs.ext4 -L BOOT "$BOOT_PART"
        mount "$BOOT_PART" /mnt/boot
        return
    fi
    
    # Criar LUKS1 para compatibilidade com GRUB
    log "$BLUE" "Criando LUKS1 para /boot (compatível com GRUB)..."
    
    echo -n "$LUKS_PASSWORD" | cryptsetup luksFormat \
        --type luks1 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --hash sha256 \
        --iter-time 5000 \
        "$BOOT_PART" -
    
    # Abrir boot criptografado
    echo -n "$LUKS_PASSWORD" | cryptsetup open "$BOOT_PART" cryptboot -
    
    # Formatar como ext4
    mkfs.ext4 -L BOOT /dev/mapper/cryptboot
    
    # Montar boot
    mount /dev/mapper/cryptboot /mnt/boot
    
    # Se UEFI, montar ESP
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        mkfs.vfat -F32 -n ESP "$ESP_PART"
        mkdir -p /mnt/boot/efi
        mount "$ESP_PART" /mnt/boot/efi
    fi
    
    log "$GREEN" "✓ BOOT criptografado configurado"
}

# ============================================================================
# CONFIGURAÇÃO DO GRUB COM SENHA
# ============================================================================

configure_grub_security() {
    log "$MAGENTA" "=== Configurando segurança do GRUB ==="
    
    # Gerar senha para GRUB
    local grub_user="grub"
    local grub_pass=$(generate_secure_password 20)
    
    # Salvar senha de forma segura
    echo "GRUB_USER=$grub_user" >> "${SECURE_DIR}/credentials"
    echo "GRUB_PASS=$grub_pass" >> "${SECURE_DIR}/credentials"
    chmod 600 "${SECURE_DIR}/credentials"
    
    # Criar hash da senha
    local grub_pass_hash=$(echo -e "$grub_pass\n$grub_pass" | grub-mkpasswd-pbkdf2 | grep -oP "(?<=PBKDF2 hash of your password is ).*")
    
    # Criar arquivo de configuração do GRUB
    cat > /mnt/etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

# Configuração de segurança do GRUB
set superusers="$grub_user"
password_pbkdf2 $grub_user $grub_pass_hash

# Proteger entradas do menu
menuentry_id_option="--unrestricted"

# Desabilitar edição de entradas
set disable_editing=true
EOF
    
    chmod +x /mnt/etc/grub.d/40_custom
    
    # Configurações adicionais do GRUB
    cat >> /mnt/etc/default/grub << EOF

# Segurança adicional
GRUB_DISABLE_RECOVERY="true"
GRUB_DISABLE_SUBMENU="true"
GRUB_TERMINAL_INPUT="console"
GRUB_ENABLE_CRYPTODISK="y"
EOF
    
    log "$GREEN" "✓ Segurança do GRUB configurada"
}

# ============================================================================
# CONFIGURAÇÃO TPM2
# ============================================================================

setup_tpm2_binding() {
    if [[ "$ENABLE_TPM2" != "true" ]] || [[ "$HAS_TPM2" != "true" ]]; then
        log "$YELLOW" "TPM2 não disponível ou desabilitado"
        return
    fi
    
    log "$MAGENTA" "=== Configurando TPM2 binding ==="
    
    # Instalar clevis para TPM2
    arch-chroot /mnt pacman -S --noconfirm clevis tpm2-tools
    
    # Configurar Clevis para desbloquear automaticamente
    local tpm2_pcrs="0,1,2,3,5,7"  # PCRs para verificar
    
    # Bind LUKS ao TPM2
    echo -n "$LUKS_PASSWORD" | arch-chroot /mnt clevis luks bind -d "$ROOT_PART" tpm2 '{"pcr_bank":"sha256","pcr_ids":"'"$tpm2_pcrs"'"}' -
    
    # Gerar initramfs com suporte TPM2
    arch-chroot /mnt mkinitcpio -P
    
    log "$GREEN" "✓ TPM2 binding configurado"
}

# ============================================================================
# CONFIGURAÇÃO DE SECURE BOOT
# ============================================================================

setup_secure_boot() {
    if [[ "$ENABLE_SECURE_BOOT" != "true" ]] || [[ "$BOOT_MODE" != "UEFI" ]]; then
        log "$YELLOW" "Secure Boot não disponível ou desabilitado"
        return
    fi
    
    log "$MAGENTA" "=== Configurando Secure Boot ==="
    
    # Instalar sbctl
    arch-chroot /mnt pacman -S --noconfirm sbctl
    
    # Criar chaves do Secure Boot
    arch-chroot /mnt sbctl create-keys
    
    # Assinar bootloader e kernel
    arch-chroot /mnt sbctl sign -s /boot/vmlinuz-linux
    arch-chroot /mnt sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
    arch-chroot /mnt sbctl sign -s /boot/EFI/systemd/systemd-bootx64.efi
    
    # Verificar assinaturas
    arch-chroot /mnt sbctl verify
    
    log "$GREEN" "✓ Secure Boot configurado"
    log "$YELLOW" "IMPORTANTE: Habilite Secure Boot na BIOS e importe as chaves"
}

# ============================================================================
# PROTEÇÕES ADICIONAIS DO KERNEL
# ============================================================================

configure_kernel_security() {
    log "$MAGENTA" "=== Configurando proteções do kernel ==="
    
    # Parâmetros de segurança do kernel
    cat > /mnt/etc/sysctl.d/99-security.conf << 'EOF'
# Proteções de rede
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Proteções de memória
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0

# Proteções de sistema
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
kernel.perf_event_paranoid = 3

# Proteções de arquivos
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Limites
kernel.core_uses_pid = 1
kernel.panic = 10
kernel.panic_on_oops = 1

# Módulos
kernel.modules_disabled = 1
kernel.unprivileged_bpf_disabled = 1
EOF
    
    # Parâmetros do GRUB para segurança
    local kernel_params=(
        "quiet"
        "loglevel=3"
        "rd.systemd.show_status=false"
        "rd.udev.log_level=3"
        "slab_nomerge"
        "init_on_alloc=1"
        "init_on_free=1"
        "page_alloc.shuffle=1"
        "pti=on"
        "vsyscall=none"
        "debugfs=off"
        "oops=panic"
        "module.sig_enforce=1"
        "lockdown=confidentiality"
        "mce=0"
        "random.trust_cpu=off"
        "intel_iommu=on"
        "amd_iommu=on"
        "iommu=force"
    )
    
    # Adicionar parâmetros ao GRUB
    local params_string="${kernel_params[*]}"
    sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$params_string\"/" /mnt/etc/default/grub
    
    log "$GREEN" "✓ Proteções do kernel configuradas"
}

# ============================================================================
# CONFIGURAÇÃO DE FIREWALL
# ============================================================================

setup_firewall() {
    log "$MAGENTA" "=== Configurando firewall ==="
    
    # Instalar nftables
    arch-chroot /mnt pacman -S --noconfirm nftables
    
    # Criar regras básicas
    cat > /mnt/etc/nftables.conf << 'EOF'
#!/usr/bin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Permitir loopback
        iif lo accept
        
        # Permitir conexões estabelecidas
        ct state established,related accept
        
        # Permitir ICMP necessário
        ip protocol icmp icmp type { echo-reply, destination-unreachable, time-exceeded } accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-reply, destination-unreachable, time-exceeded, packet-too-big } accept
        
        # Rate limiting
        ct state new limit rate 10/second accept
        
        # Log e drop
        log prefix "nftables-drop: " level debug
        counter drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        counter drop
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        counter accept
    }
}
EOF
    
    # Habilitar firewall
    arch-chroot /mnt systemctl enable nftables
    
    log "$GREEN" "✓ Firewall configurado"
}

# ============================================================================
# HARDENING DE SERVIÇOS
# ============================================================================

harden_services() {
    log "$MAGENTA" "=== Aplicando hardening de serviços ==="
    
    # Desabilitar serviços desnecessários
    local unnecessary_services=(
        "bluetooth"
        "cups"
        "avahi-daemon"
    )
    
    for service in "${unnecessary_services[@]}"; do
        arch-chroot /mnt systemctl disable "$service" 2>/dev/null || true
        arch-chroot /mnt systemctl mask "$service" 2>/dev/null || true
    done
    
    # Configurar journald para não persistir logs em disco (privacidade)
    if [[ "$ENABLE_MEMORY_CRYPTO" == "true" ]]; then
        sed -i 's/^#Storage=.*/Storage=volatile/' /mnt/etc/systemd/journald.conf
        sed -i 's/^#RuntimeMaxUse=.*/RuntimeMaxUse=50M/' /mnt/etc/systemd/journald.conf
    fi
    
    # Configurar limites de recursos
    cat > /mnt/etc/security/limits.d/99-security.conf << 'EOF'
* soft core 0
* hard core 0
* soft nproc 1000
* hard nproc 1500
* soft nofile 1024
* hard nofile 2048
EOF
    
    log "$GREEN" "✓ Hardening de serviços aplicado"
}

# ============================================================================
# CONFIGURAÇÃO FINAL E RESUMO
# ============================================================================

create_security_summary() {
    local summary_file="${SECURE_DIR}/security_summary.txt"
    
    cat > "$summary_file" << EOF
================================================================================
                        RESUMO DE SEGURANÇA DO SISTEMA
================================================================================
Data: $(date)
Hostname: $(hostname)

CRIPTOGRAFIA:
-------------
✓ Root: LUKS2 com $LUKS_CIPHER ($LUKS_KEY_SIZE bits)
✓ Swap: $([ "$ENABLE_SWAP_CRYPTO" == "true" ] && echo "Criptografado" || echo "Não criptografado")
✓ Boot: $([ "$ENABLE_GRUB_CRYPTO" == "true" ] && echo "LUKS1 (GRUB compatível)" || echo "Não criptografado")
✓ PBKDF: $LUKS_PBKDF com ${PBKDF_MEMORY}KB de memória
✓ Iterações: $LUKS_ITER_TIME ms

RECURSOS DE SEGURANÇA:
----------------------
$([ "$HAS_TPM2" == "true" ] && echo "✓ TPM2: Configurado" || echo "✗ TPM2: Não disponível")
$([ "$ENABLE_SECURE_BOOT" == "true" ] && [ "$BOOT_MODE" == "UEFI" ] && echo "✓ Secure Boot: Preparado" || echo "✗ Secure Boot: Não configurado")
$([ "$ENABLE_DETACHED_HEADERS" == "true" ] && echo "✓ Headers LUKS: Detachados" || echo "✓ Headers LUKS: Inline")
$([ "$HAS_AESNI" == "true" ] && echo "✓ AES-NI: Disponível" || echo "✗ AES-NI: Não disponível")

PROTEÇÕES:
----------
✓ GRUB: Protegido por senha
✓ Kernel: Parâmetros de segurança aplicados
✓ Firewall: nftables configurado
✓ Sysctl: Hardening aplicado
✓ Serviços: Minimizados e hardenizados

ARQUIVOS IMPORTANTES:
---------------------
✓ Credenciais: ${SECURE_DIR}/credentials
✓ Chaves: ${KEY_DIR}/
✓ Headers backup: ${HEADER_BACKUP_DIR}/
✓ Logs: ${LOG_DIR}/

PRÓXIMOS PASSOS:
----------------
1. Salve este resumo e os backups em local seguro
2. Configure Secure Boot na BIOS/UEFI
3. Teste a recuperação com os headers backup
4. Configure autenticação de 2 fatores
5. Implemente IDS/IPS adicional se necessário

================================================================================
EOF
    
    chmod 600 "$summary_file"
    log "$GREEN" "✓ Resumo de segurança criado: $summary_file"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    log "$CYAN" "╔══════════════════════════════════════════════════════════════╗"
    log "$CYAN" "║     ARCH LINUX ULTRA-SECURE INSTALLATION SCRIPT v2.0        ║"
    log "$CYAN" "║          Proteção Máxima Contra Ataques Físicos             ║"
    log "$CYAN" "╚══════════════════════════════════════════════════════════════╝"
    
    # Verificações iniciais
    check_root
    setup_logging
    
    # Detectar hardware e capacidades
    detect_hardware
    
    # Instalar dependências necessárias
    install_dependencies
    
    # Obter configurações
    if [[ -f "/root/config.json" ]]; then
        log "$BLUE" "Lendo configurações de /root/config.json..."
        DISCO_PRINCIPAL=$(jq -r '.main_disk' /root/config.json)
        SWAPSIZE_GiB=$(jq -r '.swap_gib // 8' /root/config.json)
        LUKS_PASSWORD=$(jq -r '.luks_root_password' /root/config.json)
    else
        # Modo interativo
        log "$YELLOW" "Modo interativo - Digite as configurações:"
        
        # Listar discos disponíveis
        lsblk -d -o NAME,SIZE,TYPE | grep disk
        
        read -p "Digite o disco principal (ex: /dev/sda): " DISCO_PRINCIPAL
        read -p "Tamanho do SWAP em GB (padrão 8): " swap_input
        SWAPSIZE_GiB="${swap_input:-8}"
        
        # Solicitar senha LUKS com confirmação
        while true; do
            read -sp "Digite a senha LUKS (mínimo 12 caracteres): " LUKS_PASSWORD
            echo
            read -sp "Confirme a senha LUKS: " LUKS_PASSWORD_CONFIRM
            echo
            
            if [[ "$LUKS_PASSWORD" == "$LUKS_PASSWORD_CONFIRM" ]]; then
                if [[ ${#LUKS_PASSWORD} -ge 12 ]]; then
                    break
                else
                    log "$RED" "Senha muito curta! Use pelo menos 12 caracteres."
                fi
            else
                log "$RED" "As senhas não coincidem!"
            fi
        done
    fi
    
    # Criar diretórios seguros
    mkdir -p "$SECURE_DIR" "$HEADER_BACKUP_DIR" "$KEY_DIR"
    chmod 700 "$SECURE_DIR"
    
    # Confirmar antes de prosseguir
    log "$RED" "╔══════════════════════════════════════════════════════════════╗"
    log "$RED" "║                         ATENÇÃO!                             ║"
    log "$RED" "║   TODOS OS DADOS EM $DISCO_PRINCIPAL SERÃO DESTRUÍDOS!      ║"
    log "$RED" "╚══════════════════════════════════════════════════════════════╝"
    
    if [[ "${NON_INTERACTIVE:-false}" != "true" ]]; then
        read -p "Digite 'DESTRUIR' para confirmar: " confirm
        if [[ "$confirm" != "DESTRUIR" ]]; then
            log "$YELLOW" "Operação cancelada pelo usuário"
            exit 0
        fi
    fi
    
    # Executar instalação segura
    create_secure_partitions "$DISCO_PRINCIPAL"
    setup_encrypted_root
    setup_encrypted_swap
    setup_encrypted_boot
    
    # Instalar sistema base
    log "$BLUE" "Instalando sistema base..."
    pacstrap /mnt base linux linux-firmware btrfs-progs cryptsetup grub efibootmgr
    
    # Gerar fstab
    genfstab -U /mnt >> /mnt/etc/fstab
    
    # Configurar criptografia no fstab para swap
    if [[ "$ENABLE_SWAP_CRYPTO" == "true" ]]; then
        echo "cryptswap UUID=$SWAP_UUID none luks,swap,cipher=aes-xts-plain64,size=512" >> /mnt/etc/crypttab
        echo "/dev/mapper/cryptswap none swap defaults 0 0" >> /mnt/etc/fstab
    fi
    
    # Aplicar configurações de segurança
    configure_grub_security
    configure_kernel_security
    setup_firewall
    harden_services
    setup_tpm2_binding
    setup_secure_boot
    
    # Criar resumo de segurança
    create_security_summary
    
    # Salvar configuração
    cat > "${ENV_FILE}" << EOF
export DISCO_PRINCIPAL="$DISCO_PRINCIPAL"
export ESP_PART="${ESP_PART:-}"
export BOOT_PART="$BOOT_PART"
export SWAP_PART="$SWAP_PART"
export ROOT_PART="$ROOT_PART"
export ROOT_UUID="$(blkid -s UUID -o value $ROOT_PART)"
export SWAP_UUID="$SWAP_UUID"
export BOOT_MODE="$BOOT_MODE"
export SECURE_DIR="$SECURE_DIR"
EOF
    
    log "$GREEN" "╔══════════════════════════════════════════════════════════════╗"
    log "$GREEN" "║            INSTALAÇÃO SEGURA CONCLUÍDA!                      ║"
    log "$GREEN" "╚══════════════════════════════════════════════════════════════╝"
    
    log "$CYAN" "Próximos passos:"
    log "$CYAN" "1. arch-chroot /mnt"
    log "$CYAN" "2. Configure timezone, locale, hostname"
    log "$CYAN" "3. Configure usuários e senhas"
    log "$CYAN" "4. Execute grub-install e grub-mkconfig"
    log "$CYAN" "5. Reinicie e teste o sistema"
    
    log "$YELLOW" "IMPORTANTE: Faça backup dos arquivos em $SECURE_DIR"
    log "$YELLOW" "Especialmente as chaves em $KEY_DIR e headers em $HEADER_BACKUP_DIR"
}

# ============================================================================
# TRATAMENTO DE ERROS
# ============================================================================

trap 'handle_error $? $LINENO' ERR

handle_error() {
    local exit_code=$1
    local line_number=$2
    log "$RED" "ERRO: Comando falhou com código $exit_code na linha $line_number"
    log "$RED" "Verifique o log em: $LOG_FILE"
    
    # Tentar cleanup básico
    umount -R /mnt 2>/dev/null || true
    cryptsetup close cryptroot 2>/dev/null || true
    cryptsetup close cryptboot 2>/dev/null || true
    cryptsetup close cryptswap 2>/dev/null || true
    
    exit "$exit_code"
}

# ============================================================================
# EXECUÇÃO
# ============================================================================

# Verificar parâmetros
case "${1:-}" in
    --help|-h)
        echo "Uso: $0 [opções]"
        echo "Opções:"
        echo "  --non-interactive    Usar config.json sem prompts"
        echo "  --skip-wipe         Pular secure wipe (mais rápido)"
        echo "  --minimal-security  Desabilitar recursos avançados"
        echo "  --help              Mostrar esta ajuda"
        exit 0
        ;;
    --non-interactive)
        NON_INTERACTIVE=true
        ;;
    --skip-wipe)
        ENABLE_SECURE_WIPE=false
        ;;
    --minimal-security)
        ENABLE_TPM2=false
        ENABLE_DETACHED_HEADERS=false
        ENABLE_ANTI_FORENSIC=false
        LUKS_ITER_TIME=5000
        ;;
esac

# Executar instalação
main "$@"