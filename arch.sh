#!/usr/bin/env bash
#
# install-arch-secure.sh
#
# Instalador robusto e seguro para Arch Linux com foco em criptografia
# completa, LVM, e funcionalidades de segurança física como auto-destruição.
#
# VERSÃO: 2.0
#
set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# --- CONFIGURAÇÕES DO USUÁRIO ---
# (Podem ser sobrescritas por variáveis de ambiente)
# =============================================================================

# Defina como 1 para visualizar senhas ao digitar. DESATIVA o log em arquivo.
SHOW_PASSWORDS="${SHOW_PASSWORDS:-0}"

# Discos alvo. Ex: TARGET_DISK="/dev/nvme0n1"
TARGET_DISK="${TARGET_DISK:-/dev/sda}"
DATA_DISK="${DATA_DISK:-/dev/sdb}" # Usado apenas se ENABLE_DUAL_ENCRYPTION=1

# Habilita um segundo disco criptografado para dados.
ENABLE_DUAL_ENCRYPTION="${ENABLE_DUAL_ENCRYPTION:-0}"
# Habilita o mecanismo de auto-destruição com senha.
ENABLE_AUTO_DESTRUCTION="${ENABLE_AUTO_DESTRUCTION:-1}"

# Particionamento (em MiB)
EFI_SIZE_MIB=512
BOOT_SIZE_MIB=1024
SWAP_SIZE_GB=4 # Em GiB

# Configurações do sistema
HOSTNAME="arch-secure"
TIMEZONE="America/Sao_Paulo"
LOCALE="pt_BR.UTF-8"
KEYMAP="br-abnt2"
USERNAME="operador"
USER_SHELL="/bin/bash"

# Parâmetros de criptografia LUKS (fortes)
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512
LUKS_KDF="argon2id"
LUKS_PBKDF_MEM=1048576 # 1GiB de RAM para KDF
LUKS_ITER_TIME=4000
PBKDF_PARALLEL=4

# Nomes LVM
VG_NAME="vg_system"
LV_ROOT_NAME="lv_root"
LV_SWAP_NAME="lv_swap"
LV_HOME_NAME="lv_home"
LV_ROOT_SIZE="30G"

# URL para backup de log em caso de falha (ex: "scp://user@host:/path/to/logs/")
REMOTE_BACKUP_URL="${REMOTE_BACKUP_URL:-}"

# Senhas (podem ser passadas via ambiente para automação)
LUKS_PASS="${LUKS_PASS:-}"
DESTRUCTION_PASS="${DESTRUCTION_PASS:-}"
ROOT_PASS="${ROOT_PASS:-}"
USER_PASS="${USER_PASS:-}"
PIN_DATA="${PIN_DATA:-}"

# =============================================================================
# --- INÍCIO DO SCRIPT ---
# =============================================================================

# --- Variáveis Globais e Helpers ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
LOGFILE="/var/log/install-arch-secure.log"
BOOT_MODE="" # Será definido automaticamente

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[AVISO]${NC} %s\n" "$*"; }
err() { printf "${RED}[ERRO]${NC} %s\n" "$*"; }
fatal() { err "$*"; exit 1; }
require_root() { (( EUID == 0 )) || fatal "Este script deve ser executado como root."; }

# --- Funções de Segurança e Limpeza ---

secure_cleanup() {
    info "Executando limpeza segura de dados sensíveis..."
    unset LUKS_PASS DESTRUCTION_PASS ROOT_PASS USER_PASS PIN_DATA || true
    shred -vfzu -n 3 /tmp/hd_keyfile /tmp/destruction_hash /tmp/.pwroot /tmp/.pwuser &>/dev/null || true
    rm -f /tmp/hd_keyfile /tmp/destruction_hash /tmp/.pwroot /tmp/.pwuser &>/dev/null || true
    unset HISTFILE 2>/dev/null || true
    history -c 2>/dev/null || true
}

backup_log_on_failure() {
    local exit_code=$?
    if [[ "$exit_code" -ne 0 && -n "$REMOTE_BACKUP_URL" && -f "$LOGFILE" ]]; then
        warn "O script falhou. Tentando enviar log de erro para o servidor de backup..."
        # Exemplo usando curl para SCP. Adapte conforme necessário.
        if command -v curl &>/dev/null; then
            curl --insecure --upload-file "$LOGFILE" "$REMOTE_BACKUP_URL/$(basename "$LOGFILE").$(date +%s).log" || \
            warn "Falha ao enviar o log de erro."
        else
            warn "Comando 'curl' não encontrado para enviar o log."
        fi
    fi
    secure_cleanup
}

trap backup_log_on_failure EXIT
trap secure_cleanup INT TERM

# --- Funções de Validação e Preparação ---

show_help() {
    echo "Uso: $0 [-h|--help]"
    echo
    echo "Instalador seguro e automatizado para Arch Linux."
    echo "AVISO: Este script DESTRUIRÁ todos os dados nos discos especificados."
    echo
    echo "Opções:"
    echo "  -h, --help    Mostra esta mensagem de ajuda."
    echo
    echo "Variáveis de Ambiente para Configuração:"
    echo "  TARGET_DISK: Disco principal para o sistema (padrão: /dev/sda)."
    echo "  ENABLE_DUAL_ENCRYPTION: 1 para habilitar um segundo disco de dados (padrão: 0)."
    echo "  DATA_DISK: Disco para dados se a opção acima for 1 (padrão: /dev/sdb)."
    echo "  ENABLE_AUTO_DESTRUCTION: 1 para habilitar a senha de autodestruição (padrão: 1)."
    echo "  SHOW_PASSWORDS: 1 para exibir senhas ao digitar (desativa log em arquivo)."
    echo "  LUKS_PASS, ROOT_PASS, etc.: Para fornecer senhas de forma não interativa."
    echo "  REMOTE_BACKUP_URL: URL (ex: scp://user@host:/path/) para enviar logs em caso de falha."
    echo
    echo "Exemplo de uso automatizado:"
    echo "  export TARGET_DISK=/dev/nvme0n1 LUKS_PASS='secret' ROOT_PASS='secret' USER_PASS='secret' && ./$0"
    echo
}

check_dependencies() {
    info "Verificando dependências..."
    local missing=()
    local tools=(cryptsetup lvm sgdisk mkfs.ext4 mkfs.fat pacstrap genfstab arch-chroot partprobe wipefs dd grub-install grub-mkconfig openssl curl)
    for tool in "${tools[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if (( ${#missing[@]} > 0 )); then
        fatal "Ferramentas essenciais não encontradas: ${missing[*]}. Instale-as no ambiente live."
    fi
}

check_network() {
    info "Verificando conectividade de rede..."
    if ! ping -c 1 -W 3 archlinux.org &>/dev/null; then
        fatal "Sem conexão com a internet. A instalação não pode continuar."
    fi
    info "✓ Conexão com a internet ativa."
    timedatectl set-ntp true
}

validate_critical_vars() {
    info "Validando variáveis críticas..."
    [[ -n "$TARGET_DISK" ]] || fatal "A variável TARGET_DISK não está definida."
    [[ -b "$TARGET_DISK" ]] || fatal "Disco alvo $TARGET_DISK não é um dispositivo de bloco válido."

    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        [[ -n "$DATA_DISK" ]] || fatal "ENABLE_DUAL_ENCRYPTION=1, mas DATA_DISK não está definida."
        [[ -b "$DATA_DISK" ]] || fatal "Disco de dados $DATA_DISK não é um dispositivo de bloco válido."
        [[ "$TARGET_DISK" != "$DATA_DISK" ]] || fatal "TARGET_DISK e DATA_DISK não podem ser o mesmo dispositivo."
    fi

    # Validação de senhas apenas se fornecidas via env
    if [[ -n "${LUKS_PASS:-}" ]]; then
        [[ -n "$ROOT_PASS" && -n "$USER_PASS" ]] || fatal "Se LUKS_PASS é fornecida, ROOT_PASS e USER_PASS também devem ser."
        if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
            [[ -n "$DESTRUCTION_PASS" ]] || fatal "Autodestruição habilitada, mas DESTRUCTION_PASS não foi fornecida."
            [[ "$LUKS_PASS" != "$DESTRUCTION_PASS" ]] || fatal "A senha de destruição deve ser diferente da senha LUKS."
        fi
        if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
            [[ -n "$PIN_DATA" ]] || fatal "Criptografia dupla habilitada, mas PIN_DATA não foi fornecido."
        fi
    fi
}

detect_boot_mode() {
    if [[ -d /sys/firmware/efi/efivars ]]; then
        BOOT_MODE="UEFI"
        info "✓ Sistema iniciado em modo UEFI."
    else
        BOOT_MODE="LEGACY"
        fatal "Este script suporta apenas instalações em modo UEFI."
    fi
}

# --- Funções Principais da Instalação ---

collect_passwords() {
    # Se as senhas foram passadas por env, pula a coleta interativa
    if [[ -n "$LUKS_PASS" ]]; then
        info "Senhas fornecidas por variáveis de ambiente. Pulando coleta interativa."
        return 0
    fi

    info "Iniciando coleta interativa de senhas..."
    local read_opts_vis="-p"
    local read_opts_invis="-sp"

    while true; do
        # Senha LUKS
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Senha LUKS (principal): " LUKS_PASS; echo
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Confirme a senha LUKS: " tmp_pass; echo
        if [[ "$LUKS_PASS" != "$tmp_pass" || -z "$LUKS_PASS" ]]; then warn "Senhas LUKS não coincidem ou estão vazias. Tente novamente."; continue; fi

        # Senha de Destruição
        if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
            read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Senha de AUTO-DESTRUIÇÃO: " DESTRUCTION_PASS; echo
            read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Confirme a senha de destruição: " tmp_pass; echo
            if [[ "$DESTRUCTION_PASS" != "$tmp_pass" || -z "$DESTRUCTION_PASS" ]]; then warn "Senhas de destruição não coincidem ou estão vazias."; continue; fi
            if [[ "$DESTRUCTION_PASS" == "$LUKS_PASS" ]]; then warn "Senha de destruição deve ser diferente da senha LUKS."; continue; fi
        fi

        # Senha Root
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Senha do usuário 'root': " ROOT_PASS; echo
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Confirme a senha 'root': " tmp_pass; echo
        if [[ "$ROOT_PASS" != "$tmp_pass" || -z "$ROOT_PASS" ]]; then warn "Senhas de root não coincidem ou estão vazias."; continue; fi

        # Senha do Usuário
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Senha do usuário '$USERNAME': " USER_PASS; echo
        read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Confirme a senha do usuário: " tmp_pass; echo
        if [[ "$USER_PASS" != "$tmp_pass" || -z "$USER_PASS" ]]; then warn "Senhas do usuário não coincidem ou estão vazias."; continue; fi

        # PIN do Disco de Dados
        if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
            read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "PIN para o disco de dados: " PIN_DATA; echo
            read ${SHOW_PASSWORDS:+-p} ${SHOW_PASSWORDS:- -sp} "Confirme o PIN: " tmp_pass; echo
            if [[ "$PIN_DATA" != "$tmp_pass" || -z "$PIN_DATA" ]]; then warn "PINs não coincidem ou estão vazios."; continue; fi
        fi

        info "Senhas coletadas."
        break
    done
}

prepare_for_destruction() {
    info "Limpando discos alvo..."
    local disks_to_clean=("$TARGET_DISK")
    (( ENABLE_DUAL_ENCRYPTION == 1 )) && disks_to_clean+=("$DATA_DISK")

    for disk in "${disks_to_clean[@]}"; do
        info "Limpando $disk..."
        # Desmonta quaisquer partições montadas do disco
        umount -R "${disk}"* &>/dev/null || true
        # Fecha quaisquer volumes LUKS/LVM
        cryptsetup close /dev/mapper/"$(basename "${disk}")"* &>/dev/null || true
        vgchange -an &>/dev/null || true
        # Apaga assinaturas e tabela de partição
        wipefs -a "$disk"
        sgdisk --zap-all "$disk"
    done
    partprobe
    sleep 2
}

partition_and_format() {
    info "Particionando e formatando os discos..."
    local p_suffix; p_suffix=$( [[ "$TARGET_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
    local efi_part="${TARGET_DISK}${p_suffix}1"
    local boot_part="${TARGET_DISK}${p_suffix}2"
    local luks_part="${TARGET_DISK}${p_suffix}3"

    sgdisk -n 1:0:+${EFI_SIZE_MIB}M -t 1:ef00 -c 1:"EFI System" "$TARGET_DISK"
    sgdisk -n 2:0:+${BOOT_SIZE_MIB}M -t 2:8300 -c 2:"Boot" "$TARGET_DISK"
    sgdisk -n 3:0:0               -t 3:8e00 -c 3:"LVM System" "$TARGET_DISK" # 8e00 é Linux LVM
    partprobe "$TARGET_DISK"
    sleep 1

    mkfs.fat -F32 "$efi_part"
    mkfs.ext4 -F "$boot_part"

    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        local p_data_suffix; p_data_suffix=$( [[ "$DATA_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
        local data_luks_part="${DATA_DISK}${p_data_suffix}1"
        sgdisk -n 1:0:0 -t 1:8300 -c 1:"LUKS Data" "$DATA_DISK"
        partprobe "$DATA_DISK"
    fi
}

setup_luks_and_lvm() {
    info "Configurando criptografia LUKS e LVM..."
    local p_suffix; p_suffix=$( [[ "$TARGET_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
    local luks_part="${TARGET_DISK}${p_suffix}3"

    echo -n "$LUKS_PASS" | cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
        --pbkdf "$LUKS_KDF" --pbkdf-memory "$LUKS_PBKDF_MEM" --iter-time "$LUKS_ITER_TIME" \
        --pbkdf-parallel "$PBKDF_PARALLEL" --label "cryptsystem" --batch-mode "$luks_part"

    echo -n "$LUKS_PASS" | cryptsetup open "$luks_part" cryptroot

    pvcreate /dev/mapper/cryptroot
    vgcreate "$VG_NAME" /dev/mapper/cryptroot
    lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME"
    lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME"
    lvcreate -l '100%FREE' -n "$LV_HOME_NAME" "$VG_NAME"

    mkfs.ext4 "/dev/$VG_NAME/$LV_ROOT_NAME"
    mkfs.ext4 "/dev/$VG_NAME/$LV_HOME_NAME"
    mkswap "/dev/$VG_NAME/$LV_SWAP_NAME"

    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        info "Configurando criptografia no disco de dados..."
        local p_data_suffix; p_data_suffix=$( [[ "$DATA_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
        local data_luks_part="${DATA_DISK}${p_data_suffix}1"
        
        dd if=/dev/random of=/tmp/hd_keyfile bs=64 count=1
        chmod 600 /tmp/hd_keyfile
        
        cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
            --label "cryptdata" --key-file /tmp/hd_keyfile --batch-mode "$data_luks_part"
        
        cryptsetup open "$data_luks_part" cryptdata --key-file /tmp/hd_keyfile
        mkfs.ext4 /dev/mapper/cryptdata
        cryptsetup close cryptdata
    fi
}

mount_filesystems() {
    info "Montando sistemas de arquivos para instalação..."
    local p_suffix; p_suffix=$( [[ "$TARGET_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
    mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt
    mkdir -p /mnt/{boot,home}
    mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home
    mount "${TARGET_DISK}${p_suffix}2" /mnt/boot
    mkdir -p /mnt/boot/efi
    mount "${TARGET_DISK}${p_suffix}1" /mnt/boot/efi
    swapon "/dev/$VG_NAME/$LV_SWAP_NAME"
}

install_system() {
    info "Instalando sistema base com pacstrap..."
    pacstrap /mnt base base-devel linux linux-firmware lvm2 grub efibootmgr sudo nano networkmanager openssl curl

    info "Gerando fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab
}

prepare_chroot_data() {
    info "Preparando dados para o ambiente chroot..."
    local p_suffix; p_suffix=$( [[ "$TARGET_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
    local luks_part="${TARGET_DISK}${p_suffix}3"
    
    # Salva UUIDs para uso dentro do chroot
    blkid -s UUID -o value "$luks_part" > /mnt/root/system_luks_uuid.txt
    
    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        local p_data_suffix; p_data_suffix=$( [[ "$DATA_DISK" =~ nvme|mmcblk ]] && echo "p" || echo "" )
        local data_luks_part="${DATA_DISK}${p_data_suffix}1"
        blkid -s UUID -o value "$data_luks_part" > /mnt/root/data_luks_uuid.txt
        
        # Criptografa o keyfile do disco de dados com o PIN
        mkdir -p /mnt/etc/cryptsetup-keys.d
        echo -n "$PIN_DATA" | openssl enc -e -aes-256-cbc -pbkdf2 -iter 100000 \
            -pass stdin -in /tmp/hd_keyfile -out /mnt/etc/cryptsetup-keys.d/data_disk.key.enc
        chmod 600 /mnt/etc/cryptsetup-keys.d/data_disk.key.enc
    fi

    if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
        # Salva o hash da senha de destruição
        mkdir -p /mnt/etc/secure
        printf '%s' "$DESTRUCTION_PASS" | sha256sum | awk '{print $1}' > /mnt/etc/secure/destruction.hash
        chmod 600 /mnt/etc/secure/destruction.hash
    fi

    # Passa senhas de forma segura para o chroot
    echo -n "$ROOT_PASS" > /mnt/root/.pwroot
    echo -n "$USER_PASS" > /mnt/root/.pwuser
    chmod 600 /mnt/root/.pwroot /mnt/root/.pwuser
}

configure_chroot() {
    info "Configurando o sistema instalado (chroot)..."
    arch-chroot /mnt /bin/bash -s -- \
        "$HOSTNAME" "$TIMEZONE" "$LOCALE" "$KEYMAP" "$USERNAME" "$USER_SHELL" "$VG_NAME" <<'CHROOT_SCRIPT'
    set -euo pipefail
    
    HOSTNAME="$1"
    TIMEZONE="$2"
    LOCALE="$3"
    KEYMAP="$4"
    USERNAME="$5"
    USER_SHELL="$6"
    VG_NAME="$7"

    # Configurações básicas
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
    hwclock --systohc
    sed -i "s/^#$LOCALE/$LOCALE/" /etc/locale.gen
    locale-gen
    echo "LANG=$LOCALE" > /etc/locale.conf
    echo "KEYMAP=$KEYMAP" > /etc/vconsole.conf
    echo "$HOSTNAME" > /etc/hostname
    echo "127.0.0.1 localhost" >> /etc/hosts
    echo "::1       localhost" >> /etc/hosts
    echo "127.0.1.1 $HOSTNAME.localdomain $HOSTNAME" >> /etc/hosts

    # Configura senhas e usuário
    chpasswd < /root/.pwroot
    useradd -m -s "$USER_SHELL" -G wheel "$USERNAME"
    echo "$USERNAME:$(cat /root/.pwuser)" | chpasswd
    rm /root/.pwroot /root/.pwuser
    sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

    # Configura mkinitcpio e GRUB
    SYSTEM_LUKS_UUID=$(cat /root/system_luks_uuid.txt)
    sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck)/' /etc/mkinitcpio.conf
    
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"|" /etc/default/grub
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=$SYSTEM_LUKS_UUID:cryptroot root=/dev/$VG_NAME/lv_root\"|" /etc/default/grub
    sed -i 's/^#GRUB_ENABLE_CRYPTODISK=y/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub
    
    mkinitcpio -P
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable
    grub-mkconfig -o /boot/grub/grub.cfg

    # Habilita serviços essenciais
    systemctl enable NetworkManager.service

    # Limpa arquivos temporários do chroot
    rm -f /root/*_luks_uuid.txt
CHROOT_SCRIPT
}

install_helper_scripts() {
    info "Instalando scripts auxiliares..."
    mkdir -p /mnt/usr/local/bin
    
    SYSTEM_LUKS_UUID=$(cat /mnt/root/system_luks_uuid.txt)
    DATA_LUKS_UUID=""
    (( ENABLE_DUAL_ENCRYPTION == 1 )) && DATA_LUKS_UUID=$(cat /mnt/root/data_luks_uuid.txt)

    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        cat > /mnt/usr/local/bin/unlock-data <<'UNLOCK_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
(( EUID == 0 )) || { echo "ERRO: Execute como root (sudo)." >&2; exit 1; }
read -sp "Digite o PIN para desbloquear o disco de dados: " pin; echo
ENC_KEYFILE="/etc/cryptsetup-keys.d/data_disk.key.enc"
TMP_KEYFILE="/dev/shm/data_disk.key.$$"
trap 'shred -u "$TMP_KEYFILE" &>/dev/null || rm -f "$TMP_KEYFILE"' EXIT
printf '%s' "$pin" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass stdin -in "$ENC_KEYFILE" -out "$TMP_KEYFILE" || { echo "ERRO: PIN incorreto ou falha ao decifrar." >&2; exit 1; }
cryptsetup open "/dev/disk/by-uuid/DATA_UUID_PLACEHOLDER" cryptdata --key-file "$TMP_KEYFILE"
mkdir -p /data && mount /dev/mapper/cryptdata /data
echo "✓ Disco de dados desbloqueado e montado em /data."
UNLOCK_SCRIPT
        sed -i "s/DATA_UUID_PLACEHOLDER/$DATA_LUKS_UUID/" /mnt/usr/local/bin/unlock-data
        chmod 750 /mnt/usr/local/bin/unlock-data
    fi

    if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
        cat > /mnt/usr/local/bin/crypto-destroy <<'DESTROY_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
(( EUID == 0 )) || { echo -e "${RED}ERRO: Execute como root (sudo).${NC}" >&2; exit 1; }
echo -e "${YELLOW}--- AVISO: MODO DE AUTO-DESTRUIÇÃO ---${NC}"
echo "Esta ação é IRREVERSÍVEL e destruirá todos os dados criptografados."
read -p "Para confirmar, digite 'DESTRUIR AGORA': " confirm
[[ "$confirm" == "DESTRUIR AGORA" ]] || { echo "Operação cancelada."; exit 0; }
read -sp "Senha de destruição: " pass; echo
input_hash=$(printf '%s' "$pass" | sha256sum | awk '{print $1}')
stored_hash=$(cat /etc/secure/destruction.hash)
[[ "$input_hash" == "$stored_hash" ]] || { echo -e "${RED}ERRO: Senha de destruição incorreta.${NC}"; exit 1; }

destroy_luks_partition() {
    local uuid="$1"
    local label="$2"
    local devpath="/dev/disk/by-uuid/$uuid"
    if [[ -b "$devpath" ]]; then
        echo -e "${RED}🔥 Destruindo cabeçalhos LUKS de $label ($devpath)...${NC}"
        cryptsetup luksErase --batch-mode "$devpath"
        echo -e "${RED}🔥 Sobrescrevendo início da partição $label com dados aleatórios...${NC}"
        dd if=/dev/urandom of="$devpath" bs=1M count=100 status=progress
    else
        echo -e "${YELLOW}AVISO: Partição $label (UUID: $uuid) não encontrada. Pulando.${NC}"
    fi
}
echo "Iniciando processo de destruição..."
destroy_luks_partition "SYSTEM_UUID_PLACEHOLDER" "SISTEMA"
[[ -n "DATA_UUID_PLACEHOLDER" ]] && destroy_luks_partition "DATA_UUID_PLACEHOLDER" "DADOS"
echo -e "${RED}DESTRUIÇÃO CONCLUÍDA. O sistema será desligado em 5 segundos.${NC}"
sync; sleep 5; poweroff -f
DESTROY_SCRIPT
        sed -i "s/SYSTEM_UUID_PLACEHOLDER/$SYSTEM_LUKS_UUID/" /mnt/usr/local/bin/crypto-destroy
        sed -i "s/DATA_UUID_PLACEHOLDER/$DATA_LUKS_UUID/" /mnt/usr/local/bin/crypto-destroy
        chmod 700 /mnt/usr/local/bin/crypto-destroy
    fi
    rm -f /mnt/root/*_luks_uuid.txt
}

final_cleanup_and_reboot() {
    info "Finalizando e desmontando sistemas de arquivos..."
    umount -R /mnt
    swapoff -a
    cryptsetup close cryptroot
    vgchange -an "$VG_NAME"
    sync
    
    echo
    echo "=================================================="
    echo -e "${GREEN}🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! 🎉${NC}"
    echo "=================================================="
    echo "  • Hostname: $HOSTNAME"
    echo "  • Usuário: $USERNAME"
    echo "  • Sistema de arquivos criptografado e pronto."
    echo
    echo -e "${YELLOW}Ações Pós-Instalação:${NC}"
    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        echo "  • Para desbloquear o disco de dados, use: ${BLUE}sudo unlock-data${NC}"
    fi
    if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
        echo "  • Para destruir os dados, use: ${RED}sudo crypto-destroy${NC}"
    fi
    echo
    echo -e "${GREEN}Agora você pode reiniciar o sistema com o comando 'reboot'.${NC}"
    echo
}

# --- Função Principal de Execução ---

main() {
    # Configuração inicial e logging
    if (( SHOW_PASSWORDS == 1 )); then
        LOGFILE="/dev/null"
        warn "SHOW_PASSWORDS=1. O log da instalação será descartado para não gravar senhas."
    else
        touch "$LOGFILE" && chmod 600 "$LOGFILE"
    fi
    exec > >(tee -a "$LOGFILE") 2>&1

    # Início da lógica de instalação
    require_root
    detect_boot_mode
    check_dependencies
    validate_critical_vars
    
    echo -e "${RED}--- AVISO CRÍTICO ---${NC}"
    echo "Este script irá apagar permanentemente os seguintes discos:"
    echo -e "  - Disco do Sistema: ${YELLOW}$TARGET_DISK${NC}"
    (( ENABLE_DUAL_ENCRYPTION == 1 )) && echo -e "  - Disco de Dados:   ${YELLOW}$DATA_DISK${NC}"
    echo "Todos os dados serão perdidos. Faça backup antes de continuar."
    read -p "Digite 'CONFIRMO' para prosseguir: " confirm
    [[ "$confirm" == "CONFIRMO" ]] || fatal "Operação cancelada pelo usuário."

    check_network
    collect_passwords
    prepare_for_destruction
    partition_and_format
    setup_luks_and_lvm
    mount_filesystems
    install_system
    prepare_chroot_data
    configure_chroot
    install_helper_scripts
    final_cleanup_and_reboot
}

# --- Ponto de Entrada ---
if [[ "$#" -gt 0 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
    show_help
    exit 0
fi

# Garante que o script não seja executado se for "sourced"
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
