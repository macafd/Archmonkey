# ============================================================================
# FASE 2 - DISCO PRINCIPAL (CORRIGIDA)
# ============================================================================
cat << 'EOF' > fase2-disco-principal.sh
#!/bin/bash
# fase2-disco-principal.sh - Particionamento e criptografia do disco principal
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_NAME="fase2-disco-principal"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"

[[ ! -f "$ENV_FILE" ]] && { echo -e "${RED}Execute fase1 primeiro!${NC}"; exit 1; }
source "$ENV_FILE"

setup_logging() {
    [[ "$SIMULATE" == "true" ]] && LOG_DIR="./logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME}-$(date '+%Y%m%d-%H%M%S').log"
}

log() {
    local level="$1"; shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

check_commands() {
    local cmds=("cryptsetup" "parted" "mkfs.btrfs" "mkfs.ext4" "mkfs.vfat" "btrfs" "blkid" "wipefs" "partprobe" "mkswap")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "$RED" "Comando necessário não encontrado: $cmd"
            log "$YELLOW" "Instale com: pacman -S cryptsetup parted btrfs-progs dosfstools util-linux"
            exit 1
        fi
    done
    
    # sgdisk é opcional mas útil
    if ! command -v "sgdisk" &>/dev/null; then
        log "$YELLOW" "sgdisk não encontrado, usando métodos alternativos"
    fi
}

get_configuration() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if ! command -v jq &>/dev/null; then
            log "$RED" "jq necessário para modo non-interactive!"
            exit 1
        fi
        
        if [[ ! -f "$CONFIG_FILE" ]]; then
            log "$RED" "Arquivo de configuração não encontrado: $CONFIG_FILE"
            exit 1
        fi
        
        SWAPSIZE_GiB=$(jq -r '.swap_gib // 8' "$CONFIG_FILE")
        LUKS_PASSWORD=$(jq -r '.luks_root_password' "$CONFIG_FILE")
        
        if [[ -z "$LUKS_PASSWORD" ]] || [[ "$LUKS_PASSWORD" == "null" ]]; then
            log "$RED" "Senha LUKS não encontrada no arquivo de configuração!"
            exit 1
        fi
    else
        echo -e "${YELLOW}Tamanho do swap em GB (padrão 8):${NC}"
        read -r swap
        SWAPSIZE_GiB="${swap:-8}"
        
        # Validar entrada
        if ! [[ "$SWAPSIZE_GiB" =~ ^[0-9]+$ ]]; then
            log "$RED" "Tamanho de swap inválido!"
            exit 1
        fi
        
        echo -e "${YELLOW}Senha para criptografia LUKS:${NC}"
        read -rs LUKS_PASSWORD
        echo
        echo -e "${YELLOW}Confirme a senha:${NC}"
        read -rs LUKS_PASSWORD_CONFIRM
        echo
        
        [[ "$LUKS_PASSWORD" != "$LUKS_PASSWORD_CONFIRM" ]] && { log "$RED" "Senhas não coincidem!"; exit 1; }
        
        if [[ ${#LUKS_PASSWORD} -lt 8 ]]; then
            log "$RED" "Senha muito curta! Use pelo menos 8 caracteres."
            exit 1
        fi
    fi
}

check_disk_mounted() {
    if mount | grep -q "$DISCO_PRINCIPAL"; then
        log "$RED" "Disco $DISCO_PRINCIPAL está montado! Desmonte primeiro."
        exit 1
    fi
}

partition_disk() {
    log "$BLUE" "Particionando $DISCO_PRINCIPAL..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando particionamento"; return; }
    
    check_disk_mounted
    
    # Limpar disco com segurança
    log "$YELLOW" "Limpando disco..."
    wipefs -af "$DISCO_PRINCIPAL" 2>/dev/null || true
    
    # Usar sgdisk se disponível, senão usar dd
    if command -v sgdisk &>/dev/null; then
        sgdisk -Z "$DISCO_PRINCIPAL" 2>/dev/null || true
    else
        dd if=/dev/zero of="$DISCO_PRINCIPAL" bs=512 count=2048 2>/dev/null || true
    fi
    
    partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
    sleep 1
    
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Criando tabela de partições GPT (UEFI)..."
        parted -s "$DISCO_PRINCIPAL" \
            mklabel gpt \
            mkpart ESP fat32 1MiB 513MiB \
            set 1 esp on \
            mkpart BOOT ext4 513MiB 1537MiB \
            mkpart SWAP linux-swap 1537MiB $((1537 + SWAPSIZE_GiB * 1024))MiB \
            mkpart ROOT $((1537 + SWAPSIZE_GiB * 1024))MiB 100%
    else
        log "$BLUE" "Criando tabela de partições MBR (BIOS)..."
        parted -s "$DISCO_PRINCIPAL" \
            mklabel msdos \
            mkpart primary ext4 1MiB 1025MiB \
            set 1 boot on \
            mkpart primary linux-swap 1025MiB $((1025 + SWAPSIZE_GiB * 1024))MiB \
            mkpart primary $((1025 + SWAPSIZE_GiB * 1024))MiB 100%
    fi
    
    sleep 2
    partprobe "$DISCO_PRINCIPAL"
    
    # Detectar partições corretamente
    if [[ "$DISCO_PRINCIPAL" =~ nvme|mmcblk|loop ]]; then
        PART_PREFIX="${DISCO_PRINCIPAL}p"
    else
        PART_PREFIX="${DISCO_PRINCIPAL}"
    fi
    
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        ESP_PART="${PART_PREFIX}1"
        BOOT_PART="${PART_PREFIX}2"
        SWAP_PART="${PART_PREFIX}3"
        ROOT_PART="${PART_PREFIX}4"
    else
        ESP_PART=""
        BOOT_PART="${PART_PREFIX}1"
        SWAP_PART="${PART_PREFIX}2"
        ROOT_PART="${PART_PREFIX}3"
    fi
    
    # Verificar se as partições foram criadas
    for part in $BOOT_PART $SWAP_PART $ROOT_PART; do
        if [[ ! -b "$part" ]]; then
            log "$RED" "Erro: Partição $part não foi criada!"
            exit 1
        fi
    done
    
    log "$GREEN" "Partições criadas com sucesso"
}

create_luks() {
    log "$BLUE" "Criando volume LUKS no root..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando LUKS"; return; }
    
    # Ajustar memória PBKDF baseado na RAM disponível
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local pbkdf_memory=524288
    
    if [[ $mem_kb -lt 4194304 ]]; then  # Menos de 4GB
        pbkdf_memory=262144
        log "$YELLOW" "RAM limitada detectada, ajustando PBKDF memory para 256MB"
    fi
    
    log "$BLUE" "Formatando $ROOT_PART com LUKS2..."
    echo -n "$LUKS_PASSWORD" | cryptsetup luksFormat \
        --type luks2 \
        --pbkdf argon2id \
        --iter-time 5000 \
        --pbkdf-memory $pbkdf_memory \
        --batch-mode \
        "$ROOT_PART" - || { log "$RED" "Erro ao criar LUKS!"; exit 1; }
    
    log "$BLUE" "Abrindo volume LUKS..."
    echo -n "$LUKS_PASSWORD" | cryptsetup open "$ROOT_PART" cryptroot - || \
        { log "$RED" "Erro ao abrir volume LUKS!"; exit 1; }
    
    # Obter UUID do root LUKS
    ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
    
    if [[ -z "$ROOT_UUID" ]]; then
        log "$RED" "Erro ao obter UUID do root!"
        exit 1
    fi
    
    log "$GREEN" "LUKS criado e aberto com sucesso"
}

create_filesystems() {
    log "$BLUE" "Criando sistemas de arquivos..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando formatação"; return; }
    
    # ESP (apenas UEFI)
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Formatando ESP..."
        mkfs.vfat -F32 -n ESP "$ESP_PART" || { log "$RED" "Erro ao formatar ESP!"; exit 1; }
    fi
    
    # Boot
    log "$BLUE" "Formatando /boot..."
    mkfs.ext4 -L BOOT "$BOOT_PART" || { log "$RED" "Erro ao formatar boot!"; exit 1; }
    
    # Swap - IMPORTANTE: criar filesystem de swap antes de obter UUID
    log "$BLUE" "Formatando swap..."
    mkswap -L SWAP "$SWAP_PART" || { log "$RED" "Erro ao formatar swap!"; exit 1; }
    
    # Obter UUID do swap APÓS criar o filesystem
    SWAP_UUID=$(blkid -s UUID -o value "$SWAP_PART")
    
    if [[ -z "$SWAP_UUID" ]]; then
        log "$YELLOW" "Aviso: Não foi possível obter UUID do swap"
        SWAP_UUID="PENDING"
    fi
    
    # Root (Btrfs)
    log "$BLUE" "Formatando root com Btrfs..."
    mkfs.btrfs -L ROOT /dev/mapper/cryptroot || { log "$RED" "Erro ao formatar root!"; exit 1; }
    
    # Montar e criar subvolumes
    mount /dev/mapper/cryptroot /mnt || { log "$RED" "Erro ao montar root!"; exit 1; }
    
    log "$BLUE" "Criando subvolumes Btrfs..."
    for subvol in @ @home @snapshots @var @log @cache; do
        btrfs subvolume create /mnt/$subvol || { log "$RED" "Erro ao criar subvolume $subvol!"; exit 1; }
    done
    
    umount /mnt
    
    # Remontar com subvolume @
    log "$BLUE" "Montando sistema de arquivos..."
    mount -o subvol=@,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt || \
        { log "$RED" "Erro ao montar subvolume @!"; exit 1; }
    
    # Criar pontos de montagem
    mkdir -p /mnt/{boot,home,var,var/log,var/cache,.snapshots}
    
    # Montar subvolumes
    mount -o subvol=@home,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/home
    mount -o subvol=@var,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var
    mount -o subvol=@log,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/log
    mount -o subvol=@cache,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/cache
    mount -o subvol=@snapshots,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/.snapshots
    
    # Montar boot
    mount "$BOOT_PART" /mnt/boot
    
    # Montar ESP (apenas UEFI)
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        mkdir -p /mnt/boot/efi
        mount "$ESP_PART" /mnt/boot/efi
    fi
    
    log "$GREEN" "Sistemas de arquivos criados e montados com sucesso"
}

update_env() {
    cat >> "$ENV_FILE" << ENV
export ESP_PART="$ESP_PART"
export BOOT_PART="$BOOT_PART"
export SWAP_PART="$SWAP_PART"
export ROOT_PART="$ROOT_PART"
export ROOT_UUID="$ROOT_UUID"
export SWAP_UUID="$SWAP_UUID"
export SWAPSIZE_GiB="$SWAPSIZE_GiB"
ENV
    log "$GREEN" "Variáveis de ambiente atualizadas"
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 2: DISCO PRINCIPAL ==="
    
    check_commands
    get_configuration
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}ATENÇÃO: SERÁ FORMATADO: $DISCO_PRINCIPAL${NC}"
        echo -e "${RED}TODOS OS DADOS SERÃO PERDIDOS!${NC}"
        echo -e "${RED}Digite CONFIRM para continuar:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operação cancelada"; exit 0; }
    fi
    
    partition_disk
    create_luks
    create_filesystems
    update_env
    
    log "$GREEN" "Fase 2 concluída! Próximo: ./fase3-disco-auxiliar.sh (opcional) ou ./fase4-base-system.sh"
}

main
EOF
