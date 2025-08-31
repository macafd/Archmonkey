# ============================================================================
# FASE 2 - DISCO PRINCIPAL
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

# Definir valor padrão para CONFIG_FILE se não estiver definida
CONFIG_FILE=${CONFIG_FILE:-"/root/2/Archmonkey/config.json"}

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
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessarios nao encontrados: ${missing[*]}"
        log "$YELLOW" "Instale com: pacman -S cryptsetup parted btrfs-progs dosfstools util-linux"
        exit 1
    fi
}

get_configuration() {
    # Verificação robusta para modo não interativo
    if [[ -f "$CONFIG_FILE" ]]; then
        NON_INTERACTIVE="true"
        log "$GREEN" "Arquivo de configuracao detectado: $CONFIG_FILE"
        log "$BLUE" "Modo non-interactive ativado automaticamente"
    fi

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log "$BLUE" "Lendo configuracao do arquivo: $CONFIG_FILE"
        
        # Verificar se o jq está instalado
        if ! command -v jq &>/dev/null; then
            log "$RED" "jq necessario para modo non-interactive!"
            log "$YELLOW" "Instalando jq..."
            pacman -Sy jq --noconfirm || {
                log "$RED" "Falha ao instalar jq!"
                exit 1
            }
        fi
        
        # Verificar se o arquivo de configuração existe
        if [[ ! -f "$CONFIG_FILE" ]]; then
            log "$RED" "Arquivo de configuracao nao encontrado: $CONFIG_FILE"
            exit 1
        fi
        
        # Verificar se o JSON é válido
        if ! jq . "$CONFIG_FILE" > /dev/null 2>&1; then
            log "$RED" "Arquivo de configuracao JSON invalido!"
            exit 1
        fi
        
        # Extrair valores com jq
        SWAPSIZE_GiB=$(jq -r '.swap_gib // 8' "$CONFIG_FILE")
        LUKS_PASSWORD=$(jq -r '.luks_root_password // ""' "$CONFIG_FILE")
        
        # Validar valores
        if [[ -z "$LUKS_PASSWORD" ]] || [[ "$LUKS_PASSWORD" == "null" ]]; then
            log "$RED" "Senha LUKS nao encontrada no arquivo de configuracao!"
            exit 1
        fi
        
        if ! [[ "$SWAPSIZE_GiB" =~ ^[0-9]+$ ]]; then
            log "$RED" "Tamanho de swap invalido no arquivo de configuracao!"
            exit 1
        fi
        
        log "$GREEN" "Configuracao carregada: SWAP=${SWAPSIZE_GiB}GB"
        
    else
        echo -e "${YELLOW}Tamanho do swap em GB (padrao 8):${NC}"
        read -r swap
        SWAPSIZE_GiB="${swap:-8}"
        
        # Validar entrada
        if ! [[ "$SWAPSIZE_GiB" =~ ^[0-9]+$ ]]; then
            log "$RED" "Tamanho de swap invalido!"
            exit 1
        fi
        
        while true; do
            echo -e "${YELLOW}Senha para criptografia LUKS:${NC}"
            read -rs LUKS_PASSWORD
            echo
            echo -e "${YELLOW}Confirme a senha:${NC}"
            read -rs LUKS_PASSWORD_CONFIRM
            echo
            
            if [[ "$LUKS_PASSWORD" != "$LUKS_PASSWORD_CONFIRM" ]]; then
                echo -e "${RED}Senhas nao coincidem!${NC}"
                continue
            fi
            
            if [[ ${#LUKS_PASSWORD} -lt 8 ]]; then
                echo -e "${RED}Senha muito curta! Use pelo menos 8 caracteres.${NC}"
                continue
            fi
            
            break
        done
    fi
}

check_disk_mounted() {
    if mount | grep -q "$DISCO_PRINCIPAL"; then
        log "$RED" "Disco $DISCO_PRINCIPAL esta montado! Desmonte primeiro."
        exit 1
    fi
}

secure_wipe() {
    local device="$1"
    log "$YELLOW" "Limpando disco de forma segura..."
    
    # Tentar blkdiscard primeiro (para SSDs)
    if command -v blkdiscard &>/dev/null; then
        if blkdiscard -f "$device" 2>/dev/null; then
            log "$GREEN" "Secure erase via TRIM concluido"
            return
        fi
    fi
    
    # Fallback para wipefs
    wipefs -af "$device" 2>/dev/null || true
    
    # Zerar primeiros e ultimos setores
    dd if=/dev/zero of="$device" bs=512 count=2048 2>/dev/null || true
    dd if=/dev/zero of="$device" bs=512 count=2048 seek=$(( $(blockdev --getsz "$device") - 2048 )) 2>/dev/null || true
}

partition_disk() {
    log "$BLUE" "Particionando $DISCO_PRINCIPAL..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando particionamento"; return; }
    
    check_disk_mounted
    secure_wipe "$DISCO_PRINCIPAL"
    
    partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
    sleep 1
    
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Criando tabela de particoes GPT (UEFI)..."
        parted -s "$DISCO_PRINCIPAL" \
            mklabel gpt \
            mkpart ESP fat32 1MiB 513MiB \
            set 1 esp on \
            mkpart BOOT ext4 513MiB 1537MiB \
            mkpart SWAP linux-swap 1537MiB $((1537 + SWAPSIZE_GiB * 1024))MiB \
            mkpart ROOT $((1537 + SWAPSIZE_GiB * 1024))MiB 100%
    else
        log "$BLUE" "Criando tabela de particoes MBR (BIOS)..."
        parted -s "$DISCO_PRINCIPAL" \
            mklabel msdos \
            mkpart primary ext4 1MiB 1025MiB \
            set 1 boot on \
            mkpart primary linux-swap 1025MiB $((1025 + SWAPSIZE_GiB * 1024))MiB \
            mkpart primary $((1025 + SWAPSIZE_GiB * 1024))MiB 100%
    fi
    
    sleep 2
    partprobe "$DISCO_PRINCIPAL"
    sleep 1
    
    # Detectar particoes corretamente
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
    
    # Verificar se as particoes foram criadas
    for part in $BOOT_PART $SWAP_PART $ROOT_PART; do
        if [[ ! -b "$part" ]]; then
            log "$RED" "Erro: Particao $part nao foi criada!"
            exit 1
        fi
    done
    
    if [[ "$BOOT_MODE" == "UEFI" ]] && [[ ! -b "$ESP_PART" ]]; then
        log "$RED" "Erro: Particao ESP $ESP_PART nao foi criada!"
        exit 1
    fi
    
    log "$GREEN" "Particoes criadas com sucesso"
}

create_luks() {
    log "$BLUE" "Criando volume LUKS no root..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando LUKS"; return; }
    
    # Ajustar memoria PBKDF baseado na RAM disponivel
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
    
    log "$GREEN" "LUKS criado e aberto com sucesso (UUID: $ROOT_UUID)"
}

create_filesystems() {
    log "$BLUE" "Criando sistemas de arquivos..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando formatacao"; return; }
    
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
    
    # Obter UUID do swap APOS criar o filesystem
    SWAP_UUID=$(blkid -s UUID -o value "$SWAP_PART")
    
    if [[ -z "$SWAP_UUID" ]]; then
        log "$YELLOW" "Aviso: Nao foi possivel obter UUID do swap"
        SWAP_UUID="PENDING"
    else
        log "$GREEN" "Swap UUID: $SWAP_UUID"
    fi
    
    # Root (Btrfs)
    log "$BLUE" "Formatando root com Btrfs..."
    mkfs.btrfs -L ROOT /dev/mapper/cryptroot || { log "$RED" "Erro ao formatar root!"; exit 1; }
    
    # Montar e criar subvolumes
    mount /dev/mapper/cryptroot /mnt || { log "$RED" "Erro ao montar root!"; exit 1; }
    
    log "$BLUE" "Criando subvolumes Btrfs..."
    for subvol in @ @home @snapshots @var @log @cache; do
        btrfs subvolume create /mnt/$subvol || { log "$RED" "Erro ao criar subvolume $subvol!"; exit 1; }
        log "$GREEN" "  Subvolume criado: $subvol"
    done
    
    umount /mnt
    
    # Remontar com subvolume @
    log "$BLUE" "Montando sistema de arquivos final..."
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
export ESP_PART="${ESP_PART:-}"
export BOOT_PART="$BOOT_PART"
export SWAP_PART="$SWAP_PART"
export ROOT_PART="$ROOT_PART"
export ROOT_UUID="$ROOT_UUID"
export SWAP_UUID="$SWAP_UUID"
export SWAPSIZE_GiB="$SWAPSIZE_GiB"
ENV
    log "$GREEN" "Variaveis de ambiente atualizadas"
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 2: DISCO PRINCIPAL ==="
    
    check_commands
    get_configuration
    
    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}ATENCAO: SERA FORMATADO: $DISCO_PRINCIPAL${NC}"
        echo -e "${RED}TODOS OS DADOS SERAO PERDIDOS!${NC}"
        echo -e "${RED}Digite CONFIRM para continuar:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operacao cancelada"; exit 0; }
    fi
    
    partition_disk
    create_luks
    create_filesystems
    update_env
    
    log "$GREEN" "Fase 2 concluida! Proximo: ./fase3-disco-auxiliar.sh (opcional) ou ./fase4-base-system.sh"
}

main
EOF