#!/bin/bash
# fase2-disco-principal.sh - Particionamento e criptografia do disco principal
# VERSÃO TOTALMENTE CORRIGIDA - Resolve problemas de montagem e ordem de criação
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
    local cmds=("cryptsetup" "parted" "mkfs.btrfs" "mkfs.ext4" "mkfs.vfat" "btrfs" "blkid" "wipefs" "partprobe" "mkswap" "lsblk" "dmsetup" "fuser")
    local missing=()
    
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessarios nao encontrados: ${missing[*]}"
        log "$YELLOW" "Instale com: pacman -S cryptsetup parted btrfs-progs dosfstools util-linux lvm2 psmisc"
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

check_and_close_luks() {
    local luks_name="$1"
    
    if [[ -b "/dev/mapper/$luks_name" ]]; then
        log "$YELLOW" "Volume LUKS '$luks_name' ja existe. Fechando..."
        
        # Tentar desmontar primeiro
        if mount | grep -q "/dev/mapper/$luks_name"; then
            log "$YELLOW" "  Desmontando volumes montados em /dev/mapper/$luks_name..."
            umount -R /mnt 2>/dev/null || true
            sleep 1
        fi
        
        # Fechar o volume LUKS
        if cryptsetup close "$luks_name" 2>/dev/null; then
            log "$GREEN" "  Volume LUKS '$luks_name' fechado com sucesso"
        else
            # Se falhou, tentar forçar
            log "$YELLOW" "  Tentando fechar forcadamente..."
            dmsetup remove -f "$luks_name" 2>/dev/null || true
            sleep 1
            
            # Verificar se foi fechado
            if [[ -b "/dev/mapper/$luks_name" ]]; then
                log "$RED" "  Erro: Nao foi possivel fechar o volume LUKS '$luks_name'"
                log "$YELLOW" "  Tente executar manualmente:"
                log "$YELLOW" "    umount -R /mnt"
                log "$YELLOW" "    cryptsetup close $luks_name"
                log "$YELLOW" "    dmsetup remove $luks_name"
                exit 1
            fi
        fi
    fi
}

cleanup_disk() {
    local device="$1"
    log "$YELLOW" "Limpando completamente o disco $device..."
    
    # 1. Desmontar /mnt e seus submounts primeiro
    if mount | grep -q "^.*on /mnt"; then
        log "$BLUE" "Desmontando /mnt e submounts..."
        umount -R /mnt 2>/dev/null || true
        sleep 1
    fi
    
    # 2. Fechar volume cryptroot se existir
    check_and_close_luks "cryptroot"
    
    # 3. Desmontar todas as partições do disco
    log "$BLUE" "Desmontando particoes do disco..."
    for mount_point in $(mount | grep "^${device}" | awk '{print $3}'); do
        log "$YELLOW" "  Desmontando $mount_point..."
        umount -f "$mount_point" 2>/dev/null || true
    done
    
    # 4. Fechar todos os volumes LUKS relacionados ao disco
    log "$BLUE" "Fechando volumes LUKS relacionados..."
    for luks_dev in $(dmsetup ls --target crypt | awk '{print $1}'); do
        if cryptsetup status "$luks_dev" 2>/dev/null | grep -q "${device}"; then
            log "$YELLOW" "  Fechando volume LUKS: $luks_dev..."
            cryptsetup close "$luks_dev" 2>/dev/null || true
        fi
    done
    
    # 5. Desativar swap se estiver no disco
    log "$BLUE" "Desativando swap..."
    for swap_part in $(swapon -s | grep "^${device}" | awk '{print $1}'); do
        log "$YELLOW" "  Desativando swap em $swap_part..."
        swapoff "$swap_part" 2>/dev/null || true
    done
    
    # 6. Remover LVM se existir
    log "$BLUE" "Removendo volumes LVM..."
    if command -v vgchange &>/dev/null; then
        vgchange -an 2>/dev/null || true
    fi
    
    # 7. Limpar device mapper forçadamente
    log "$BLUE" "Limpando device mapper..."
    for dm_dev in $(dmsetup ls --target crypt | awk '{print $1}'); do
        dmsetup remove -f "$dm_dev" 2>/dev/null || true
    done
    
    # 8. Terminar processos usando o disco
    log "$BLUE" "Terminando processos usando o disco..."
    if command -v fuser &>/dev/null; then
        fuser -km "$device" 2>/dev/null || true
    fi
    
    # 9. Sincronizar e aguardar
    sync
    sleep 2
    
    # 10. Forçar kernel a reler tabela de partições vazia
    log "$BLUE" "Limpando tabela de particoes..."
    dd if=/dev/zero of="$device" bs=512 count=34 2>/dev/null || true
    dd if=/dev/zero of="$device" bs=512 count=34 seek=$(( $(blockdev --getsz "$device") - 34 )) 2>/dev/null || true
    
    # 11. Informar kernel sobre mudanças
    partprobe "$device" 2>/dev/null || true
    sleep 1
    
    # 12. Verificação final
    if [[ -b "/dev/mapper/cryptroot" ]]; then
        log "$RED" "AVISO: cryptroot ainda existe apos limpeza!"
        log "$YELLOW" "Tentando remocao forcada final..."
        dmsetup remove -f cryptroot 2>/dev/null || true
        sleep 1
    fi
    
    log "$GREEN" "Limpeza do disco concluida"
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
    if command -v blkdiscard &>/dev/null && [[ "$DRY_RUN" != "true" ]]; then
        if blkdiscard -f "$device" 2>/dev/null; then
            log "$GREEN" "Secure erase via TRIM concluido"
            return
        fi
    fi
    
    # Fallback para wipefs
    wipefs -af "$device" 2>/dev/null || true
    
    # Zerar primeiros e ultimos setores
    dd if=/dev/zero of="$device" bs=512 count=2048 status=none 2>/dev/null || true
    dd if=/dev/zero of="$device" bs=512 count=2048 seek=$(( $(blockdev --getsz "$device") - 2048 )) status=none 2>/dev/null || true
}

partition_disk() {
    log "$BLUE" "Particionando $DISCO_PRINCIPAL..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando particionamento"; return; }
    
    # IMPORTANTE: Limpar completamente o disco antes de particionar
    cleanup_disk "$DISCO_PRINCIPAL"
    
    # Limpar de forma segura
    secure_wipe "$DISCO_PRINCIPAL"
    
    # Aguardar kernel processar mudanças
    sleep 2
    
    # Criar nova tabela de partições com tratamento de erro
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Criando tabela de particoes GPT (UEFI)..."
        
        # Criar tabela GPT primeiro
        if ! parted -s "$DISCO_PRINCIPAL" mklabel gpt; then
            log "$RED" "Erro ao criar tabela GPT!"
            exit 1
        fi
        
        # Criar partições uma por vez com verificação
        log "$BLUE" "Criando particao ESP..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart ESP fat32 1MiB 513MiB; then
            log "$RED" "Erro ao criar particao ESP!"
            exit 1
        fi
        parted -s "$DISCO_PRINCIPAL" set 1 esp on
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
        
        log "$BLUE" "Criando particao BOOT..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart BOOT ext4 513MiB 1537MiB; then
            log "$RED" "Erro ao criar particao BOOT!"
            exit 1
        fi
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
        
        log "$BLUE" "Criando particao SWAP..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart SWAP linux-swap 1537MiB $((1537 + SWAPSIZE_GiB * 1024))MiB; then
            log "$RED" "Erro ao criar particao SWAP!"
            exit 1
        fi
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
        
        log "$BLUE" "Criando particao ROOT..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart ROOT $((1537 + SWAPSIZE_GiB * 1024))MiB 100%; then
            log "$RED" "Erro ao criar particao ROOT!"
            exit 1
        fi
        
    else
        log "$BLUE" "Criando tabela de particoes MBR (BIOS)..."
        
        # Criar tabela MBR primeiro
        if ! parted -s "$DISCO_PRINCIPAL" mklabel msdos; then
            log "$RED" "Erro ao criar tabela MBR!"
            exit 1
        fi
        
        # Criar partições uma por vez
        log "$BLUE" "Criando particao BOOT..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart primary ext4 1MiB 1025MiB; then
            log "$RED" "Erro ao criar particao BOOT!"
            exit 1
        fi
        parted -s "$DISCO_PRINCIPAL" set 1 boot on
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
        
        log "$BLUE" "Criando particao SWAP..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart primary linux-swap 1025MiB $((1025 + SWAPSIZE_GiB * 1024))MiB; then
            log "$RED" "Erro ao criar particao SWAP!"
            exit 1
        fi
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
        
        log "$BLUE" "Criando particao ROOT..."
        if ! parted -s "$DISCO_PRINCIPAL" mkpart primary $((1025 + SWAPSIZE_GiB * 1024))MiB 100%; then
            log "$RED" "Erro ao criar particao ROOT!"
            exit 1
        fi
    fi
    
    # Forçar kernel a reler tabela de partições múltiplas vezes
    log "$BLUE" "Sincronizando tabela de particoes com kernel..."
    sync
    sleep 2
    
    for i in {1..3}; do
        partprobe "$DISCO_PRINCIPAL" 2>/dev/null || true
        sleep 1
    done
    
    # Usar blockdev para forçar releitura
    blockdev --rereadpt "$DISCO_PRINCIPAL" 2>/dev/null || true
    sleep 2
    
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
    
    # Aguardar dispositivos aparecerem
    log "$BLUE" "Aguardando dispositivos de particao..."
    local max_wait=10
    local wait_count=0
    
    while [[ $wait_count -lt $max_wait ]]; do
        local all_found=true
        
        for part in $BOOT_PART $SWAP_PART $ROOT_PART; do
            if [[ ! -b "$part" ]]; then
                all_found=false
                break
            fi
        done
        
        if [[ "$BOOT_MODE" == "UEFI" ]] && [[ ! -b "$ESP_PART" ]]; then
            all_found=false
        fi
        
        if [[ "$all_found" == "true" ]]; then
            break
        fi
        
        sleep 1
        ((wait_count++))
        log "$YELLOW" "  Aguardando... ($wait_count/$max_wait)"
    done
    
    # Verificar se as particoes foram criadas
    for part in $BOOT_PART $SWAP_PART $ROOT_PART; do
        if [[ ! -b "$part" ]]; then
            log "$RED" "Erro: Particao $part nao foi criada!"
            log "$YELLOW" "Tente executar: partprobe $DISCO_PRINCIPAL"
            log "$YELLOW" "Ou reinicie o sistema e execute novamente"
            exit 1
        fi
    done
    
    if [[ "$BOOT_MODE" == "UEFI" ]] && [[ ! -b "$ESP_PART" ]]; then
        log "$RED" "Erro: Particao ESP $ESP_PART nao foi criada!"
        exit 1
    fi
    
    log "$GREEN" "Particoes criadas com sucesso"
    
    # Listar partições para confirmação
    log "$BLUE" "Particoes criadas:"
    lsblk "$DISCO_PRINCIPAL"
}

create_luks() {
    log "$BLUE" "Criando volume LUKS no root..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando LUKS"; return; }
    
    # Verificar se a partição existe
    if [[ ! -b "$ROOT_PART" ]]; then
        log "$RED" "Erro: Particao $ROOT_PART nao existe!"
        exit 1
    fi
    
    # IMPORTANTE: Verificar e fechar volume LUKS existente
    check_and_close_luks "cryptroot"
    
    # Verificar se a partição já tem LUKS
    if cryptsetup isLuks "$ROOT_PART" 2>/dev/null; then
        log "$YELLOW" "Particao $ROOT_PART ja tem LUKS. Limpando..."
        wipefs -a "$ROOT_PART" 2>/dev/null || true
        sleep 1
    fi
    
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
    
    # Aguardar um momento antes de abrir
    sleep 1
    
    log "$BLUE" "Abrindo volume LUKS..."
    
    # Verificar novamente se cryptroot não existe antes de abrir
    if [[ -b /dev/mapper/cryptroot ]]; then
        log "$YELLOW" "cryptroot ainda existe. Removendo..."
        dmsetup remove -f cryptroot 2>/dev/null || true
        sleep 1
    fi
    
    echo -n "$LUKS_PASSWORD" | cryptsetup open "$ROOT_PART" cryptroot - || \
        { log "$RED" "Erro ao abrir volume LUKS!"; exit 1; }
    
    # Aguardar o dispositivo aparecer
    sleep 1
    
    # Verificar se o volume foi aberto
    if [[ ! -b /dev/mapper/cryptroot ]]; then
        log "$RED" "Erro: Volume LUKS nao foi aberto corretamente!"
        exit 1
    fi
    
    # Obter UUID do root LUKS
    ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
    
    if [[ -z "$ROOT_UUID" ]]; then
        log "$RED" "Erro ao obter UUID do root!"
        exit 1
    fi
    
    log "$GREEN" "LUKS criado e aberto com sucesso (UUID: $ROOT_UUID)"
}

# FUNÇÃO CORRIGIDA - Ordem de montagem dos subvolumes
create_filesystems() {
    log "$BLUE" "Criando sistemas de arquivos..."
    
    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Pulando formatacao"; return; }
    
    # Desmontar qualquer coisa em /mnt antes de começar
    if mount | grep -q " /mnt"; then
        log "$YELLOW" "Desmontando /mnt existente..."
        umount -R /mnt 2>/dev/null || true
        sleep 1
    fi
    
    # ESP (apenas UEFI)
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Formatando ESP..."
        wipefs -a "$ESP_PART" 2>/dev/null || true
        mkfs.vfat -F32 -n ESP "$ESP_PART" || { log "$RED" "Erro ao formatar ESP!"; exit 1; }
    fi
    
    # Boot
    log "$BLUE" "Formatando /boot..."
    wipefs -a "$BOOT_PART" 2>/dev/null || true
    mkfs.ext4 -L BOOT "$BOOT_PART" || { log "$RED" "Erro ao formatar boot!"; exit 1; }
    
    # Swap - IMPORTANTE: criar filesystem de swap antes de obter UUID
    log "$BLUE" "Formatando swap..."
    wipefs -a "$SWAP_PART" 2>/dev/null || true
    mkswap -L SWAP "$SWAP_PART" || { log "$RED" "Erro ao formatar swap!"; exit 1; }
    
    # Aguardar filesystem ser criado
    sleep 1
    sync
    
    # Obter UUID do swap APOS criar o filesystem
    SWAP_UUID=$(blkid -s UUID -o value "$SWAP_PART")
    
    if [[ -z "$SWAP_UUID" ]]; then
        log "$YELLOW" "Aviso: Tentando obter UUID do swap novamente..."
        sleep 2
        partprobe "$SWAP_PART" 2>/dev/null || true
        SWAP_UUID=$(blkid -s UUID -o value "$SWAP_PART")
        
        if [[ -z "$SWAP_UUID" ]]; then
            log "$YELLOW" "Aviso: Nao foi possivel obter UUID do swap"
            SWAP_UUID="PENDING"
        fi
    else
        log "$GREEN" "Swap UUID: $SWAP_UUID"
    fi
    
    # Root (Btrfs)
    log "$BLUE" "Formatando root com Btrfs..."
    
    # Verificar se cryptroot existe
    if [[ ! -b /dev/mapper/cryptroot ]]; then
        log "$RED" "Erro: /dev/mapper/cryptroot nao existe!"
        exit 1
    fi
    
    wipefs -a /dev/mapper/cryptroot 2>/dev/null || true
    mkfs.btrfs -L ROOT /dev/mapper/cryptroot || { log "$RED" "Erro ao formatar root!"; exit 1; }
    
    # Montar e criar subvolumes
    mount /dev/mapper/cryptroot /mnt || { log "$RED" "Erro ao montar root!"; exit 1; }
    
    log "$BLUE" "Criando subvolumes Btrfs..."
    for subvol in @ @home @snapshots @var @log @cache; do
        btrfs subvolume create /mnt/$subvol || { log "$RED" "Erro ao criar subvolume $subvol!"; exit 1; }
        log "$GREEN" "  Subvolume criado: $subvol"
    done
    
    umount /mnt
    sleep 1
    
    # Remontar com subvolume @
    log "$BLUE" "Montando sistema de arquivos final..."
    mount -o subvol=@,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt || \
        { log "$RED" "Erro ao montar subvolume @!"; exit 1; }
    
    # Criar pontos de montagem ANTES de montar os subvolumes
    log "$BLUE" "Criando pontos de montagem..."
    mkdir -p /mnt/{boot,home,var,.snapshots}
    
    # Montar subvolumes (ordem importante!)
    log "$BLUE" "Montando subvolumes..."
    
    # 1. Montar @home
    mount -o subvol=@home,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/home || \
        { log "$RED" "Erro ao montar subvolume @home!"; exit 1; }
    log "$GREEN" "  Montado: @home em /mnt/home"
    
    # 2. Montar @var
    mount -o subvol=@var,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var || \
        { log "$RED" "Erro ao montar subvolume @var!"; exit 1; }
    log "$GREEN" "  Montado: @var em /mnt/var"
    
    # 3. IMPORTANTE: Criar diretórios DEPOIS de montar @var
    log "$BLUE" "Criando subdiretorios em /mnt/var..."
    mkdir -p /mnt/var/{log,cache}
    
    # 4. Agora montar @log e @cache
    mount -o subvol=@log,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/log || \
        { log "$RED" "Erro ao montar subvolume @log!"; exit 1; }
    log "$GREEN" "  Montado: @log em /mnt/var/log"
    
    mount -o subvol=@cache,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/cache || \
        { log "$RED" "Erro ao montar subvolume @cache!"; exit 1; }
    log "$GREEN" "  Montado: @cache em /mnt/var/cache"
    
    # 5. Montar @snapshots
    mount -o subvol=@snapshots,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/.snapshots || \
        { log "$RED" "Erro ao montar subvolume @snapshots!"; exit 1; }
    log "$GREEN" "  Montado: @snapshots em /mnt/.snapshots"
    
    # 6. Montar boot
    log "$BLUE" "Montando particao /boot..."
    mount "$BOOT_PART" /mnt/boot || { log "$RED" "Erro ao montar /boot!"; exit 1; }
    log "$GREEN" "  Montado: /boot"
    
    # 7. Montar ESP (apenas UEFI)
    if [[ "$BOOT_MODE" == "UEFI" ]]; then
        log "$BLUE" "Montando particao ESP..."
        mkdir -p /mnt/boot/efi
        mount "$ESP_PART" /mnt/boot/efi || { log "$RED" "Erro ao montar ESP!"; exit 1; }
        log "$GREEN" "  Montado: ESP em /boot/efi"
    fi
    
    log "$GREEN" "Sistemas de arquivos criados e montados com sucesso"
    
    # Verificar montagens
    log "$BLUE" "Verificando montagens:"
    mount | grep "/mnt" | while read -r line; do
        log "$GREEN" "  $line"
    done
    
    # Verificar se todos os pontos críticos existem
    log "$BLUE" "Verificando estrutura de diretorios:"
    for dir in /mnt /mnt/boot /mnt/home /mnt/var /mnt/var/log /mnt/var/cache /mnt/.snapshots; do
        if [[ -d "$dir" ]]; then
            log "$GREEN" "  ✓ $dir existe"
        else
            log "$RED" "  ✗ $dir NAO existe!"
        fi
    done
}

update_env() {
    # Limpar variáveis antigas do arquivo se existirem
    if grep -q "^export ESP_PART=" "$ENV_FILE" 2>/dev/null; then
        log "$YELLOW" "Limpando variaveis antigas do arquivo de ambiente..."
        sed -i '/^export ESP_PART=/d' "$ENV_FILE"
        sed -i '/^export BOOT_PART=/d' "$ENV_FILE"
        sed -i '/^export SWAP_PART=/d' "$ENV_FILE"
        sed -i '/^export ROOT_PART=/d' "$ENV_FILE"
        sed -i '/^export ROOT_UUID=/d' "$ENV_FILE"
        sed -i '/^export SWAP_UUID=/d' "$ENV_FILE"
        sed -i '/^export SWAPSIZE_GiB=/d' "$ENV_FILE"
    fi
    
    # Adicionar novas variáveis
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

pre_flight_check() {
    log "$BLUE" "Executando verificacoes pre-voo..."
    
    # Verificar se já existe um sistema montado em /mnt
    if mount | grep -q " /mnt "; then
        log "$YELLOW" "Sistema ja montado em /mnt detectado"
        echo -e "${YELLOW}Deseja desmontar e continuar? (s/n):${NC}"
        
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            read -r resposta
            if [[ "$resposta" != "s" ]]; then
                log "$YELLOW" "Operacao cancelada pelo usuario"
                exit 0
            fi
        fi
        
        log "$YELLOW" "Desmontando sistema existente..."
        umount -R /mnt 2>/dev/null || true
        sleep 1
    fi
    
    # Verificar se cryptroot já existe
    if [[ -b /dev/mapper/cryptroot ]]; then
        log "$YELLOW" "Volume cryptroot detectado"
        check_and_close_luks "cryptroot"
    fi
    
    # Verificar espaço em disco
    local disk_size=$(blockdev --getsize64 "$DISCO_PRINCIPAL" 2>/dev/null || echo 0)
    local disk_size_gb=$((disk_size / 1024 / 1024 / 1024))
    local required_gb=$((10 + SWAPSIZE_GiB))  # Mínimo 10GB + swap
    
    if [[ $disk_size_gb -lt $required_gb ]]; then
        log "$RED" "Espaco insuficiente no disco!"
        log "$RED" "Disponivel: ${disk_size_gb}GB, Necessario: ${required_gb}GB"
        exit 1
    fi
    
    log "$GREEN" "Verificacoes pre-voo concluidas"
}

main() {
    setup_logging
    log "$BLUE" "=== FASE 2: DISCO PRINCIPAL ==="
    log "$BLUE" "Disco alvo: $DISCO_PRINCIPAL"
    
    check_commands
    get_configuration
    
    # Executar verificações antes de continuar
    pre_flight_check
    
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
    
    log "$GREEN" "=== FASE 2 CONCLUIDA COM SUCESSO ==="
    log "$GREEN" "Sistema de arquivos montado em /mnt"
    log "$GREEN" "Proximo: ./fase3-disco-auxiliar.sh (opcional) ou ./fase4-base-system.sh"
}

# Tratamento de erro global
trap 'log "$RED" "Erro na linha $LINENO. Codigo de saida: $?"' ERR

main "$@"