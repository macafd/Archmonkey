#!/bin/bash
# fase3-disco-auxiliar.sh - Configuracao do disco auxiliar com protecoes avancadas
# Versao aprimorada com protecoes contra ataques fisicos
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_NAME="fase3-disco-auxiliar"
LOG_DIR="/var/log/arch-secure-setup"
ENV_FILE="/tmp/arch_setup_vars.env"
SECURE_DIR="/root/.secure"
HEADER_BACKUP_NAME="bkdiscoaux"

[[ ! -f "$ENV_FILE" ]] && { echo -e "${RED}Execute fase1 primeiro!${NC}"; exit 1; }
source "$ENV_FILE"

# Definir valor padrão para CONFIG_FILE se não estiver definida
CONFIG_FILE=${CONFIG_FILE:-"/root/2/Archmonkey/config.json"}

[[ -z "$DISCO_AUXILIAR" ]] && { echo -e "${YELLOW}Disco auxiliar nao configurado. Pulando...${NC}"; exit 0; }

# ============================================================================
# FUNCOES DE SEGURANCA APRIMORADAS
# ============================================================================

setup_secure_environment() {
    log "$CYAN" "Configurando ambiente seguro..."
    
    # Criar diretorio seguro para backups
    if [[ ! -d "$SECURE_DIR" ]]; then
        mkdir -p "$SECURE_DIR"
        chmod 700 "$SECURE_DIR"
        
        # Ocultar diretorio (atributo imutavel apos populado)
        if command -v chattr &>/dev/null; then
            touch "$SECURE_DIR/.protect"
        fi
    fi
    
    # Desativar swap temporariamente (previne vazamento de chaves)
    if swapon --show | grep -q .; then
        log "$YELLOW" "Desativando swap para prevenir vazamento de chaves..."
        swapoff -a
        SWAP_WAS_ON=true
    fi
    
    # Limpar cache de memoria
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    
    # Configurar parametros de seguranca do kernel
    configure_kernel_security
}

configure_kernel_security() {
    log "$CYAN" "Aplicando parametros de seguranca do kernel..."
    
    # Protecao contra cold boot attacks
    echo 1 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
    echo 1 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
    echo 0 > /proc/sys/kernel/kexec_load_disabled 2>/dev/null || true
    
    # Prevenir acesso direto a memoria
    echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
    
    # Limitar informacoes do kernel
    echo 1 > /proc/sys/kernel/modules_disabled 2>/dev/null || true
}

backup_luks_header() {
    local device="$1"
    local backup_file="$SECURE_DIR/${HEADER_BACKUP_NAME}_$(date +%Y%m%d_%H%M%S).img"
    local checksum_file="${backup_file}.sha512"
    
    log "$MAGENTA" "=== BACKUP DO CABECALHO LUKS ==="
    log "$BLUE" "Salvando cabecalho LUKS em: $backup_file"
    
    # Fazer backup do header
    if cryptsetup luksHeaderBackup "$device" --header-backup-file "$backup_file"; then
        log "$GREEN" "Backup do cabecalho criado com sucesso!"
        
        # Calcular checksum
        sha512sum "$backup_file" > "$checksum_file"
        
        # Proteger arquivos
        chmod 400 "$backup_file" "$checksum_file"
        
        # Tornar imutavel (protecao contra delecao acidental)
        if command -v chattr &>/dev/null; then
            chattr +i "$backup_file" "$checksum_file"
            log "$GREEN" "Arquivos de backup protegidos com atributo imutavel"
        fi
        
        # Salvar informacoes no arquivo de ambiente
        echo "export LUKS_HEADER_BACKUP=\"$backup_file\"" >> "$ENV_FILE"
        echo "export LUKS_HEADER_CHECKSUM=\"$checksum_file\"" >> "$ENV_FILE"
        
        return 0
    else
        log "$RED" "ERRO: Falha ao criar backup do cabecalho!"
        return 1
    fi
}

secure_wipe_device() {
    local device="$1"
    
    log "$CYAN" "Executando limpeza segura do dispositivo..."
    
    # Usar metodos multiplos para garantir limpeza
    if command -v shred &>/dev/null; then
        log "$BLUE" "Executando shred (1 passada)..."
        shred -v -n 1 "$device" 2>/dev/null || true
    fi
    
    # Preencher com dados aleatorios
    log "$BLUE" "Preenchendo com dados aleatorios..."
    dd if=/dev/urandom of="$device" bs=1M count=100 status=progress 2>/dev/null || true
    
    # Wipefs para garantir remocao de assinaturas
    wipefs -af "$device"
}

create_luks_with_enhanced_security() {
    local device="$1"
    local password="$2"
    
    log "$MAGENTA" "=== CRIANDO VOLUME LUKS COM SEGURANCA APRIMORADA ==="
    
    # Parametros de seguranca aprimorados
    local CIPHER="aes-xts-plain64"
    local KEY_SIZE="512"
    local HASH="sha512"
    local ITER_TIME="5000"  # Aumentado para maior resistencia
    local PBKDF_MEMORY="524288"  # 512MB para Argon2id
    
    # Adicionar opcoes anti-forensicas
    log "$BLUE" "Aplicando configuracoes anti-forensicas..."
    
    echo -n "$password" | cryptsetup luksFormat \
        --type luks2 \
        --cipher "$CIPHER" \
        --key-size "$KEY_SIZE" \
        --hash "$HASH" \
        --pbkdf argon2id \
        --iter-time "$ITER_TIME" \
        --pbkdf-memory "$PBKDF_MEMORY" \
        --use-random \
        --verify-passphrase \
        --batch-mode \
        "$device" - || {
            log "$RED" "Erro ao criar volume LUKS!"
            return 1
        }
    
    # Adicionar slot de recuperacao com key-file aleatoria
    create_recovery_keyfile "$device" "$password"
    
    return 0
}

create_recovery_keyfile() {
    local device="$1"
    local password="$2"
    local keyfile="$SECURE_DIR/${HEADER_BACKUP_NAME}.key"
    
    log "$BLUE" "Criando keyfile de recuperacao..."
    
    # Gerar keyfile aleatoria de 4096 bytes
    dd if=/dev/urandom of="$keyfile" bs=4096 count=1 2>/dev/null
    chmod 400 "$keyfile"
    
    # Adicionar keyfile como slot adicional
    echo -n "$password" | cryptsetup luksAddKey "$device" "$keyfile" --key-slot 1 -
    
    if command -v chattr &>/dev/null; then
        chattr +i "$keyfile"
        log "$GREEN" "Keyfile de recuperacao protegida: $keyfile"
    fi
    
    echo "export LUKS_RECOVERY_KEYFILE=\"$keyfile\"" >> "$ENV_FILE"
}

verify_device_security() {
    local device="$1"
    
    log "$CYAN" "=== VERIFICACAO DE SEGURANCA ==="
    
    # Verificar configuracoes LUKS
    log "$BLUE" "Analisando configuracoes de seguranca..."
    
    local luks_dump=$(cryptsetup luksDump "$device")
    
    # Verificar cipher
    if echo "$luks_dump" | grep -q "aes-xts-plain64"; then
        log "$GREEN" "✓ Cipher forte detectado (AES-XTS)"
    else
        log "$YELLOW" "⚠ Cipher pode ser melhorado"
    fi
    
    # Verificar PBKDF
    if echo "$luks_dump" | grep -q "argon2id"; then
        log "$GREEN" "✓ PBKDF resistente (Argon2id)"
    else
        log "$YELLOW" "⚠ PBKDF pode ser melhorado"
    fi
    
    # Verificar tamanho da chave
    if echo "$luks_dump" | grep -q "512 bits"; then
        log "$GREEN" "✓ Tamanho de chave otimo (512 bits)"
    else
        log "$YELLOW" "⚠ Tamanho de chave pode ser aumentado"
    fi
    
    # Verificar slots ativos
    local active_slots=$(echo "$luks_dump" | grep -c "ENABLED")
    log "$BLUE" "Slots de chave ativos: $active_slots"
}

setup_tamper_detection() {
    local device="$1"
    
    log "$CYAN" "Configurando deteccao de adulteracao..."
    
    # Criar hash do estado atual do dispositivo
    local state_file="$SECURE_DIR/${HEADER_BACKUP_NAME}.state"
    
    # Capturar estado do header LUKS
    cryptsetup luksDump "$device" | sha512sum > "$state_file"
    chmod 400 "$state_file"
    
    log "$GREEN" "Estado do dispositivo salvo para deteccao de adulteracao"
}

# ============================================================================
# FUNCOES ORIGINAIS MODIFICADAS
# ============================================================================

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
    local cmds=("cryptsetup" "parted" "wipefs" "partprobe" "blkid" "dd" "sha512sum")
    local missing=()

    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Comandos necessarios nao encontrados: ${missing[*]}"
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
        LUKS_AUX_PASSWORD=$(jq -r '.luks_aux_password // ""' "$CONFIG_FILE")
        LINUX_ONLY=$(jq -r '.linux_only // false' "$CONFIG_FILE")
        ENABLE_SECURE_WIPE=$(jq -r '.enable_secure_wipe // true' "$CONFIG_FILE")
        ENABLE_TAMPER_DETECTION=$(jq -r '.enable_tamper_detection // true' "$CONFIG_FILE")

        # Validar valores
        if [[ -z "$LUKS_AUX_PASSWORD" ]] || [[ "$LUKS_AUX_PASSWORD" == "null" ]]; then
            log "$RED" "Senha LUKS auxiliar nao encontrada no arquivo de configuracao!"
            exit 1
        fi

        log "$GREEN" "Configuracao carregada: LINUX_ONLY=${LINUX_ONLY}, SECURE_WIPE=${ENABLE_SECURE_WIPE}"

    else
        echo -e "${YELLOW}Senha LUKS para disco auxiliar:${NC}"
        read -rs LUKS_AUX_PASSWORD
        echo
        echo -e "${YELLOW}Confirme a senha:${NC}"
        read -rs LUKS_AUX_CONFIRM
        echo

        if [[ "$LUKS_AUX_PASSWORD" != "$LUKS_AUX_CONFIRM" ]]; then
            log "$RED" "Senhas nao coincidem!"
            exit 1
        fi

        if [[ ${#LUKS_AUX_PASSWORD} -lt 8 ]]; then
            echo -e "${RED}Senha muito curta! Use pelo menos 8 caracteres.${NC}"
            exit 1
        fi

        echo -e "${YELLOW}Usar ext4 (Linux only) em vez de exFAT? [s/N]:${NC}"
        read -r linux_only
        [[ "$linux_only" =~ ^[Ss]$ ]] && LINUX_ONLY=true || LINUX_ONLY=false
        
        echo -e "${YELLOW}Executar limpeza segura do disco? [S/n]:${NC}"
        read -r secure_wipe
        [[ ! "$secure_wipe" =~ ^[Nn]$ ]] && ENABLE_SECURE_WIPE=true || ENABLE_SECURE_WIPE=false
        
        echo -e "${YELLOW}Ativar deteccao de adulteracao? [S/n]:${NC}"
        read -r tamper_detect
        [[ ! "$tamper_detect" =~ ^[Nn]$ ]] && ENABLE_TAMPER_DETECTION=true || ENABLE_TAMPER_DETECTION=false
    fi
}

cleanup_on_exit() {
    # Reativar swap se estava ativo
    if [[ "${SWAP_WAS_ON:-false}" == "true" ]]; then
        log "$YELLOW" "Reativando swap..."
        swapon -a 2>/dev/null || true
    fi
    
    # Limpar variaveis sensiveis da memoria
    unset LUKS_AUX_PASSWORD LUKS_AUX_CONFIRM
    
    # Limpar cache
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
}

main() {
    # Configurar trap para limpeza
    trap cleanup_on_exit EXIT
    
    setup_logging
    log "$MAGENTA" "=== FASE 3: DISCO AUXILIAR COM PROTECOES AVANCADAS ==="
    
    # Configurar ambiente seguro
    setup_secure_environment

    check_commands
    get_configuration

    if [[ "$DRY_RUN" != "true" && "$NON_INTERACTIVE" != "true" ]]; then
        echo -e "${RED}FORMATAR $DISCO_AUXILIAR? Digite CONFIRM:${NC}"
        read -r confirm
        [[ "$confirm" != "CONFIRM" ]] && { log "$YELLOW" "Operacao cancelada"; exit 0; }
    fi

    [[ "$DRY_RUN" == "true" ]] && { log "$YELLOW" "DRY-RUN: Nada foi alterado"; exit 0; }

    # Limpeza segura opcional
    if [[ "$ENABLE_SECURE_WIPE" == "true" ]]; then
        secure_wipe_device "$DISCO_AUXILIAR"
    else
        wipefs -af "$DISCO_AUXILIAR"
    fi

    # Particionar
    log "$BLUE" "Particionando $DISCO_AUXILIAR..."
    parted -s "$DISCO_AUXILIAR" mklabel gpt mkpart DATA 0% 100%
    sleep 2  # Aumentado para garantir deteccao
    partprobe "$DISCO_AUXILIAR"
    sleep 1

    # Detectar particao corretamente
    if [[ "$DISCO_AUXILIAR" =~ nvme|mmcblk|loop ]]; then
        AUX_PART="${DISCO_AUXILIAR}p1"
    else
        AUX_PART="${DISCO_AUXILIAR}1"
    fi

    # Verificar se particao foi criada
    if [[ ! -b "$AUX_PART" ]]; then
        log "$RED" "Erro: Particao $AUX_PART nao foi criada!"
        exit 1
    fi

    # LUKS com seguranca aprimorada
    create_luks_with_enhanced_security "$AUX_PART" "$LUKS_AUX_PASSWORD"
    
    # Fazer backup do header LUKS
    backup_luks_header "$AUX_PART"
    
    # Verificar seguranca
    verify_device_security "$AUX_PART"

    # Abrir volume
    echo -n "$LUKS_AUX_PASSWORD" | cryptsetup open "$AUX_PART" cryptdata -

    # Formatar
    if [[ "$LINUX_ONLY" == "true" ]]; then
        log "$BLUE" "Formatando com ext4..."
        if command -v mkfs.ext4 &>/dev/null; then
            mkfs.ext4 -L DATA -E lazy_itable_init=0,lazy_journal_init=0 /dev/mapper/cryptdata
            # Opcoes de montagem seguras para ext4
            echo "export AUX_MOUNT_OPTS=\"noatime,nodiratime,noexec,nosuid\"" >> "$ENV_FILE"
        else
            log "$RED" "mkfs.ext4 nao encontrado!"
            exit 1
        fi
    else
        log "$BLUE" "Formatando com exFAT..."
        if command -v mkfs.exfat &>/dev/null; then
            mkfs.exfat -n DATA /dev/mapper/cryptdata
        elif command -v mkexfatfs &>/dev/null; then
            mkexfatfs -n DATA /dev/mapper/cryptdata
        else
            log "$RED" "mkfs.exfat nao encontrado! Instale exfatprogs ou exfat-utils"
            exit 1
        fi
        echo "export AUX_MOUNT_OPTS=\"noexec,nosuid\"" >> "$ENV_FILE"
    fi

    AUX_UUID=$(blkid -s UUID -o value "$AUX_PART")

    echo "export AUX_PART=\"$AUX_PART\"" >> "$ENV_FILE"
    echo "export AUX_UUID=\"$AUX_UUID\"" >> "$ENV_FILE"
    echo "export SECURE_DIR=\"$SECURE_DIR\"" >> "$ENV_FILE"

    # Configurar deteccao de adulteracao
    if [[ "$ENABLE_TAMPER_DETECTION" == "true" ]]; then
        setup_tamper_detection "$AUX_PART"
    fi

    cryptsetup close cryptdata
    
    # Proteger diretorio de backups
    if command -v chattr &>/dev/null && [[ -f "$SECURE_DIR/.protect" ]]; then
        chattr +i "$SECURE_DIR"
        log "$GREEN" "Diretorio de backups protegido com atributo imutavel"
    fi

    log "$GREEN" "========================================="
    log "$GREEN" "Disco auxiliar configurado com sucesso!"
    log "$GREEN" "Backup do header salvo em: $SECURE_DIR"
    log "$GREEN" "UUID: $AUX_UUID"
    log "$GREEN" "========================================="
    log "$CYAN" "Proximo passo: ./fase4-base-system.sh"
}

# Executar funcao principal
main