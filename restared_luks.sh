#!/bin/bash
# ============================================================================
# LUKS Header Recovery Tool - Ferramenta Independente de Recuperação
# Versão: 2.0 - Recuperação segura de cabeçalhos LUKS
# ============================================================================

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Variáveis globais
SCRIPT_VERSION="2.0"
TEMP_DIR="/tmp/luks_recovery_$$"
LOG_FILE="/tmp/luks_recovery_$(date +%Y%m%d_%H%M%S).log"
SELECTED_BACKUP=""
SELECTED_DEVICE=""
CHECKSUM_FILE=""
FORCE_MODE=false
VERIFY_ONLY=false

# ============================================================================
# FUNÇÕES UTILITÁRIAS
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          LUKS HEADER RECOVERY TOOL v${SCRIPT_VERSION}                 ║"
    echo "║         Ferramenta de Recuperação de Cabeçalho LUKS       ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    local level="$1"
    shift
    echo -e "${level}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"
}

error_exit() {
    log "$RED" "ERRO: $1"
    cleanup
    exit 1
}

cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "Este script deve ser executado como root!"
    fi
}

check_dependencies() {
    local deps=("cryptsetup" "blkid" "lsblk" "sha512sum" "file")
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$RED" "Dependências faltando: ${missing[*]}"
        log "$YELLOW" "Instale com: apt/yum/pacman install ${missing[*]}"
        exit 1
    fi
}

# ============================================================================
# FUNÇÕES DE DETECÇÃO
# ============================================================================

detect_usb_devices() {
    log "$CYAN" "Detectando dispositivos USB montados..."
    
    local usb_mounts=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            usb_mounts+=("$line")
        fi
    done < <(lsblk -o NAME,MOUNTPOINT,SIZE,TYPE,TRAN | grep -E "usb|USB" | grep -E "part|disk" | awk '{if($2 && $2!="MOUNTPOINT") print $2}' | grep -v "^$")
    
    # Adicionar outros pontos de montagem comuns
    for mount in /media/* /mnt/* /run/media/$USER/* ; do
        if [[ -d "$mount" ]] && mountpoint -q "$mount" 2>/dev/null; then
            usb_mounts+=("$mount")
        fi
    done
    
    # Remover duplicatas
    local unique_mounts=($(printf "%s\n" "${usb_mounts[@]}" | sort -u))
    
    if [[ ${#unique_mounts[@]} -eq 0 ]]; then
        log "$YELLOW" "Nenhum dispositivo USB detectado automaticamente."
        log "$BLUE" "Você pode inserir o caminho manualmente."
    else
        log "$GREEN" "Dispositivos USB encontrados:"
        for mount in "${unique_mounts[@]}"; do
            echo -e "${BLUE}  → $mount${NC}"
        done
    fi
    
    printf "%s\n" "${unique_mounts[@]}"
}

find_backup_files() {
    local search_path="$1"
    local backup_files=()
    
    log "$CYAN" "Procurando arquivos de backup em: $search_path"
    
    # Padrões de busca para backups LUKS
    local patterns=(
        "*.img"
        "*.luks"
        "*.header"
        "*backup*"
        "*bkdisco*"
        "*luks*backup*"
        "*header*backup*"
    )
    
    for pattern in "${patterns[@]}"; do
        while IFS= read -r file; do
            if [[ -f "$file" ]] && file "$file" 2>/dev/null | grep -q "LUKS"; then
                backup_files+=("$file")
            elif [[ -f "$file" ]] && [[ $(stat -c%s "$file") -eq 16777216 ]]; then
                # Tamanho típico de header LUKS2 (16MB)
                backup_files+=("$file")
            elif [[ -f "$file" ]] && [[ $(stat -c%s "$file") -eq 2097152 ]]; then
                # Tamanho típico de header LUKS1 (2MB)
                backup_files+=("$file")
            fi
        done < <(find "$search_path" -type f -iname "$pattern" 2>/dev/null)
    done
    
    # Remover duplicatas
    local unique_files=($(printf "%s\n" "${backup_files[@]}" | sort -u))
    
    if [[ ${#unique_files[@]} -gt 0 ]]; then
        log "$GREEN" "Arquivos de backup encontrados: ${#unique_files[@]}"
    fi
    
    printf "%s\n" "${unique_files[@]}"
}

detect_luks_devices() {
    log "$CYAN" "Detectando dispositivos com LUKS..."
    
    local luks_devices=()
    
    # Buscar todos os dispositivos de bloco
    while IFS= read -r device; do
        if cryptsetup isLuks "$device" 2>/dev/null; then
            local size=$(lsblk -b -n -o SIZE "$device" 2>/dev/null | head -1)
            local size_human=$(numfmt --to=iec-i --suffix=B "$size" 2>/dev/null || echo "$size")
            local model=$(lsblk -n -o MODEL "$device" 2>/dev/null | head -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
            
            luks_devices+=("$device|$size_human|$model")
        fi
    done < <(lsblk -n -p -o NAME,TYPE | grep -E "disk|part" | awk '{print $1}')
    
    if [[ ${#luks_devices[@]} -eq 0 ]]; then
        log "$YELLOW" "Nenhum dispositivo LUKS detectado!"
    else
        log "$GREEN" "Dispositivos LUKS encontrados:"
        for dev_info in "${luks_devices[@]}"; do
            IFS='|' read -r dev size model <<< "$dev_info"
            echo -e "${BLUE}  → $dev ${CYAN}[$size]${NC} ${YELLOW}$model${NC}"
        done
    fi
    
    printf "%s\n" "${luks_devices[@]}"
}

# ============================================================================
# FUNÇÕES DE SELEÇÃO INTERATIVA
# ============================================================================

select_backup_file() {
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}         SELEÇÃO DO ARQUIVO DE BACKUP${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}\n"
    
    # Detectar dispositivos USB
    local usb_mounts=($(detect_usb_devices))
    
    echo -e "${YELLOW}Opções de busca:${NC}"
    echo -e "${BLUE}1)${NC} Buscar em dispositivos USB detectados"
    echo -e "${BLUE}2)${NC} Buscar em diretório específico"
    echo -e "${BLUE}3)${NC} Inserir caminho completo do arquivo"
    echo -e "${BLUE}4)${NC} Buscar em /root/.secure (backup local)"
    echo
    
    read -p "Escolha uma opção [1-4]: " search_option
    
    local backup_files=()
    
    case $search_option in
        1)
            if [[ ${#usb_mounts[@]} -eq 0 ]]; then
                log "$RED" "Nenhum dispositivo USB detectado!"
                log "$YELLOW" "Conecte um pendrive e tente novamente."
                return 1
            fi
            
            echo -e "\n${CYAN}Selecione o dispositivo USB:${NC}"
            local i=1
            for mount in "${usb_mounts[@]}"; do
                local space_info=$(df -h "$mount" 2>/dev/null | tail -1 | awk '{print $2" usado:"$3" livre:"$4}')
                echo -e "${BLUE}$i)${NC} $mount ${YELLOW}[$space_info]${NC}"
                ((i++))
            done
            
            read -p "Escolha [1-${#usb_mounts[@]}]: " usb_choice
            
            if [[ $usb_choice -ge 1 && $usb_choice -le ${#usb_mounts[@]} ]]; then
                local selected_mount="${usb_mounts[$((usb_choice-1))]}"
                backup_files=($(find_backup_files "$selected_mount"))
            fi
            ;;
            
        2)
            read -p "Digite o caminho do diretório: " search_dir
            if [[ -d "$search_dir" ]]; then
                backup_files=($(find_backup_files "$search_dir"))
            else
                log "$RED" "Diretório não encontrado!"
                return 1
            fi
            ;;
            
        3)
            read -p "Digite o caminho completo do arquivo: " file_path
            if [[ -f "$file_path" ]]; then
                backup_files=("$file_path")
            else
                log "$RED" "Arquivo não encontrado!"
                return 1
            fi
            ;;
            
        4)
            if [[ -d "/root/.secure" ]]; then
                backup_files=($(find_backup_files "/root/.secure"))
            else
                log "$RED" "Diretório /root/.secure não encontrado!"
                return 1
            fi
            ;;
            
        *)
            log "$RED" "Opção inválida!"
            return 1
            ;;
    esac
    
    if [[ ${#backup_files[@]} -eq 0 ]]; then
        log "$RED" "Nenhum arquivo de backup encontrado!"
        return 1
    fi
    
    echo -e "\n${CYAN}Arquivos de backup encontrados:${NC}"
    local i=1
    for file in "${backup_files[@]}"; do
        local size=$(stat -c%s "$file" 2>/dev/null)
        local size_human=$(numfmt --to=iec-i --suffix=B "$size" 2>/dev/null || echo "$size")
        local date=$(stat -c%y "$file" 2>/dev/null | cut -d' ' -f1)
        echo -e "${BLUE}$i)${NC} $(basename "$file")"
        echo -e "   ${YELLOW}Caminho:${NC} $file"
        echo -e "   ${YELLOW}Tamanho:${NC} $size_human | ${YELLOW}Data:${NC} $date"
        
        # Verificar se existe checksum
        if [[ -f "${file}.sha512" ]]; then
            echo -e "   ${GREEN}✓ Arquivo de checksum encontrado${NC}"
        fi
        echo
        ((i++))
    done
    
    read -p "Selecione o arquivo [1-${#backup_files[@]}]: " file_choice
    
    if [[ $file_choice -ge 1 && $file_choice -le ${#backup_files[@]} ]]; then
        SELECTED_BACKUP="${backup_files[$((file_choice-1))]}"
        CHECKSUM_FILE="${SELECTED_BACKUP}.sha512"
        log "$GREEN" "Arquivo selecionado: $SELECTED_BACKUP"
        return 0
    else
        log "$RED" "Seleção inválida!"
        return 1
    fi
}

select_target_device() {
    echo -e "\n${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}         SELEÇÃO DO DISPOSITIVO ALVO${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}\n"
    
    local luks_devices=($(detect_luks_devices))
    
    if [[ ${#luks_devices[@]} -eq 0 ]]; then
        log "$YELLOW" "Nenhum dispositivo LUKS detectado automaticamente."
        echo -e "${YELLOW}Deseja inserir o caminho manualmente? [s/N]:${NC}"
        read -r manual_input
        
        if [[ "$manual_input" =~ ^[Ss]$ ]]; then
            read -p "Digite o caminho do dispositivo (ex: /dev/sda1): " device_path
            
            if [[ -b "$device_path" ]]; then
                SELECTED_DEVICE="$device_path"
                log "$GREEN" "Dispositivo selecionado: $SELECTED_DEVICE"
                return 0
            else
                log "$RED" "Dispositivo não encontrado ou não é um dispositivo de bloco!"
                return 1
            fi
        else
            return 1
        fi
    fi
    
    echo -e "${CYAN}Dispositivos LUKS disponíveis:${NC}\n"
    local i=1
    for dev_info in "${luks_devices[@]}"; do
        IFS='|' read -r dev size model <<< "$dev_info"
        echo -e "${BLUE}$i)${NC} $dev"
        echo -e "   ${YELLOW}Tamanho:${NC} $size"
        [[ -n "$model" ]] && echo -e "   ${YELLOW}Modelo:${NC} $model"
        
        # Mostrar informações LUKS
        local luks_version=$(cryptsetup luksDump "$dev" 2>/dev/null | grep "Version:" | awk '{print $2}')
        local uuid=$(cryptsetup luksDump "$dev" 2>/dev/null | grep "UUID:" | awk '{print $2}')
        [[ -n "$luks_version" ]] && echo -e "   ${YELLOW}LUKS:${NC} v$luks_version"
        [[ -n "$uuid" ]] && echo -e "   ${YELLOW}UUID:${NC} $uuid"
        echo
        ((i++))
    done
    
    read -p "Selecione o dispositivo [1-${#luks_devices[@]}]: " device_choice
    
    if [[ $device_choice -ge 1 && $device_choice -le ${#luks_devices[@]} ]]; then
        local selected_info="${luks_devices[$((device_choice-1))]}"
        SELECTED_DEVICE=$(echo "$selected_info" | cut -d'|' -f1)
        log "$GREEN" "Dispositivo selecionado: $SELECTED_DEVICE"
        return 0
    else
        log "$RED" "Seleção inválida!"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE VERIFICAÇÃO
# ============================================================================

verify_backup_integrity() {
    log "$CYAN" "Verificando integridade do backup..."
    
    if [[ ! -f "$SELECTED_BACKUP" ]]; then
        log "$RED" "Arquivo de backup não encontrado!"
        return 1
    fi
    
    # Verificar se é um header LUKS válido
    if ! file "$SELECTED_BACKUP" 2>/dev/null | grep -q "LUKS"; then
        log "$YELLOW" "AVISO: Arquivo pode não ser um header LUKS válido"
        
        # Verificar tamanho típico
        local size=$(stat -c%s "$SELECTED_BACKUP")
        if [[ $size -eq 16777216 ]] || [[ $size -eq 2097152 ]]; then
            log "$BLUE" "Tamanho do arquivo corresponde a um header LUKS"
        else
            log "$YELLOW" "Tamanho incomum para header LUKS: $(numfmt --to=iec-i --suffix=B $size)"
        fi
    fi
    
    # Verificar checksum se disponível
    if [[ -f "$CHECKSUM_FILE" ]]; then
        log "$BLUE" "Verificando checksum SHA-512..."
        
        # Criar diretório temporário
        mkdir -p "$TEMP_DIR"
        cp "$SELECTED_BACKUP" "$TEMP_DIR/"
        cp "$CHECKSUM_FILE" "$TEMP_DIR/"
        
        cd "$TEMP_DIR"
        if sha512sum -c "$(basename "$CHECKSUM_FILE")" &>/dev/null; then
            log "$GREEN" "✓ Integridade verificada com sucesso!"
            cd - >/dev/null
            return 0
        else
            log "$RED" "✗ Falha na verificação de integridade!"
            cd - >/dev/null
            
            if [[ "$FORCE_MODE" == "true" ]]; then
                log "$YELLOW" "Modo forçado ativado, continuando mesmo assim..."
                return 0
            else
                echo -e "${YELLOW}Deseja continuar mesmo assim? (ARRISCADO) [s/N]:${NC}"
                read -r continue_anyway
                [[ "$continue_anyway" =~ ^[Ss]$ ]] && return 0 || return 1
            fi
        fi
    else
        log "$YELLOW" "Arquivo de checksum não encontrado"
        log "$BLUE" "Não é possível verificar integridade automaticamente"
        
        if [[ "$VERIFY_ONLY" == "true" ]]; then
            return 1
        fi
        
        echo -e "${YELLOW}Continuar sem verificação de checksum? [s/N]:${NC}"
        read -r continue_no_check
        [[ "$continue_no_check" =~ ^[Ss]$ ]] && return 0 || return 1
    fi
}

analyze_device() {
    log "$CYAN" "Analisando dispositivo alvo..."
    
    if [[ ! -b "$SELECTED_DEVICE" ]]; then
        log "$RED" "Dispositivo não é um dispositivo de bloco válido!"
        return 1
    fi
    
    # Verificar se é LUKS
    if ! cryptsetup isLuks "$SELECTED_DEVICE" 2>/dev/null; then
        log "$YELLOW" "AVISO: Dispositivo não parece ter LUKS atualmente"
        echo -e "${YELLOW}Isso é esperado se o header está corrompido.${NC}"
        echo -e "${YELLOW}Continuar com a restauração? [s/N]:${NC}"
        read -r continue_restore
        [[ "$continue_restore" =~ ^[Ss]$ ]] || return 1
    else
        log "$GREEN" "✓ Dispositivo LUKS detectado"
        
        # Mostrar informações atuais
        echo -e "\n${CYAN}Informações atuais do dispositivo:${NC}"
        cryptsetup luksDump "$SELECTED_DEVICE" 2>/dev/null | head -20
        
        # Fazer backup do header atual antes de sobrescrever
        echo -e "\n${YELLOW}Deseja fazer backup do header atual antes de restaurar? [S/n]:${NC}"
        read -r backup_current
        
        if [[ ! "$backup_current" =~ ^[Nn]$ ]]; then
            local current_backup="/tmp/luks_header_current_$(date +%Y%m%d_%H%M%S).img"
            if cryptsetup luksHeaderBackup "$SELECTED_DEVICE" --header-backup-file "$current_backup"; then
                log "$GREEN" "Header atual salvo em: $current_backup"
            else
                log "$RED" "Falha ao fazer backup do header atual"
            fi
        fi
    fi
    
    return 0
}

# ============================================================================
# FUNÇÃO DE RESTAURAÇÃO
# ============================================================================

perform_restoration() {
    echo -e "\n${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${RED}            ⚠️  RESTAURAÇÃO DO HEADER ⚠️${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}\n"
    
    echo -e "${RED}${BOLD}ATENÇÃO: Esta operação irá:${NC}"
    echo -e "${YELLOW}• Sobrescrever o header LUKS atual de $SELECTED_DEVICE${NC}"
    echo -e "${YELLOW}• Usar o backup: $(basename "$SELECTED_BACKUP")${NC}"
    echo -e "${YELLOW}• Esta operação é IRREVERSÍVEL sem um backup do header atual${NC}"
    echo
    
    # Mostrar resumo
    echo -e "${CYAN}══════════════════ RESUMO ══════════════════${NC}"
    echo -e "${BLUE}Arquivo de Backup:${NC} $SELECTED_BACKUP"
    echo -e "${BLUE}Dispositivo Alvo:${NC} $SELECTED_DEVICE"
    echo -e "${BLUE}Tamanho do Backup:${NC} $(stat -c%s "$SELECTED_BACKUP" | numfmt --to=iec-i --suffix=B)"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo
    
    echo -e "${RED}${BOLD}Digite 'RESTAURAR' para confirmar a operação:${NC}"
    read -r confirmation
    
    if [[ "$confirmation" != "RESTAURAR" ]]; then
        log "$YELLOW" "Operação cancelada pelo usuário"
        return 1
    fi
    
    log "$MAGENTA" "Iniciando restauração..."
    
    # Executar restauração
    if cryptsetup luksHeaderRestore "$SELECTED_DEVICE" --header-backup-file "$SELECTED_BACKUP"; then
        log "$GREEN" "✓ Header LUKS restaurado com sucesso!"
        
        # Verificar restauração
        if cryptsetup isLuks "$SELECTED_DEVICE" 2>/dev/null; then
            log "$GREEN" "✓ Dispositivo LUKS verificado após restauração"
            
            echo -e "\n${CYAN}Novas informações do dispositivo:${NC}"
            cryptsetup luksDump "$SELECTED_DEVICE" 2>/dev/null | head -15
            
            echo -e "\n${GREEN}${BOLD}Restauração concluída com sucesso!${NC}"
            echo -e "${YELLOW}Você pode agora tentar desbloquear o dispositivo com:${NC}"
            echo -e "${BLUE}cryptsetup open $SELECTED_DEVICE <nome_do_mapeamento>${NC}"
            
            return 0
        else
            log "$RED" "AVISO: Não foi possível verificar LUKS após restauração"
            echo -e "${YELLOW}A restauração foi executada, mas a verificação falhou.${NC}"
            echo -e "${YELLOW}Isso pode indicar um problema com o backup ou dispositivo.${NC}"
            return 1
        fi
    else
        log "$RED" "✗ Falha na restauração do header!"
        echo -e "${RED}Possíveis causas:${NC}"
        echo -e "${YELLOW}• Arquivo de backup corrompido${NC}"
        echo -e "${YELLOW}• Dispositivo com problemas${NC}"
        echo -e "${YELLOW}• Incompatibilidade de versão LUKS${NC}"
        echo -e "${YELLOW}• Permissões insuficientes${NC}"
        return 1
    fi
}

# ============================================================================
# FUNÇÃO DE TESTE
# ============================================================================

test_restored_device() {
    echo -e "\n${CYAN}Deseja testar o dispositivo restaurado? [s/N]:${NC}"
    read -r test_device
    
    if [[ "$test_device" =~ ^[Ss]$ ]]; then
        log "$CYAN" "Testando dispositivo..."
        
        echo -e "${YELLOW}Digite a senha para desbloquear:${NC}"
        read -rs password
        echo
        
        local test_name="luks_test_$$"
        
        if echo -n "$password" | cryptsetup open "$SELECTED_DEVICE" "$test_name" -; then
            log "$GREEN" "✓ Dispositivo desbloqueado com sucesso!"
            
            # Mostrar informações
            if [[ -b "/dev/mapper/$test_name" ]]; then
                echo -e "\n${CYAN}Informações do dispositivo desbloqueado:${NC}"
                lsblk "/dev/mapper/$test_name" 2>/dev/null
                
                # Fechar dispositivo
                cryptsetup close "$test_name"
                log "$GREEN" "Dispositivo fechado após teste bem-sucedido"
            fi
        else
            log "$RED" "Falha ao desbloquear dispositivo"
            echo -e "${YELLOW}Verifique se a senha está correta${NC}"
        fi
    fi
}

# ============================================================================
# MODO DE EMERGÊNCIA
# ============================================================================

emergency_mode() {
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}            MODO DE EMERGÊNCIA ATIVADO${NC}"
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════${NC}\n"
    
    log "$YELLOW" "Executando em modo de emergência - verificações mínimas"
    
    read -p "Caminho do arquivo de backup: " SELECTED_BACKUP
    read -p "Dispositivo alvo (ex: /dev/sda1): " SELECTED_DEVICE
    
    if [[ ! -f "$SELECTED_BACKUP" ]]; then
        error_exit "Arquivo de backup não encontrado!"
    fi
    
    if [[ ! -b "$SELECTED_DEVICE" ]]; then
        error_exit "Dispositivo não encontrado!"
    fi
    
    echo -e "\n${RED}Restaurar SEM verificações de segurança?${NC}"
    echo -e "${RED}Digite 'EMERGENCIA' para confirmar:${NC}"
    read -r emergency_confirm
    
    if [[ "$emergency_confirm" == "EMERGENCIA" ]]; then
        if cryptsetup luksHeaderRestore "$SELECTED_DEVICE" --header-backup-file "$SELECTED_BACKUP"; then
            log "$GREEN" "Restauração de emergência concluída!"
        else
            log "$RED" "Falha na restauração de emergência!"
        fi
    fi
}

# ============================================================================
# MENU PRINCIPAL
# ============================================================================

show_menu() {
    echo -e "\n${CYAN}Selecione uma opção:${NC}"
    echo -e "${BLUE}1)${NC} Restauração Guiada (Recomendado)"
    echo -e "${BLUE}2)${NC} Verificar Integridade do Backup"
    echo -e "${BLUE}3)${NC} Modo de Emergência (Sem Verificações)"
    echo -e "${BLUE}4)${NC} Informações sobre Dispositivo LUKS"
    echo -e "${BLUE}5)${NC} Criar Backup do Header Atual"
    echo -e "${BLUE}0)${NC} Sair"
    echo
    read -p "Opção: " menu_choice
    
    case $menu_choice in
        1)
            if select_backup_file && select_target_device; then
                if verify_backup_integrity && analyze_device; then
                    if perform_restoration; then
                        test_restored_device
                    fi
                fi
            fi
            ;;
        2)
            VERIFY_ONLY=true
            if select_backup_file; then
                verify_backup_integrity && log "$GREEN" "Verificação concluída!"
            fi
            ;;
        3)
            emergency_mode
            ;;
        4)
            if select_target_device; then
                echo -e "\n${CYAN}Informações do dispositivo:${NC}"
                cryptsetup luksDump "$SELECTED_DEVICE" 2>/dev/null || log "$RED" "Não foi possível ler informações LUKS"
            fi
            ;;
        5)
            if select_target_device; then
                local backup_name="/tmp/luks_backup_$(date +%Y%m%d_%H%M%S).img"
                if cryptsetup luksHeaderBackup "$SELECTED_DEVICE" --header-backup-file "$backup_name"; then
                    sha512sum "$backup_name" > "${backup_name}.sha512"
                    log "$GREEN" "Backup criado: $backup_name"
                    log "$GREEN" "Checksum: ${backup_name}.sha512"
                else
                    log "$RED" "Falha ao criar backup"
                fi
            fi
            ;;
        0)
            log "$BLUE" "Saindo..."
            cleanup
            exit 0
            ;;
        *)
            log "$RED" "Opção inválida!"
            ;;
    esac
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Configurar trap para limpeza
    trap cleanup EXIT INT TERM
    
    # Limpar tela e mostrar banner
    clear
    print_banner
    
    # Verificações iniciais
    check_root
    check_dependencies
    
    log "$GREEN" "Sistema pronto para recuperação"
    log "$BLUE" "Log salvo em: $LOG_FILE"
    
    # Processar argumentos de linha de comando
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force|-f)
                FORCE_MODE=true
                log "$YELLOW" "Modo forçado ativado"
                shift
                ;;
            --emergency|-e)
                emergency_mode
                exit $?
                ;;
            --help|-h)
                echo "Uso: $0 [opções]"
                echo "Opções:"
                echo "  --force, -f      Modo forçado (ignora alguns avisos)"
                echo "  --emergency, -e  Modo de emergência"
                echo "  --help, -h       Mostra esta ajuda"
                exit 0
                ;;
            *)
                log "$RED" "Opção desconhecida: $1"
                shift
                ;;
        esac
    done
    
    # Loop do menu principal
    while true; do
        show_menu
    done
}

# ============================================================================
# EXECUTAR SCRIPT
# ============================================================================

main "$@"