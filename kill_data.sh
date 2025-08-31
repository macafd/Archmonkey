#!/bin/bash

#############################################
# Script de Formatação Segura de Discos
# Para Arch Linux Live
# Autor: Sistema Automatizado
# Versão: 2.0
#############################################

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Verificar se está rodando como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${BOLD}Este script precisa ser executado como root!${NC}"
        echo -e "${YELLOW}Use: sudo $0${NC}"
        exit 1
    fi
}

# Instalar dependências necessárias
install_dependencies() {
    echo -e "${CYAN}${BOLD}Verificando dependências...${NC}"
    
    DEPS=("pv" "dialog" "smartmontools" "hdparm")
    MISSING_DEPS=()
    
    for dep in "${DEPS[@]}"; do
        if ! command -v $dep &> /dev/null; then
            MISSING_DEPS+=($dep)
        fi
    done
    
    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo -e "${YELLOW}Instalando dependências faltantes: ${MISSING_DEPS[*]}${NC}"
        pacman -Sy --noconfirm ${MISSING_DEPS[@]} 2>/dev/null || {
            echo -e "${RED}Erro ao instalar dependências. Tentando método alternativo...${NC}"
            for dep in "${MISSING_DEPS[@]}"; do
                pacman -S --noconfirm $dep 2>/dev/null
            done
        }
    fi
    
    echo -e "${GREEN}Todas as dependências estão instaladas!${NC}\n"
}

# Banner inicial
show_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           FORMATADOR SEGURO DE DISCOS - ARCH LINUX          ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  ⚠️  ATENÇÃO: TODOS OS DADOS SERÃO PERMANENTEMENTE APAGADOS  ║"
    echo "║              ESTA AÇÃO NÃO PODE SER DESFEITA!               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

# Detectar tipo de disco (SSD ou HDD)
get_disk_type() {
    local disk=$1
    local disk_name=$(basename $disk)
    
    # Verificar se é SSD via rotational flag
    if [ -f "/sys/block/$disk_name/queue/rotational" ]; then
        local rotational=$(cat /sys/block/$disk_name/queue/rotational)
        if [ "$rotational" == "0" ]; then
            echo "SSD"
        else
            echo "HDD"
        fi
    else
        # Fallback: usar smartctl
        if smartctl -i $disk 2>/dev/null | grep -q "Solid State Device\|SSD"; then
            echo "SSD"
        else
            echo "HDD"
        fi
    fi
}

# Obter tamanho do disco formatado
get_disk_size() {
    local disk=$1
    lsblk -bno SIZE $disk 2>/dev/null | head -1 | awk '{
        size=$1
        if (size >= 1099511627776) printf "%.2f TB", size/1099511627776
        else if (size >= 1073741824) printf "%.2f GB", size/1073741824
        else if (size >= 1048576) printf "%.2f MB", size/1048576
        else printf "%.2f KB", size/1024
    }'
}

# Listar discos disponíveis
list_disks() {
    echo -e "${CYAN}${BOLD}Discos disponíveis no sistema:${NC}\n"
    echo -e "${YELLOW}ID\tDispositivo\tTamanho\t\tTipo\tModelo${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    local i=1
    DISKS=()
    
    while IFS= read -r disk; do
        if [[ ! "$disk" =~ loop|ram|sr|zram ]]; then
            local size=$(get_disk_size /dev/$disk)
            local type=$(get_disk_type /dev/$disk)
            local model=$(hdparm -I /dev/$disk 2>/dev/null | grep "Model Number" | cut -d: -f2 | xargs)
            [ -z "$model" ] && model=$(cat /sys/block/$disk/device/model 2>/dev/null | xargs)
            [ -z "$model" ] && model="N/A"
            
            DISKS+=("/dev/$disk")
            printf "${GREEN}%d${NC}\t/dev/%-10s\t%-10s\t%s\t%s\n" $i $disk "$size" "$type" "$model"
            ((i++))
        fi
    done < <(lsblk -ndo NAME)
    
    echo ""
}

# Selecionar discos para formatar
select_disks() {
    local selected_disks=()
    
    while true; do
        echo -e "${PURPLE}${BOLD}Digite os números dos discos a formatar (separados por espaço):${NC}"
        echo -e "${YELLOW}Exemplo: 1 3 4 (ou 'all' para todos, 'q' para sair)${NC}"
        read -p "> " selection
        
        if [[ "$selection" == "q" ]]; then
            echo -e "${YELLOW}Operação cancelada pelo usuário.${NC}"
            exit 0
        elif [[ "$selection" == "all" ]]; then
            selected_disks=("${DISKS[@]}")
            break
        else
            for num in $selection; do
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#DISKS[@]}" ]; then
                    selected_disks+=("${DISKS[$((num-1))]}")
                else
                    echo -e "${RED}Número inválido: $num${NC}"
                fi
            done
            
            if [ ${#selected_disks[@]} -gt 0 ]; then
                break
            else
                echo -e "${RED}Nenhum disco válido selecionado!${NC}"
            fi
        fi
    done
    
    SELECTED_DISKS=("${selected_disks[@]}")
}

# Escolher método de limpeza
select_wipe_method() {
    echo -e "${CYAN}${BOLD}Selecione o método de limpeza:${NC}\n"
    echo -e "${GREEN}1${NC} - Rápido (dd com zeros - 1 passada)"
    echo -e "${GREEN}2${NC} - Seguro (dd com random - 1 passada)"
    echo -e "${GREEN}3${NC} - Militar (shred - 3 passadas com random)"
    echo -e "${GREEN}4${NC} - Paranóico (shred - 7 passadas DoD 5220.22-M)"
    echo -e "${GREEN}5${NC} - SSD Secure Erase (apenas para SSDs)"
    echo ""
    
    while true; do
        read -p "Escolha o método (1-5): " method
        case $method in
            [1-5]) WIPE_METHOD=$method; break;;
            *) echo -e "${RED}Opção inválida!${NC}";;
        esac
    done
}

# Confirmar operação
confirm_operation() {
    echo -e "\n${RED}${BOLD}════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}CONFIRMAÇÃO FINAL - LEIA COM ATENÇÃO!${NC}"
    echo -e "${RED}${BOLD}════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}${BOLD}Discos selecionados para formatação:${NC}"
    for disk in "${SELECTED_DISKS[@]}"; do
        local size=$(get_disk_size $disk)
        local type=$(get_disk_type $disk)
        echo -e "  ${RED}• $disk${NC} (${size}, ${type})"
    done
    
    echo -e "\n${YELLOW}${BOLD}Método de limpeza:${NC}"
    case $WIPE_METHOD in
        1) echo -e "  ${CYAN}Rápido (zeros)${NC}";;
        2) echo -e "  ${CYAN}Seguro (random)${NC}";;
        3) echo -e "  ${CYAN}Militar (3 passadas)${NC}";;
        4) echo -e "  ${CYAN}Paranóico (7 passadas)${NC}";;
        5) echo -e "  ${CYAN}SSD Secure Erase${NC}";;
    esac
    
    echo -e "\n${RED}${BOLD}⚠️  TODOS OS DADOS SERÃO PERDIDOS PERMANENTEMENTE! ⚠️${NC}"
    echo -e "${RED}${BOLD}Esta ação é IRREVERSÍVEL!${NC}\n"
    
    echo -e "${YELLOW}Digite '${RED}${BOLD}CONFIRMAR${NC}${YELLOW}' (em maiúsculas) para continuar:${NC}"
    read -p "> " confirmation
    
    if [[ "$confirmation" != "CONFIRMAR" ]]; then
        echo -e "\n${GREEN}Operação cancelada. Nenhum disco foi modificado.${NC}"
        exit 0
    fi
}

# Calcular tempo estimado
calculate_eta() {
    local size=$1
    local speed=$2
    local seconds=$(echo "scale=0; $size / $speed" | bc 2>/dev/null)
    
    if [ -z "$seconds" ] || [ "$seconds" -eq 0 ]; then
        echo "Calculando..."
    else
        local hours=$((seconds / 3600))
        local minutes=$(((seconds % 3600) / 60))
        local secs=$((seconds % 60))
        printf "%02d:%02d:%02d" $hours $minutes $secs
    fi
}

# Limpar disco com dd e zeros
wipe_with_zeros() {
    local disk=$1
    local size=$(blockdev --getsize64 $disk)
    
    echo -e "${CYAN}Limpando $disk com zeros...${NC}"
    dd if=/dev/zero of=$disk bs=4M status=progress 2>&1 | \
    while IFS= read -r line; do
        if [[ $line =~ ([0-9]+)\ bytes ]]; then
            local bytes=${BASH_REMATCH[1]}
            local percent=$(echo "scale=2; $bytes * 100 / $size" | bc 2>/dev/null)
            printf "\r${GREEN}Progresso: %.2f%%${NC}" $percent
        fi
    done
    echo ""
}

# Limpar disco com dd e random
wipe_with_random() {
    local disk=$1
    local size=$(blockdev --getsize64 $disk)
    
    echo -e "${CYAN}Limpando $disk com dados aleatórios...${NC}"
    pv -tpreb -s $size /dev/urandom | dd of=$disk bs=4M 2>/dev/null
}

# Limpar disco com shred
wipe_with_shred() {
    local disk=$1
    local passes=$2
    
    echo -e "${CYAN}Limpando $disk com shred ($passes passadas)...${NC}"
    shred -vfz -n $passes $disk
}

# SSD Secure Erase
ssd_secure_erase() {
    local disk=$1
    
    echo -e "${CYAN}Executando Secure Erase em $disk...${NC}"
    
    # Verificar se suporta secure erase
    if ! hdparm -I $disk 2>/dev/null | grep -q "supported: enhanced erase"; then
        echo -e "${YELLOW}Este SSD não suporta Secure Erase. Usando método alternativo...${NC}"
        
        # Usar TRIM/discard como alternativa
        echo -e "${CYAN}Executando TRIM/discard em todo o disco...${NC}"
        blkdiscard -v $disk 2>&1
        
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}TRIM falhou. Usando zeros...${NC}"
            wipe_with_zeros $disk
        fi
    else
        # Configurar senha temporária
        hdparm --user-master u --security-set-pass p $disk
        
        # Executar secure erase
        time hdparm --user-master u --security-erase p $disk
        
        echo -e "${GREEN}Secure Erase concluído!${NC}"
    fi
}

# Processar limpeza de disco
process_disk() {
    local disk=$1
    local disk_type=$(get_disk_type $disk)
    local disk_size=$(get_disk_size $disk)
    
    echo -e "\n${PURPLE}${BOLD}════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}Processando: $disk ($disk_size, $disk_type)${NC}"
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════${NC}\n"
    
    # Desmontar partições se montadas
    echo -e "${YELLOW}Desmontando partições...${NC}"
    umount ${disk}* 2>/dev/null
    
    # Executar método de limpeza selecionado
    case $WIPE_METHOD in
        1) wipe_with_zeros $disk;;
        2) wipe_with_random $disk;;
        3) wipe_with_shred $disk 3;;
        4) wipe_with_shred $disk 7;;
        5) 
            if [[ "$disk_type" == "SSD" ]]; then
                ssd_secure_erase $disk
            else
                echo -e "${YELLOW}Disco não é SSD. Usando método seguro...${NC}"
                wipe_with_random $disk
            fi
            ;;
    esac
    
    # Criar nova tabela de partições GPT
    echo -e "\n${CYAN}Criando nova tabela de partições GPT...${NC}"
    parted -s $disk mklabel gpt 2>/dev/null || sgdisk -Z $disk 2>/dev/null
    
    # Sincronizar
    sync
    
    echo -e "${GREEN}${BOLD}✓ $disk formatado com sucesso!${NC}"
}

# Função principal
main() {
    check_root
    show_banner
    install_dependencies
    
    # Listar discos
    list_disks
    
    if [ ${#DISKS[@]} -eq 0 ]; then
        echo -e "${RED}Nenhum disco encontrado!${NC}"
        exit 1
    fi
    
    # Selecionar discos
    select_disks
    
    # Selecionar método
    select_wipe_method
    
    # Confirmar operação
    confirm_operation
    
    # Processar cada disco
    START_TIME=$(date +%s)
    TOTAL_DISKS=${#SELECTED_DISKS[@]}
    CURRENT_DISK=0
    
    echo -e "\n${GREEN}${BOLD}Iniciando processo de formatação...${NC}\n"
    
    for disk in "${SELECTED_DISKS[@]}"; do
        ((CURRENT_DISK++))
        echo -e "${BLUE}${BOLD}[Disco $CURRENT_DISK de $TOTAL_DISKS]${NC}"
        process_disk $disk
    done
    
    # Calcular tempo total
    END_TIME=$(date +%s)
    TOTAL_TIME=$((END_TIME - START_TIME))
    HOURS=$((TOTAL_TIME / 3600))
    MINUTES=$(((TOTAL_TIME % 3600) / 60))
    SECONDS=$((TOTAL_TIME % 60))
    
    # Relatório final
    echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}           FORMATAÇÃO CONCLUÍDA COM SUCESSO!            ${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${CYAN}Resumo da operação:${NC}"
    echo -e "  • Discos formatados: ${GREEN}$TOTAL_DISKS${NC}"
    echo -e "  • Tempo total: ${GREEN}$(printf "%02d:%02d:%02d" $HOURS $MINUTES $SECONDS)${NC}"
    echo -e "  • Método usado: ${GREEN}"
    case $WIPE_METHOD in
        1) echo -e "Rápido (zeros)${NC}";;
        2) echo -e "Seguro (random)${NC}";;
        3) echo -e "Militar (3 passadas)${NC}";;
        4) echo -e "Paranóico (7 passadas)${NC}";;
        5) echo -e "SSD Secure Erase${NC}";;
    esac
    
    echo -e "\n${YELLOW}${BOLD}Todos os dados foram permanentemente removidos.${NC}"
    echo -e "${GREEN}Os discos estão prontos para uso!${NC}\n"
}

# Tratamento de interrupção
trap 'echo -e "\n${RED}${BOLD}Operação interrompida pelo usuário!${NC}"; exit 1' INT

# Executar
main "$@"