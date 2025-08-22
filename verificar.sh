#!/bin/bash
set -euo pipefail

# Funções de output
output() {
    printf '\e[1;34m%-6s\e[m\n' "${@}"
}

error() {
    printf '\e[1;31m%-6s\e[m\n' "${@}" >&2
}

success() {
    printf '\e[1;32m%-6s\e[m\n' "${@}"
}

warning() {
    printf '\e[1;33m%-6s\e[m\n' "${@}"
}

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root"
    exit 1
fi

echo
output "=== VERIFICAÇÃO DE BACKUP LUKS ==="
echo

# Esperar pelo pendrive
output "Insira o pendrive com o backup e aguarde..."
while true; do
    # Listar dispositivos removíveis (pendrives)
    pendrives=$(lsblk -dpno NAME,MOUNTPOINT,SIZE,MODEL | grep -E "/dev/(sd|mmcblk)" | grep -v "/dev/nvme")
    
    if [[ -n "$pendrives" ]]; then
        output "Pendrive(s) detectado(s):"
        echo "$pendrives" | while read -r line; do
            echo "  $line"
        done
        break
    fi
    sleep 2
done

# Selecionar pendrive
output "Selecione o número do pendrive para verificar:"
select pendrive in $(echo "$pendrives" | awk '{print $1}'); do
    if [[ -n "$pendrive" ]]; then
        output "Pendrive selecionado: $pendrive"
        break
    else
        error "Seleção inválida"
        exit 1
    fi
done

# Montar pendrive
output "Montando pendrive..."
mount_point=$(mktemp -d)
mount "$pendrive" "$mount_point" 2>/dev/null || {
    error "Falha ao montar o pendrive $pendrive"
    exit 1
}

# Listar backups disponíveis
output "Backups disponíveis no pendrive:"
backups=$(find "$mount_point" -name "*.img" -o -name "*.info" | grep -E "luks-backup" | sort | uniq | sed 's/\.info$//' | sed 's/\.img$//' | uniq)

if [[ -z "$backups" ]]; then
    error "Nenhum backup LUKS encontrado no pendrive"
    umount "$pendrive"
    exit 1
fi

select backup_base in $backups; do
    if [[ -n "$backup_base" ]]; then
        backup_file="${backup_base}.img"
        info_file="${backup_base}.info"
        output "Backup selecionado: $(basename "$backup_file")"
        break
    else
        error "Seleção inválida"
        umount "$pendrive"
        exit 1
    fi
done

# Verificar se os arquivos existem
if [[ ! -f "$backup_file" ]]; then
    error "Arquivo de backup não encontrado: $backup_file"
    umount "$pendrive"
    exit 1
fi

if [[ ! -f "$info_file" ]]; then
    warning "Arquivo de informações não encontrado: $info_file"
fi

# Identificar dispositivo original
output "Identificando dispositivo original do backup..."
device_name=$(echo "$backup_file" | grep -oE "nvme[^.]*|sd[^.]*")
if [[ -n "$device_name" ]]; then
    device_path="/dev/${device_name}"
    output "Dispositivo provável: $device_path"
else
    output "Não foi possível identificar o dispositivo original pelo nome do arquivo"
    read -rp "Digite o caminho completo do dispositivo LUKS (ex: /dev/nvme0n1p2): " device_path
fi

# Verificar se o dispositivo existe e é LUKS
if [[ ! -e "$device_path" ]]; then
    warning "Dispositivo $device_path não encontrado no sistema"
    read -rp "Deseja continuar apenas com verificação do arquivo? (s/N): " continue_anyway
    if [[ ! "$continue_anyway" =~ ^[Ss]$ ]]; then
        umount "$pendrive"
        exit 1
    fi
    device_path=""
fi

# Verificar integridade do backup
output "Verificando integridade do backup..."
if [[ -n "$device_path" ]] && cryptsetup isLuks "$device_path"; then
    # Verificar contra dispositivo real
    if cryptsetup luksHeaderRestore --test "$device_path" --header-backup-file "$backup_file"; then
        success "✓ Backup é compatível com o dispositivo $device_path"
    else
        error "✗ Backup NÃO é compatível com o dispositivo $device_path"
    fi
else
    # Verificar apenas a estrutura do header
    if cryptsetup luksDump "$backup_file" >/dev/null 2>&1; then
        success "✓ Estrutura do header LUKS parece válida"
    else
        error "✗ Estrutura do header LUKS é inválida"
    fi
fi

# Verificar informações do backup
if [[ -f "$info_file" ]]; then
    output "Informações do backup:"
    echo "=== LUKS DUMP ==="
    cat "$info_file"
    echo "================="
fi

# Desmontar pendrive
output "Desmontando pendrive..."
sync
umount "$pendrive"
rmdir "$mount_point"

output "Verificação concluída!"
output "Arquivo de backup: $(basename "$backup_file")"
if [[ -f "$info_file" ]]; then
    output "Arquivo de informações: $(basename "$info_file")"
fi