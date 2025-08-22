#!/bin/bash
set -euo pipefail

# Função para mostrar mensagens
output() {
    printf '\e[1;34m%-6s\e[m\n' "${@}"
}

error() {
    printf '\e[1;31m%-6s\e[m\n' "${@}" >&2
}

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root"
    exit 1
fi

# Mostrar discos disponíveis
output "Discos disponíveis no sistema:"
lsblk -o NAME,SIZE,MODEL,TYPE,MOUNTPOINT

# Selecionar dispositivo para backup
output "Selecione o número do dispositivo LUKS para backup:"
select device in $(lsblk -dpno NAME | grep -E "/dev/(nvme|sd|mmcblk|vd)"); do
    if [[ -n "$device" ]]; then
        if cryptsetup isLuks "$device"; then
            output "Dispositivo selecionado: $device"
            break
        else
            error "O dispositivo $device não é LUKS"
            exit 1
        fi
    else
        error "Seleção inválida"
        exit 1
    fi
done

# Esperar pelo pendrive
output "Insira o pendrive para backup e aguarde..."
while true; do
    pendrives=$(lsblk -dpno NAME,MOUNTPOINT | grep -E "/dev/(sd|mmcblk)" | grep -v "$device")
    if [[ -n "$pendrives" ]]; then
        output "Pendrive(s) detectado(s):"
        echo "$pendrives"
        break
    fi
    sleep 2
done

# Selecionar pendrive
output "Selecione o número do pendrive para backup:"
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
    # Se falhar, tentar formatar como FAT32
    output "Formatando pendrive como FAT32..."
    mkfs.fat -F 32 "$pendrive"
    mount "$pendrive" "$mount_point"
}

# Criar nome único para backup
backup_name="luks-backup-$(date +%Y%m%d-%H%M%S)-$(basename "$device")"
backup_file="$mount_point/$backup_name.img"

# Fazer backup do header LUKS
output "Fazendo backup do header LUKS..."
cryptsetup luksHeaderBackup "$device" --header-backup-file "$backup_file"

# Verificar integridade do backup
output "Verificando integridade do backup..."
if cryptsetup luksHeaderRestore --test "$device" --header-backup-file "$backup_file"; then
    output "✓ Backup verificado com sucesso"
else
    error "✗ Falha na verificação do backup"
    umount "$pendrive"
    exit 1
fi

# Fazer backup das informações LUKS
info_file="$mount_point/${backup_name}.info"
cryptsetup luksDump "$device" > "$info_file"

# Desmontar pendrive
output "Desmontando pendrive..."
sync
umount "$pendrive"
rmdir "$mount_point"

output "Backup concluído com sucesso!"
output "Arquivo de backup: $backup_file"
output "Arquivo de informações: $info_file"
output "Guarde o pendrive em local seguro!"