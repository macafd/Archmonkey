#!/usr/bin/env bash
set -euo pipefail

echo "===[ FASE 1: Preparação do Live ISO ]==="

timedatectl set-ntp true
echo "[*] NTP ativado."

echo "[*] Discos detectados:"
lsblk -o NAME,SIZE,TYPE

read -p "Informe o disco PRINCIPAL (ex: /dev/nvme0n1): " DISCO_SSD
read -p "Informe o disco AUXILIAR (ex: /dev/sda): " DISCO_HDD

echo "$DISCO_SSD" > /tmp/disco_principal.txt
echo "$DISCO_HDD" > /tmp/disco_auxiliar.txt

echo "[*] Valores salvos em /tmp/disco_*.txt"
echo "===[ Preparo concluído. Próxima etapa: ./fase2-disco-principal.sh ]==="
