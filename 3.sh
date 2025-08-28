#!/usr/bin/env bash
set -euo pipefail

DISCO_HDD=$(cat /tmp/disco_auxiliar.txt)

echo "===[ FASE 3: Configuração do disco auxiliar ($DISCO_HDD) ]==="

read -p "Defina a senha do LUKS do HDD auxiliar: " -s SENHA_HDD
echo

parted "$DISCO_HDD" --script mklabel gpt mkpart primary 1MiB 100%

echo -n "$SENHA_HDD" | cryptsetup luksFormat ${DISCO_HDD}1 \
  --type luks2 --cipher aes-xts-plain64 --key-size 512 \
  --pbkdf argon2id --iter-time 5000 --pbkdf-memory 262144 --label cryptaux -

echo -n "$SENHA_HDD" | cryptsetup open ${DISCO_HDD}1 cryptaux -

mkfs.exfat -n AUXILIAR /dev/mapper/cryptaux
mkdir -p /mnt/aux
mount /dev/mapper/cryptaux /mnt/aux

echo "===[ Disco auxiliar configurado. Próxima etapa: ./fase4-base-system.sh ]==="
