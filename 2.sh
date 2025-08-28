#!/usr/bin/env bash
set -euo pipefail

DISCO_SSD=$(cat /tmp/disco_principal.txt)

echo "===[ FASE 2: Configuração do disco principal ($DISCO_SSD) ]==="

read -p "Tamanho da SWAP em GiB (ex: 8): " SWAPSIZE
read -p "Defina a senha do LUKS do SSD: " -s SENHA_SSD
echo

echo "[*] Limpando disco..."
blkdiscard -f "$DISCO_SSD" || true

echo "[*] Criando partições..."
parted -a optimal "$DISCO_SSD" --script \
  mklabel gpt \
  mkpart ESP fat32 1MiB 513MiB \
  set 1 esp on \
  mkpart swap linux-swap -${SWAPSIZE}GiB 100% \
  mkpart cryptroot 513MiB -${SWAPSIZE}GiB

echo "[*] Configurando LUKS (root)..."
echo -n "$SENHA_SSD" | cryptsetup luksFormat ${DISCO_SSD}p3 \
  --type luks2 --cipher aes-xts-plain64 --key-size 512 \
  --pbkdf argon2id --iter-time 5000 --pbkdf-memory 524288 --label cryptroot -

echo -n "$SENHA_SSD" | cryptsetup open ${DISCO_SSD}p3 cryptroot -

echo "[*] Criando Btrfs e subvolumes..."
mkfs.btrfs -L ROOT /dev/mapper/cryptroot
mount /dev/mapper/cryptroot /mnt
for sub in @ @home @snapshots @var @log @cache; do
  btrfs subvolume create /mnt/$sub
done
umount /mnt

mount -o subvol=@,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt
mkdir -p /mnt/{home,.snapshots,var,efi}
mount -o subvol=@home,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/home
mount -o subvol=@snapshots,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/.snapshots
mount -o subvol=@var,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var
mount -o subvol=@log,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/log
mount -o subvol=@cache,compress=zstd:3,noatime /dev/mapper/cryptroot /mnt/var/cache

mkfs.vfat -F32 -n EFI ${DISCO_SSD}p1
mount ${DISCO_SSD}p1 /mnt/efi

mkswap ${DISCO_SSD}p2

echo "===[ Disco principal configurado. Próxima etapa: ./fase3-disco-auxiliar.sh ]==="
