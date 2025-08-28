#!/usr/bin/env bash
set -euo pipefail

echo "===[ FASE 4: Instalação do sistema base ]==="

pacstrap /mnt \
  base linux linux-firmware \
  btrfs-progs cryptsetup grub efibootmgr \
  micro sudo networkmanager \
  exfatprogs \
  xfce4 lightdm lightdm-gtk-greeter \
  man-db man-pages \
  amd-ucode intel-ucode \
  nftables reflector git vim

genfstab -U /mnt >> /mnt/etc/fstab

echo "===[ Base instalada. Próxima etapa: entrar no chroot ]==="
echo "👉 Execute: arch-chroot /mnt"
echo "👉 Depois rode: ./fase5-config-chroot.sh"
