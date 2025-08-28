#!/usr/bin/env bash
set -euo pipefail

echo "===[ FASE 5: Configuração dentro do chroot ]==="

read -p "Nome do computador (hostname): " HOSTNAME
read -p "Nome do usuário: " USERNAME

ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
hwclock --systohc
sed -i 's/^#\(pt_BR.UTF-8\|en_US.UTF-8\)/\1/' /etc/locale.gen
locale-gen
echo 'LANG=pt_BR.UTF-8' > /etc/locale.conf

echo "$HOSTNAME" > /etc/hostname
cat >/etc/hosts <<EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $HOSTNAME
EOF

# mkinitcpio hooks
sed -i 's/^HOOKS=.*/HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt btrfs filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

# GRUB
CRYPTUUID=$(blkid -s UUID -o value $(cat /tmp/disco_principal.txt)p3)
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet nowatchdog rd.luks.name=$CRYPTUUID=cryptroot root=/dev/mapper/cryptroot rootflags=subvol=@ rw\"|" /etc/default/grub
grub-install --target=x86_64-efi --efi-directory=/efi --bootloader-id=GRUB
grub-mkconfig -o /boot/grub/grub.cfg

# usuário
passwd
useradd -m -G wheel -s /bin/bash "$USERNAME"
passwd "$USERNAME"
EDITOR=micro visudo   # habilitar %wheel

systemctl enable NetworkManager lightdm fstrim.timer systemd-timesyncd

echo "===[ Configuração concluída. Próxima etapa: ./fase6-backup-scripts.sh ]==="
