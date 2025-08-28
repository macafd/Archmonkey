#!/usr/bin/env bash
set -euo pipefail

echo "===[ FASE 7: Autodestruição ]==="

# runtime
cat >/usr/local/bin/selfdestruct-now.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[*] Destruindo headers LUKS..."
cryptsetup luksErase /dev/nvme0n1p3 || true
cryptsetup luksErase /dev/sda1      || true
swapoff -a || true
if [ -b /dev/mapper/cryptswap ]; then
  dd if=/dev/zero of=/dev/mapper/cryptswap bs=16M status=progress || true
fi
blkdiscard -f /dev/nvme0n1 || true
dd if=/dev/zero of=/dev/sda bs=16M status=progress oflag=direct || true
systemctl poweroff -f
EOF
chmod +x /usr/local/bin/selfdestruct-now.sh

# initramfs hook
mkdir -p /etc/initcpio/hooks /etc/initcpio/install
cat >/etc/initcpio/hooks/selfdestruct <<'EOF'
run_hook() {
  if ! grep -qw 'selfdestruct=1' /proc/cmdline; then
    return
  fi
  echo "[initramfs] AUTODESTRUIÇÃO ATIVA!"
  cryptsetup luksErase /dev/nvme0n1p3 || true
  cryptsetup luksErase /dev/sda1      || true
  blkdiscard -f /dev/nvme0n1 || true
  dd if=/dev/zero of=/dev/sda bs=16M status=progress oflag=direct || true
  poweroff -f
}
EOF

cat >/etc/initcpio/install/selfdestruct <<'EOF'
build() {
  add_binary cryptsetup
  add_binary blkdiscard
  add_binary dd
  add_runscript
}
EOF

# adicionar ao mkinitcpio
sed -i 's|HOOKS=(.*)|HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt selfdestruct btrfs filesystems fsck)|' /etc/mkinitcpio.conf
mkinitcpio -P

# entrada no GRUB
cat >>/etc/grub.d/40_custom <<'EOF'
menuentry 'Autodestruição do Sistema (profunda)' {
    insmod part_gpt
    insmod fat
    search --no-floppy --fs-uuid --set=root $(blkid -s UUID -o value /dev/nvme0n1p1)
    linux /vmlinuz-linux selfdestruct=1 quiet
    initrd /amd-ucode.img /intel-ucode.img /initramfs-linux.img
}
EOF

grub-mkconfig -o /boot/grub/grub.cfg

echo "===[ Autodestruição instalada. Setup concluído! ]==="
