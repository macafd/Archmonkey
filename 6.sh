#!/usr/bin/env bash
set -euo pipefail

echo "===[ FASE 6: Script de backup dos headers LUKS ]==="

cat >/usr/local/bin/backup-luks-headers.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DATE=$(date +%F)
USB_DEV="${1:-/dev/sdb1}"

mkdir -p /mnt/usb
mount "$USB_DEV" /mnt/usb
umask 077

cryptsetup luksHeaderBackup /dev/nvme0n1p3 --header-backup-file "/mnt/usb/luks_header_nvme0n1p3_${DATE}.backup"
cryptsetup luksHeaderBackup /dev/sda1      --header-backup-file "/mnt/usb/luks_header_sda1_${DATE}.backup"

tar -C /mnt/usb -czf - "luks_header_nvme0n1p3_${DATE}.backup" "luks_header_sda1_${DATE}.backup" \
  | gpg -c --cipher-algo AES256 -o "/mnt/usb/luks_backups_${DATE}.tar.gz.gpg"

find /mnt/usb -name 'luks_header_*.backup' -mtime +7 -delete
find /mnt/usb -name 'luks_backups_*.tar.gz.gpg' -mtime +7 -delete

umount /mnt/usb
EOF

chmod +x /usr/local/bin/backup-luks-headers.sh
echo "===[ Backup script instalado. Próxima etapa: ./fase7-autodestruicao.sh ]==="
