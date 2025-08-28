# Configuração de Segurança Máxima com Arch Linux: Criptografia, Autodestruição e Backup

## 📋 Pré-requisitos e Preparação
1. Boot no Ambiente Live do Arch Linux
2. Verifique o Modo UEFI: `cat /sys/firmware/efi/fw_platform_size`
3. Conecte-se à Internet: `iwctl` (Wi-Fi) ou `dhcpcd` (cabo)
4. Identifique os Discos: `lsblk` (nvme0n1 = SSD, sda = HDD)

## 🛡️ Configuração do Disco Principal (SSD - nvme0n1)

### 1. Particionamento com LUKS2
dd if=/dev/zero of=/dev/nvme0n1 bs=1M status=progress
parted /dev/nvme0n1 mklabel gpt
parted /dev/nvme0n1 mkpart ESP fat32 1MiB 513MiB
parted /dev/nvme0n1 set 1 esp on
parted /dev/nvme0n1 mkpart cryptroot 513MiB 100%

### 2. Configuração LUKS2
cryptsetup luksFormat /dev/nvme0n1p2 \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha3-512 \
  --iter-time 5000 \
  --pbkdf argon2id \
  --pbkdf-memory 524288

cryptsetup open /dev/nvme0n1p2 cryptroot

### 3. Sistema de Arquivos Btrfs
mkfs.btrfs /dev/mapper/cryptroot
mount /dev/mapper/cryptroot /mnt
btrfs subvolume create /mnt/@root
btrfs subvolume create /mnt/@home
btrfs subvolume create /mnt/@snapshots
umount /mnt

mount -o compress=zstd,ssd,noatime,subvol=@root /dev/mapper/cryptroot /mnt
mkdir -p /mnt/{home,.snapshots}
mount -o compress=zstd,ssd,noatime,subvol=@home /dev/mapper/cryptroot /mnt/home
mount -o compress=zstd,ssd,noatime,subvol=@snapshots /dev/mapper/cryptroot /mnt/.snapshots

mkfs.fat -F32 /dev/nvme0n1p1
mkdir /mnt/efi
mount /dev/nvme0n1p1 /mnt/efi

## 💾 Configuração do Disco Auxiliar (HDD - sda)

### 1. Particionamento e Criptografia
parted /dev/sda mklabel gpt
parted /dev/sda mkpart primary exfat 1MiB 100%

cryptsetup luksFormat /dev/sda1 \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha3-512 \
  --iter-time 5000 \
  --pbkdf argon2id \
  --pbkdf-memory 262144

cryptsetup open /dev/sda1 cryptaux
mkfs.exfat /dev/mapper/cryptaux -n "AUXILIAR"
mkdir /mnt/aux
mount /dev/mapper/cryptaux /mnt/aux

### 2. Configuração para Montagem Automática
Edite /etc/crypttab:
cryptaux  /dev/sda1  none  timeout=180

Edite /etc/fstab:
/dev/mapper/cryptaux  /aux  exfat  defaults,noatime,uid=1000,gid=1000  0  2

## 🔥 Mecanismo de Autodestruição

### 1. Backup dos Headers LUKS para Pendrive
mkdir /mnt/usb
mount /dev/sdb1 /mnt/usb

cryptsetup luksHeaderBackup /dev/nvme0n1p2 --header-backup-file /mnt/usb/luks_header_nvme0n1p2.backup
cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file /mnt/usb/luks_header_sda1.backup

tar -czf - /mnt/usb/luks_*.backup | gpg -c --cipher-algo AES256 -o /mnt/usb/luks_backups.tar.gz.gpg
umount /mnt/usb

### 2. Script de Autodestruição Aprimorado
Crie /usr/local/bin/selfdestruct.sh:

#!/bin/bash
echo "Destruindo headers LUKS..."
cryptsetup luksErase /dev/nvme0n1p2
cryptsetup luksErase /dev/sda1

echo "Sobrescrevendo discos com zeros..."
dd if=/dev/zero of=/dev/nvme0n1 bs=1M status=progress &
dd if=/dev/zero of=/dev/sda bs=1M status=progress &
wait

echo "Limpando memória RAM..."
echo 1 > /proc/sys/vm/drop_caches

swapoff -a
if [ -b /dev/mapper/cryptswap ]; then
    dd if=/dev/zero of=/dev/mapper/cryptswap bs=1M status=progress
fi

echo "Autodestruição concluída. Desligando sistema..."
systemctl poweroff -f

chmod +x /usr/local/bin/selfdestruct.sh

### 3. Ativação por Hotkey com GRUB
Edite /etc/default/grub:
GRUB_CMDLINE_LINUX_DEFAULT="quiet rd.luks.name=$(blkid -s UUID -o value /dev/nvme0n1p2)=cryptroot root=/dev/mapper/cryptroot rootflags=subvol=@root rw"
GRUB_CMDLINE_LINUX=""

Crie entrada no /etc/grub.d/40_custom:
menuentry 'Autodestruição do Sistema' {
    set root=(hd0,gpt2)
    linux16 /vmlinuz-linux root=/dev/mapper/cryptroot quiet
    initrd16 /initramfs-linux.img
    echo "Iniciando autodestruição em 10 segundos..."
    sleep 10
    /usr/local/bin/selfdestruct.sh
}

grub-mkconfig -o /boot/grub/grub.cfg

## ⚙️ Instalação do Sistema Base
pacstrap /mnt base linux linux-firmware btrfs-progs grub efibootmgr micro sudo networkmanager xfce4 lightdm-gtk-greeter exfatprogs evtest

genfstab -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt

## 🔒 Configuração de Swap Criptografada
parted /dev/nvme0n1 mkpart primary linux-swap 100% 116%

cryptsetup luksFormat --type luks2 /dev/nvme0n1p3
cryptsetup open /dev/nvme0n1p3 cryptswap
mkswap /dev/mapper/cryptswap
swapon /dev/mapper/cryptswap

Edite /etc/crypttab:
cryptswap /dev/nvme0n1p3 /dev/urandom swap,cipher=aes-xts-plain64,size=256

Edite /etc/fstab:
/dev/mapper/cryptswap none swap defaults 0 0

## 🔄 Sistema de Backup e Restauração
Crie /usr/local/bin/backup-luks-headers.sh:

#!/bin/bash
BACKUP_DIR="/aux/backups/luks_headers"
DATE=$(date +%Y-%m-%d)
PENDRIEVE="/dev/sdb1"

mkdir -p /mnt/usb
mount $PENDRIEVE /mnt/usb

cryptsetup luksHeaderBackup /dev/nvme0n1p2 --header-backup-file /mnt/usb/luks_header_nvme0n1p2_$DATE.backup
cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file /mnt/usb/luks_header_sda1_$DATE.backup

tar -czf - /mnt/usb/luks_*_$DATE.backup | gpg -c --cipher-algo AES256 -o /mnt/usb/luks_backups_$DATE.tar.gz.gpg

find /mnt/usb -name "luks_header_*.backup" -mtime +7 -delete
find /mnt/usb -name "luks_backups_*.tar.gz.gpg" -mtime +7 -delete

umount /mnt/usb

chmod +x /usr/local/bin/backup-luks-headers.sh

## ✅ Testes Finais
cryptsetup luksDump /dev/nvme0n1p2
cryptsetup luksDump /dev/sda1
/usr/local/bin/backup-luks-headers.sh
swapon --show

## 📌 Notas Importantes
- Mantenha backups dos headers LUKS em pelo menos dois pendrives
- Teste o sistema em ambiente controlado antes de usar em produção
- Os parâmetros foram ajustados para hardware com 4GB RAM
