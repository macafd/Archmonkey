
cat << 'EOF_README' > README.md
# Arch Secure Setup

Sistema completo de instalação segura do Arch Linux com criptografia total, backup automatizado e autodestruição de emergência.

## ⚠️ AVISOS IMPORTANTES

**ESTE SISTEMA CONTÉM RECURSOS DE DESTRUIÇÃO DE DADOS IRREVERSÍVEIS!**

- Todas as operações de formatação são **permanentes**
- O sistema de autodestruição **NÃO PODE SER REVERTIDO**
- Sempre mantenha backups externos de seus dados importantes
- Teste primeiro em ambiente virtual ou com modo `--simulate`

## 📋 Requisitos

- ISO do Arch Linux (boot UEFI ou BIOS)
- Mínimo 4GB RAM (8GB recomendado)
- SSD para sistema (mínimo 20GB)
- HDD para dados (opcional)
- Conexão com internet

## 🚀 Instalação Rápida

### Preparação

1. Boot pelo ISO do Arch Linux
2. Configure rede e teclado:
```bash
loadkeys br-abnt2
iwctl  # ou use ethernet
```

3. Extraia o pacote:
```bash
tar -xzf arch-secure-setup.tar.gz
cd arch-secure-setup
chmod +x *.sh
```

### Execução das Fases

#### Fase 1: Detecção de Hardware
```bash
./fase1-preparo.sh
```
- Detecta hardware disponível
- Solicita seleção de discos
- Salva configuração inicial

#### Fase 2: Disco Principal (SSD)
```bash
./fase2-disco-principal.sh
```
- Particiona disco principal
- Cria ESP, /boot, swap e root
- Configura LUKS2 + Btrfs com subvolumes
- **DESTRÓI TODOS OS DADOS NO DISCO!**

#### Fase 3: Disco Auxiliar (HDD) - Opcional
```bash
./fase3-disco-auxiliar.sh
```
- Particiona disco auxiliar
- Criptografia LUKS2
- ExFAT (compatível Windows/Mac) ou ext4
- **DESTRÓI TODOS OS DADOS NO DISCO!**

#### Fase 4: Sistema Base
```bash
./fase4-base-system.sh
```
- Instala sistema base com pacstrap
- Gera fstab
- Copia scripts para chroot

#### Fase 5: Configuração (DENTRO DO CHROOT!)
```bash
arch-chroot /mnt
cd /root
./fase5-config-chroot.sh
```
- Configura timezone, locale, hostname
- Instala e configura GRUB
- Cria usuário
- Configura mkinitcpio
- Opção de habilitar autodestruição

#### Fase 6: Scripts de Backup (Opcional)
```bash
./fase6-backup-scripts.sh
```
- Instala script de backup de headers LUKS
- Opção de backup em USB
- Timer systemd para backup semanal

#### Fase 7: Autodestruição (Opcional - PERIGOSO!)
```bash
./fase7-autodestruicao.sh
```
- Instala script de autodestruição runtime
- Requer confirmação múltipla
- **EXTREMAMENTE PERIGOSO!**

### Finalização
```bash
exit  # sair do chroot
umount -R /mnt
reboot
```

## 🛠️ Modos de Operação

### Modo Interativo (Padrão)
Execução normal com prompts para todas as configurações:
```bash
./fase1-preparo.sh
```

### Modo Dry-Run
Simula execução sem modificar nada:
```bash
./fase1-preparo.sh --dry-run
```

### Modo Simulate
Usa dispositivos loopback para teste completo:
```bash
./fase1-preparo.sh --simulate
```

### Modo Não-Interativo
Usa arquivo de configuração JSON:
```bash
./fase1-preparo.sh --non-interactive config.json
```

## 📁 Estrutura de Partições

### Disco Principal (SSD)
```
/dev/nvme0n1
├── p1  512MB  ESP (FAT32)        /boot/efi
├── p2  1GB    Boot (ext4)        /boot
├── p3  8GB    Swap (criptografado)
└── p4  Resto  Root (LUKS2+Btrfs) /
```

### Subvolumes Btrfs
```
@           -> /
@home       -> /home
@snapshots  -> /.snapshots
@var        -> /var
@log        -> /var/log
@cache      -> /var/cache
```

## 🔐 Segurança

### Criptografia
- LUKS2 com Argon2id PBKDF
- AES-256-XTS para volumes
- Swap criptografada com chave aleatória

### Backups
- Headers LUKS salvos e criptografados com GPG
- Rotação automática (padrão: 7 dias)
- Opção de backup em USB externo

### Autodestruição
- **Script runtime**: `/usr/local/bin/selfdestruct-now.sh`
- **Boot trigger**: `selfdestruct=1` no kernel cmdline
- **Entrada GRUB**: Menu especial (se habilitado)

## ⚡ Testes

### Teste Completo com Simulate
```bash
./test_simulate.sh
```

### Teste Manual com Loopback
```bash
# Criar imagens
dd if=/dev/zero of=test-ssd.img bs=1M count=4096
dd if=/dev/zero of=test-hdd.img bs=1M count=8192

# Associar com loopback
sudo losetup /dev/loop0 test-ssd.img
sudo losetup /dev/loop1 test-hdd.img

# Executar com --simulate
./fase1-preparo.sh --simulate
```

## 📝 Arquivo de Configuração

Exemplo `config.json`:
```json
{
  "disco_principal": "/dev/nvme0n1",
  "disco_auxiliar": "/dev/sda",
  "swap_gib": 8,
  "hostname": "archlinux",
  "username": "usuario",
  "timezone": "America/Sao_Paulo",
  "locale": "pt_BR.UTF-8",
  "luks_root_iter_time": 5000,
  "luks_root_pbkdf_memory": 524288,
  "btrfs_compress_level": 3,
  "autodestruct_enabled": false
}


## 🚨 Recuperação

### Restaurar Header LUKS
```bash
# Descriptografar backup
gpg -d luks-headers-20240101.tar.gz.gpg | tar -xz

# Restaurar header
cryptsetup luksHeaderRestore /dev/nvme0n1p4 --header-backup-file header_dev_nvme0n1p4.img
```

### Montar Sistema Manualmente
```bash
cryptsetup open /dev/nvme0n1p4 cryptroot
mount -o subvol=@ /dev/mapper/cryptroot /mnt
mount -o subvol=@home /dev/mapper/cryptroot /mnt/home
mount /dev/nvme0n1p2 /mnt/boot
mount /dev/nvme0n1p1 /mnt/boot/efi
```

## ⚠️ Problemas Conhecidos

1. **"Device busy"**: Desmonte com `umount -R /mnt`
2. **GRUB não encontra root**: Verifique UUIDs em `/etc/default/grub`
3. **Swap não ativa**: Verifique `/etc/crypttab`
4. **Boot lento**: Normal na primeira vez (geração de chaves)

## 📚 Documentação Adicional

- [Arch Wiki - Criptografia](https://wiki.archlinux.org/title/Dm-crypt)
- [Arch Wiki - Btrfs](https://wiki.archlinux.org/title/Btrfs)
- [LUKS Documentation](https://gitlab.com/cryptsetup/cryptsetup)

## 📄 Licença

Este projeto é fornecido "como está", sem garantias de qualquer tipo.
Use por sua conta e risco.

## 🤝 Contribuições

Sugestões e melhorias são bem-vindas, mas sempre priorize:
1. Segurança
2. Clareza
3. Reversibilidade (exceto autodestruição)

EOF_README
