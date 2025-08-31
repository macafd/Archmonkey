#!/bin/bash
# generate-config.sh - Gera arquivo de configuração exemplo
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}Criando config.example.json...${NC}"

cat << 'CONFIG_EOF' > config.example.json
{
  "disco_principal": "/dev/nvme0n1",
  "disco_auxiliar": "/dev/sda",
  "usb_backup": "/dev/sdb1",
  "swap_gib": 8,
  "hostname": "archlinux",
  "username": "usuario",
  "user_password": "CHANGE_ME",
  "root_password": "CHANGE_ME",
  "luks_root_password": "CHANGE_ME",
  "luks_aux_password": "CHANGE_ME",
  "reuse_luks_password": false,
  "timezone": "America/Sao_Paulo",
  "locale": "pt_BR.UTF-8",
  "luks_root_iter_time": 5000,
  "luks_root_pbkdf_memory": 524288,
  "luks_aux_pbkdf_memory": 262144,
  "btrfs_compress_level": 3,
  "linux_only": false,
  "retain_backups_days": 7,
  "enable_backup_timer": false,
  "autodestruct_enabled": false,
  "simulate": false
}
CONFIG_EOF

echo -e "${GREEN}Arquivo config.example.json criado com sucesso!${NC}"
echo -e "${YELLOW}IMPORTANTE: Edite o arquivo e altere todas as senhas antes de usar!${NC}"
