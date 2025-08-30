# ============================================================================
# TEST SIMULATE
# ============================================================================
echo -e "${GREEN}Criando test_simulate.sh...${NC}"
cat << 'EOF' > test_simulate.sh
#!/bin/bash
# test_simulate.sh - Teste completo com dispositivos virtuais
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== TESTE DE SIMULAÇÃO ===${NC}"

[[ $EUID -ne 0 ]] && { echo -e "${RED}Execute como root${NC}"; exit 1; }

cleanup() {
    echo -e "${YELLOW}Limpando...${NC}"
    umount -R /mnt 2>/dev/null || true
    cryptsetup close cryptroot 2>/dev/null || true
    losetup -D 2>/dev/null || true
    rm -f test-*.img
}

trap cleanup EXIT

# Criar imagens
echo -e "${BLUE}Criando imagens de teste...${NC}"
dd if=/dev/zero of=test-ssd.img bs=1M count=4096 status=progress
dd if=/dev/zero of=test-hdd.img bs=1M count=2048 status=progress

# Config JSON
cat > test-config.json << JSON
{
  "disco_principal": "/dev/loop0",
  "disco_auxiliar": "/dev/loop1",
  "swap_gib": 1,
  "hostname": "test-arch",
  "username": "testuser",
  "user_password": "test123",
  "root_password": "root123",
  "luks_root_password": "luks123",
  "luks_aux_password": "luks456",
  "timezone": "America/Sao_Paulo",
  "locale": "pt_BR.UTF-8",
  "autodestruct_enabled": false
}
JSON

# Associar loops
losetup /dev/loop0 test-ssd.img
losetup /dev/loop1 test-hdd.img

echo -e "${GREEN}Executando fases...${NC}"

# Executar fases
./fase1-preparo.sh --simulate --non-interactive test-config.json
./fase2-disco-principal.sh
./fase3-disco-auxiliar.sh

echo -e "${GREEN}Teste concluído!${NC}"
echo -e "${YELLOW}Verificações:${NC}"
lsblk
[[ -b /dev/mapper/cryptroot ]] && echo -e "${GREEN}✓ LUKS root OK${NC}"
mount | grep -q /mnt && echo -e "${GREEN}✓ Montagens OK${NC}"

EOF

