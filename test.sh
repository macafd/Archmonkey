# ============================================================================
# TEST SIMULATE (CORRIGIDO)
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

# Verificar se scripts existem
for script in fase1-preparo.sh fase2-disco-principal.sh fase3-disco-auxiliar.sh; do
    if [[ ! -f "$script" ]]; then
        echo -e "${RED}Script $script não encontrado!${NC}"
        exit 1
    fi
done

cleanup() {
    echo -e "${YELLOW}Limpando ambiente de teste...${NC}"
    umount -R /mnt 2>/dev/null || true
    cryptsetup close cryptroot 2>/dev/null || true
    cryptsetup close cryptdata 2>/dev/null || true
    losetup -D 2>/dev/null || true
    rm -f test-*.img test-config.json
}

trap cleanup EXIT

# Criar imagens
echo -e "${BLUE}Criando imagens de teste...${NC}"
dd if=/dev/zero of=test-ssd.img bs=1M count=4096 status=progress
dd if=/dev/zero of=test-hdd.img bs=1M count=2048 status=progress

# Config JSON para teste
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
echo -e "${BLUE}Configurando dispositivos loopback...${NC}"
losetup /dev/loop0 test-ssd.img || { echo -e "${RED}Erro ao criar loop0${NC}"; exit 1; }
losetup /dev/loop1 test-hdd.img || { echo -e "${RED}Erro ao criar loop1${NC}"; exit 1; }

echo -e "${GREEN}Executando fases de teste...${NC}"

# Executar fases
./fase1-preparo.sh --simulate --non-interactive test-config.json || \
    { echo -e "${RED}Erro na fase 1${NC}"; exit 1; }

./fase2-disco-principal.sh || \
    { echo -e "${RED}Erro na fase 2${NC}"; exit 1; }

./fase3-disco-auxiliar.sh || \
    { echo -e "${RED}Erro na fase 3${NC}"; exit 1; }

echo -e "${GREEN}=== TESTE CONCLUÍDO COM SUCESSO ===${NC}"
echo -e "${YELLOW}Verificações:${NC}"

# Verificações
echo -e "${BLUE}Estrutura de disco:${NC}"
lsblk /dev/loop0 /dev/loop1 2>/dev/null || true

[[ -b /dev/mapper/cryptroot ]] && echo -e "${GREEN}✓ LUKS root criado${NC}" || echo -e "${RED}✗ LUKS root não encontrado${NC}"
mount | grep -q /mnt && echo -e "${GREEN}✓ Sistema montado${NC}" || echo -e "${RED}✗ Sistema não montado${NC}"

echo
echo -e "${YELLOW}Para limpar o ambiente de teste, execute:${NC}"
echo -e "${GREEN}umount -R /mnt; cryptsetup close cryptroot; losetup -D${NC}"
EOF

# Tornar todos os scripts executáveis
chmod +x *.sh

# Criar tarball
echo -e "${BLUE}Criando tarball...${NC}"
cd ..
tar -czf arch-secure-setup.tar.gz arch-secure-setup/

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              GERAÇÃO CONCLUÍDA COM SUCESSO!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Arquivo gerado: ${GREEN}arch-secure-setup.tar.gz${NC}"
echo -e "${YELLOW}Para usar:${NC}"
echo -e "  ${GREEN}tar -xzf arch-secure-setup.tar.gz${NC}"
echo -e "  ${GREEN}cd arch-secure-setup${NC}"
echo -e "  ${GREEN}./fase1-preparo.sh --help${NC}"
echo
echo -e "${RED}LEMBRE-SE: Este sistema realiza operações destrutivas!${NC}"
echo -e "${RED}Sempre teste primeiro com --simulate ou em VMs!${NC}"
