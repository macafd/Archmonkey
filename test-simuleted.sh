# ============================================================================
# SEPARADOR DE ARQUIVO
# ============================================================================

#!/bin/bash
# test_simulate.sh - Teste completo com dispositivos virtuais (CORRIGIDO)
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== TESTE DE SIMULAÇÃO ===${NC}"

# Verificar root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Execute como root${NC}"
    exit 1
fi

# Verificar se scripts existem
REQUIRED_SCRIPTS=(
    "fase1-preparo.sh"
    "fase2-disco-principal.sh" 
    "fase3-disco-auxiliar.sh"
    "fase4-base-system.sh"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [[ ! -f "$script" ]]; then
        echo -e "${RED}Script $script não encontrado!${NC}"
        exit 1
    fi
done

# Função de limpeza
cleanup() {
    echo -e "${YELLOW}Limpando ambiente de teste...${NC}"
    
    # Desmontar filesystems
    umount -R /mnt 2>/dev/null || true
    
    # Fechar volumes criptografados
    cryptsetup close cryptroot 2>/dev/null || true
    cryptsetup close cryptdata 2>/dev/null || true
    cryptsetup close cryptswap 2>/dev/null || true
    
    # Remover dispositivos loopback
    losetup -d /dev/loop0 2>/dev/null || true
    losetup -d /dev/loop1 2>/dev/null || true
    
    # Remover arquivos temporários
    rm -f test-*.img test-config.json 2>/dev/null || true
}

# Configurar trap para limpeza
trap cleanup EXIT

# Criar imagens de teste
echo -e "${BLUE}Criando imagens de teste...${NC}"

if [[ ! -f "test-ssd.img" ]]; then
    echo -e "${YELLOW}Criando imagem SSD (4GB)...${NC}"
    dd if=/dev/zero of=test-ssd.img bs=1M count=4096 status=progress
else
    echo -e "${GREEN}Imagem SSD já existe${NC}"
fi

if [[ ! -f "test-hdd.img" ]]; then
    echo -e "${YELLOW}Criando imagem HDD (2GB)...${NC}"
    dd if=/dev/zero of=test-hdd.img bs=1M count=2048 status=progress
else
    echo -e "${GREEN}Imagem HDD já existe${NC}"
fi

# Criar arquivo de configuração para teste
echo -e "${BLUE}Criando arquivo de configuração de teste...${NC}"
cat > test-config.json << JSON_EOF
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
  "autodestruct_enabled": false,
  "enable_backup_timer": false
}
JSON_EOF

# Limpar dispositivos loopback existentes
echo -e "${BLUE}Limpando dispositivos loopback antigos...${NC}"
losetup -d /dev/loop0 2>/dev/null || true
losetup -d /dev/loop1 2>/dev/null || true

# Associar loops
echo -e "${BLUE}Configurando dispositivos loopback...${NC}"
losetup /dev/loop0 test-ssd.img || {
    echo -e "${RED}Erro ao criar loop0${NC}"
    exit 1
}

losetup /dev/loop1 test-hdd.img || {
    echo -e "${RED}Erro ao criar loop1${NC}"
    exit 1
}

echo -e "${GREEN}Dispositivos loopback configurados:${NC}"
losetup -l | grep loop

# Executar fases de teste
echo -e "${BLUE}=== Executando Fase 1 ===${NC}"
./fase1-preparo.sh --simulate --non-interactive test-config.json || {
    echo -e "${RED}Erro na fase 1${NC}"
    exit 1
}

echo -e "${BLUE}=== Executando Fase 2 ===${NC}"
./fase2-disco-principal.sh || {
    echo -e "${RED}Erro na fase 2${NC}"
    exit 1
}

echo -e "${BLUE}=== Executando Fase 3 ===${NC}"
./fase3-disco-auxiliar.sh || {
    echo -e "${RED}Erro na fase 3${NC}"
    exit 1
}

# Verificações finais
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              TESTE CONCLUÍDO COM SUCESSO!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

echo -e "${YELLOW}Verificações:${NC}"

# Verificar estrutura de disco
echo -e "${BLUE}Estrutura de disco:${NC}"
lsblk /dev/loop0 /dev/loop1 2>/dev/null || true

# Verificar LUKS
if [[ -b /dev/mapper/cryptroot ]]; then
    echo -e "${GREEN}✓ LUKS root criado${NC}"
else
    echo -e "${RED}✗ LUKS root não encontrado${NC}"
fi

# Verificar montagem
if mount | grep -q /mnt; then
    echo -e "${GREEN}✓ Sistema montado${NC}"
    echo -e "${BLUE}Pontos de montagem:${NC}"
    mount | grep /mnt
else
    echo -e "${RED}✗ Sistema não montado${NC}"
fi

# Verificar subvolumes Btrfs
if [[ -d /mnt ]]; then
    echo -e "${BLUE}Verificando subvolumes Btrfs:${NC}"
    btrfs subvolume list /mnt 2>/dev/null || echo "  Não foi possível listar subvolumes"
fi

echo
echo -e "${YELLOW}Para continuar com a instalação de teste:${NC}"
echo -e "${GREEN}  ./fase4-base-system.sh${NC}"
echo
echo -e "${YELLOW}Para limpar o ambiente de teste:${NC}"
echo -e "${GREEN}  umount -R /mnt${NC}"
echo -e "${GREEN}  cryptsetup close cryptroot${NC}"
echo -e "${GREEN}  losetup -D${NC}"
echo -e "${GREEN}  rm -f test-*.img test-config.json${NC}"



