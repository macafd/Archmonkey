# ============================================================================
# SEPARADOR DE ARQUIVO  
# ============================================================================

#!/bin/bash
# validate-installation.sh - Valida instalação completa
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== VALIDAÇÃO DA INSTALAÇÃO ===${NC}"

# Função de verificação
check_item() {
    local description="$1"
    local command="$2"
    
    if eval "$command" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $description"
        return 0
    else
        echo -e "${RED}✗${NC} $description"
        return 1
    fi
}

# Contador de erros
ERRORS=0

echo -e "${BLUE}Verificando scripts principais:${NC}"
check_item "fase1-preparo.sh existe" "[[ -f fase1-preparo.sh ]]" || ((ERRORS++))
check_item "fase2-disco-principal.sh existe" "[[ -f fase2-disco-principal.sh ]]" || ((ERRORS++))
check_item "fase3-disco-auxiliar.sh existe" "[[ -f fase3-disco-auxiliar.sh ]]" || ((ERRORS++))
check_item "fase4-base-system.sh existe" "[[ -f fase4-base-system.sh ]]" || ((ERRORS++))
check_item "fase5-config-chroot.sh existe" "[[ -f fase5-config-chroot.sh ]]" || ((ERRORS++))
check_item "fase6-backup-scripts.sh existe" "[[ -f fase6-backup-scripts.sh ]]" || ((ERRORS++))
check_item "fase7-autodestruicao.sh existe" "[[ -f fase7-autodestruicao.sh ]]" || ((ERRORS++))

echo
echo -e "${BLUE}Verificando arquivos auxiliares:${NC}"
check_item "config.example.json existe" "[[ -f config.example.json ]]" || ((ERRORS++))
check_item "README.md existe" "[[ -f README.md ]]" || ((ERRORS++))
check_item "test_simulate.sh existe" "[[ -f test_simulate.sh ]]" || ((ERRORS++))

echo
echo -e "${BLUE}Verificando permissões:${NC}"
for script in *.sh; do
    if [[ -f "$script" ]]; then
        check_item "$script é executável" "[[ -x $script ]]" || {
            chmod +x "$script"
            echo -e "  ${YELLOW}Corrigido: chmod +x $script${NC}"
        }
    fi
done

echo
echo -e "${BLUE}Verificando sintaxe dos scripts:${NC}"
for script in *.sh; do
    if [[ -f "$script" ]]; then
        if bash -n "$script" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} $script sintaxe OK"
        else
            echo -e "${RED}✗${NC} $script tem erros de sintaxe"
            ((ERRORS++))
        fi
    fi
done

echo
echo -e "${BLUE}Verificando JSON:${NC}"
if command -v jq &>/dev/null; then
    if [[ -f config.example.json ]]; then
        if jq empty config.example.json 2>/dev/null; then
            echo -e "${GREEN}✓${NC} config.example.json é JSON válido"
        else
            echo -e "${RED}✗${NC} config.example.json tem erros de JSON"
            ((ERRORS++))
        fi
    fi
else
    echo -e "${YELLOW}⚠${NC} jq não instalado, pulando validação JSON"
fi

echo
echo -e "${BLUE}Resultado da validação:${NC}"
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           TODOS OS TESTES PASSARAM COM SUCESSO!             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}A instalação está pronta para uso!${NC}"
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              FORAM ENCONTRADOS $ERRORS ERROS!                    ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}Corrija os erros antes de usar os scripts!${NC}"
    exit 1
fi
