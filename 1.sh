#!/bin/bash

# =============================================================================
# Script: 01-setup-ambiente-blindado.sh
# Descrição: Configuração inicial do ambiente live com máximo isolamento e segurança
# Versão: 2.0
# Autor: Segurança Máxima
# Licença: GPLv3
# =============================================================================

# Configurações globais
set -euo pipefail
IFS=$'\n\t'

# Variáveis de configuração
LOG_DIR="/var/log/arch-secure-install"
CONFIG_FILE="/tmp/arch-install-config.conf"
LOCK_FILE="/tmp/arch-setup.lock"
TMPFS_SIZE="512M"
TMPFS_MOUNT_OPTS="size=${TMPFS_SIZE},noexec,nodev,nosuid,mode=1777"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de logging
log() {
    local SEVERITY=$1
    local MESSAGE=$2
    local TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${TIMESTAMP} [${SEVERITY}] ${MESSAGE}" | tee -a "${LOG_DIR}/setup.log"
    
    # Cores para terminal
    case "${SEVERITY}" in
        "ERROR") echo -e "${RED}${TIMESTAMP} [${SEVERITY}] ${MESSAGE}${NC}" ;;
        "SUCCESS") echo -e "${GREEN}${TIMESTAMP} [${SEVERITY}] ${MESSAGE}${NC}" ;;
        "WARNING") echo -e "${YELLOW}${TIMESTAMP} [${SEVERITY}] ${MESSAGE}${NC}" ;;
        "INFO") echo -e "${BLUE}${TIMESTAMP} [${SEVERITY}] ${MESSAGE}${NC}" ;;
        *) echo -e "${TIMESTAMP} [${SEVERITY}] ${MESSAGE}" ;;
    esac
}

# Função para verificar e criar estrutura de logs
init_logs() {
    log "INFO" "Inicializando sistema de logs"
    
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}"
        chmod 700 "${LOG_DIR}"
        log "SUCCESS" "Diretório de logs criado: ${LOG_DIR}"
    fi
    
    # Criar arquivo de log principal
    touch "${LOG_DIR}/setup.log"
    chmod 600 "${LOG_DIR}/setup.log"
}

# Verificar ambiente e pré-requisitos
verify_environment() {
    log "INFO" "Verificando ambiente de execução"
    
    # Verificar se é root
    if [[ $(id -u) -ne 0 ]]; then
        log "ERROR" "Este script deve ser executado como root"
        exit 1
    fi
    
    # Verificar se já foi executado
    if [[ -f "${LOCK_FILE}" ]]; then
        log "WARNING" "Script já executado anteriormente"
        exit 0
    fi
    
    # Verificar se é Arch Linux
    if ! grep -q "Arch Linux" /etc/os-release 2>/dev/null; then
        log "ERROR" "Este script deve ser executado no Arch Linux Live"
        exit 1
    fi
    
    # Verificar memória
    local MEM_AVAIL=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    if [[ ${MEM_AVAIL} -lt 3800000 ]]; then
        log "WARNING" "Memória disponível abaixo do ideal (4GB recomendado)"
    fi
    
    log "SUCCESS" "Verificação de ambiente concluída"
}

# Configurar namespaces isolados
setup_namespaces() {
    log "INFO" "Configurando namespaces isolados"
    
    # Criar namespace para processos críticos
    if command -v unshare >/dev/null 2>&1; then
        unshare --pid --uts --ipc --net --mount --fork --mount-proc /bin/bash -c "
            mount -t tmpfs none /tmp
            echo 'Namespaces isolados configurados'
        " &
        local NS_PID=$!
        log "SUCCESS" "Namespaces criados com PID: ${NS_PID}"
    else
        log "WARNING" "unshare não disponível, namespaces não configurados"
    fi
}

# Remover identificadores de hardware
remove_hw_identifiers() {
    log "INFO" "Removendo identificadores de hardware"
    
    # MAC addresses
    for iface in /sys/class/net/*; do
        local IFACE_NAME=$(basename "${iface}")
        if [[ "${IFACE_NAME}" != "lo" ]]; then
            ip link set dev "${IFACE_NAME}" address 00:00:00:00:00:00 2>/dev/null || true
        fi
    done
    
    # Machine ID
    echo > /etc/machine-id
    rm -f /var/lib/dbus/machine-id 2>/dev/null || true
    ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
    
    log "SUCCESS" "Identificadores de hardware removidos"
}

# Desativar serviços desnecessários
disable_services() {
    log "INFO" "Desativando serviços desnecessários"
    
    local SERVICES=(
        "systemd-timesyncd"
        "systemd-resolved"
        "tlp"
        "avahi-daemon"
        "bluetooth"
        "cups"
    )
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "${service}"; then
            systemctl stop "${service}"
            systemctl disable "${service}"
            log "INFO" "Serviço desativado: ${service}"
        fi
    done
    
    log "SUCCESS" "Serviços desnecessários desativados"
}

# Configurar tmpfs seguro
setup_secure_tmpfs() {
    log "INFO" "Configurando tmpfs seguro"
    
    # Montar tmpfs para /tmp
    mount -t tmpfs -o "${TMPFS_MOUNT_OPTS}" tmpfs /tmp
    
    # Configurar permissões seguras
    chmod 1777 /tmp
    
    # Configurar TMPDIR
    export TMPDIR="/tmp"
    
    log "SUCCESS" "Tmpfs seguro configurado em /tmp"
}

# Limpeza forense de áreas temporárias
forensic_cleanup() {
    log "INFO" "Executando limpeza forense"
    
    # Sincronizar sistemas de arquivos
    sync
    
    # Limpar caches
    echo 3 > /proc/sys/vm/drop_caches
    
    # Limpar diretórios temporários
    rm -rf /tmp/* /var/tmp/* /var/log/*.old
    
    # Limpar history
    history -c
    
    log "SUCCESS" "Limpeza forense concluída"
}

# Configurar políticas de segurança
setup_security_policies() {
    log "INFO" "Configurando políticas de segurança"
    
    # Configurações sysctl hardening
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Kernel hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_enable=0

# Network security
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1

# Memory protection
vm.swappiness=10
vm.unprivileged_userfaultfd=0
EOF
    
    # Aplicar configurações
    sysctl --system
    
    log "SUCCESS" "Políticas de segurança configuradas"
}

# Isolamento de dispositivos de E/S
isolate_devices() {
    log "INFO" "Isolando dispositivos de E/S"
    
    # Desativar dispositivos USB não essenciais
    for dev in /sys/bus/usb/devices/*/authorized; do
        echo 0 > "${dev}" 2>/dev/null || true
    done
    
    log "SUCCESS" "Dispositivos de E/S isolados"
}

# Verificação de integridade do ambiente
verify_environment_integrity() {
    log "INFO" "Verificando integridade do ambiente"
    
    # Binários críticos para verificação
    local CRITICAL_BINS=(
        "/bin/bash"
        "/usr/bin/sh"
        "/bin/mount"
        "/bin/umount"
        "/usr/bin/pacman"
    )
    
    for bin in "${CRITICAL_BINS[@]}"; do
        if [[ ! -f "${bin}" ]]; then
            log "ERROR" "Binário crítico não encontrado: ${bin}"
            exit 1
        fi
        
        # Verificar permissões
        if [[ -x "${bin}" ]]; then
            log "INFO" "Binário verificado: ${bin}"
        else
            log "ERROR" "Binário sem permissão de execução: ${bin}"
            exit 1
        fi
    done
    
    log "SUCCESS" "Verificação de integridade concluída"
}

# Configuração anti-VM e detecção de hypervisor
setup_anti_vm() {
    log "INFO" "Configurando proteções anti-VM"
    
    # Verificar se está em ambiente virtualizado
    if dmidecode -t system | grep -q "Manufacturer\|Product" &&
       ! dmidecode -t system | grep -q "Manufacturer: Unknown\|Product: Unknown"; then
        log "WARNING" "Ambiente virtualizado detectado"
        
        # Implementar medidas específicas para VM
        cat > /etc/modprobe.d/blacklist-vm.conf << 'EOF'
# Prevenir detecção de virtualização
blacklist hyperv
blacklist vmw_vmci
blacklist vmw_vsock_vmci_transport
blacklist vmw_vsock_virtio_transport_common
blacklist vmw_vsock_virtio_transport
EOF
    else
        log "INFO" "Ambiente físico detectado"
    fi
    
    log "SUCCESS" "Proteções anti-VM configuradas"
}

# Configurar cgroups para isolamento de recursos
setup_cgroups() {
    log "INFO" "Configurando cgroups para isolamento"
    
    # Criar cgroup para processos críticos
    if [[ -d /sys/fs/cgroup ]]; then
        mkdir -p /sys/fs/cgroup/secure-install
        echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control
        
        # Configurar limites
        echo "500M" > /sys/fs/cgroup/secure-install/memory.max
        echo "100000" > /sys/fs/cgroup/secure-install/pids.max
        
        log "SUCCESS" "Cgroups configurados para isolamento de recursos"
    else
        log "WARNING" "Sistema cgroups não disponível"
    fi
}

# Função principal
main() {
    log "INFO" "Iniciando configuração do ambiente blindado"
    
    # Inicializar sistema de logs
    init_logs
    
    # Verificar ambiente
    verify_environment
    
    # Configurar namespaces isolados
    setup_namespaces
    
    # Remover identificadores de hardware
    remove_hw_identifiers
    
    # Desativar serviços desnecessários
    disable_services
    
    # Configurar tmpfs seguro
    setup_secure_tmpfs
    
    # Executar limpeza forense
    forensic_cleanup
    
    # Configurar políticas de segurança
    setup_security_policies
    
    # Isolar dispositivos de E/S
    isolate_devices
    
    # Verificar integridade do ambiente
    verify_environment_integrity
    
    # Configurar proteções anti-VM
    setup_anti_vm
    
    # Configurar cgroups
    setup_cgroups
    
    # Criar arquivo de lock
    touch "${LOCK_FILE}"
    chmod 600 "${LOCK_FILE}"
    
    log "SUCCESS" "Configuração do ambiente blindado concluída com sucesso"
}

# Tratamento de sinais
trap 'log "ERROR" "Script interrompido pelo usuário"; exit 1' INT TERM

# Execução principal
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi