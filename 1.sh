#!/bin/bash
set -euo pipefail

# Variáveis (ajuste conforme necessário)
SSD="/dev/nvme0n1p2"
HDD="/dev/sdb2"

# Função de log
log() { echo "[SELFDESTRUCT] $*" >&2; }

# Configurar hook de auto-destruição
setup_selfdestruct_hook() {
    # Criar diretórios necessários
    mkdir -p /mnt/etc/initcpio/hooks
    mkdir -p /mnt/etc/initcpio/install

    # Criar hook
    cat > /mnt/etc/initcpio/hooks/wipe_on_fail << 'EOF'
#!/usr/bin/env bash
run_hook() {
    local dev name tries=0 max=5
    dev="/dev/nvme0n1p2"
    name="cryptroot"
    
    echo "[wipe_on_fail] Protegendo $dev ($name) - $max tentativas."
    while (( tries < max )); do
        if cryptsetup open "$dev" "$name"; then
            echo "[wipe_on_fail] Desbloqueado com sucesso."
            return 0
        else
            tries=$((tries+1))
            echo "[wipe_on_fail] Senha incorreta ($tries/$max)."
        fi
    done
    echo "[wipe_on_fail] Limite atingido. Iniciando destruição."
    /usr/local/sbin/selfdestruct.sh
}
EOF

    # Criar script de instalação do hook
    cat > /mnt/etc/initcpio/install/wipe_on_fail << 'EOF'
#!/usr/bin/env bash
build() {
    add_binary cryptsetup
    add_file /usr/local/sbin/selfdestruct.sh
    add_runscript
}
help() {
    cat <<'EOF'
Hook que limita tentativas de desbloqueio LUKS
EOF
}
EOF

    chmod 755 /mnt/etc/initcpio/hooks/wipe_on_fail
    chmod 755 /mnt/etc/initcpio/install/wipe_on_fail
}

# Configurar script de auto-destruição
setup_selfdestruct_script() {
    cat > /mnt/usr/local/sbin/selfdestruct.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
SSD="/dev/nvme0n1p2"
HDD="/dev/sdb2"
log() { echo "[SELFDESTRUCT] $*" >&2; }
nuke() {
    log "Apagando keyslots LUKS..."
    cryptsetup luksErase "$SSD" || true
    cryptsetup luksErase "$HDD" || true
    log "Sobrescrevendo discos..."
    dd if=/dev/urandom of="$SSD" bs=1M count=32 status=none || true
    dd if=/dev/urandom of="$HDD" bs=1M count=32 status=none || true
    sync
    systemctl poweroff -i
}
nuke
EOF
    chmod 700 /mnt/usr/local/sbin/selfdestruct.sh
}

# Executar configuração
setup_selfdestruct_hook
setup_selfdestruct_cript

# Adicionar hook ao mkinitcpio
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf block keyboard keymap wipe_on_fail encrypt filesystems fsck)/' /mnt/etc/mkinitcpio.conf

# Regenerar initramfs
arch-chroot /mnt mkinitcpio -P

echo "Configuração de auto-destruição concluída!"