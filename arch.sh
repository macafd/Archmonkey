#!/usr/bin/env bash
#
# install-arch-secure.sh
#
# Suíte de Instalação e Gerenciamento para Arch Linux. Foco em segurança,
# acessibilidade, backups completos e recuperação de desastres.
#
# VERSÃO: 4.2 

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# --- CONFIGURAÇÕES GLOBAIS ---
# =============================================================================

# Configurações básicas
SHOW_PASSWORDS="${SHOW_PASSWORDS:-0}"
TARGET_DISK="${TARGET_DISK:-}"
DATA_DISK="${DATA_DISK:-}"
ENABLE_DUAL_ENCRYPTION="${ENABLE_DUAL_ENCRYPTION:-0}"
ENABLE_AUTO_DESTRUCTION="${ENABLE_AUTO_DESTRUCTION:-1}"

# Particionamento
EFI_SIZE_MIB=512
BOOT_SIZE_MIB=1024
SWAP_SIZE_GB=4

# Configurações do sistema
HOSTNAME="${HOSTNAME:-arch-secure}"
TIMEZONE="America/Sao_Paulo"
LOCALE="pt_BR.UTF-8"
KEYMAP="br-abnt2"
USERNAME="${USERNAME:-operador}"
USER_FULL_NAME="${USER_FULL_NAME:-}"
USER_SHELL="/bin/bash"

# Criptografia
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512
LUKS_KDF="argon2id"
LUKS_PBKDF_MEM=1048576
LUKS_ITER_TIME=4000
PBKDF_PARALLEL=4

# LVM
VG_NAME="vg_system"
LV_ROOT_NAME="lv_root"
LV_SWAP_NAME="lv_swap"
LV_HOME_NAME="lv_home"
LV_ROOT_SIZE="30G"

# Flags de controle
REFORMAT_DATA_DISK=1
REINSTALL_KEEP_HOME=0

# =============================================================================
# --- VARIÁVEIS E HELPERS ---
# =============================================================================

# Cores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

# Funções de log
info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[AVISO]${NC} %s\n" "$*"; }
err() { printf "${RED}[ERRO]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[SUCESSO]${NC} %s\n" "$*"; }
prompt() { printf "${MAGENTA}>>>${NC} %s" "$*"; }
fatal() { err "$*"; exit 1; }

# Variáveis globais
LOGFILE="/var/log/install-arch-secure.log"
BOOT_MODE=""
MIN_BACKUP_SPACE=100  # Espaço mínimo em MB para backup

# =============================================================================
# --- FUNÇÕES DE SEGURANÇA ---
# =============================================================================

require_root() {
    (( EUID == 0 )) || fatal "Este script deve ser executado como root."
}

secure_cleanup() {
    info "Limpando dados sensíveis da memória..."
    unset LUKS_PASS DESTRUCTION_PASS ROOT_PASS USER_PASS PIN_DATA BACKUP_GPG_PASS || true
    [[ -d /tmp/arch_backup_local ]] && shred -vfzu -n 3 -r /tmp/arch_backup_local/* &>/dev/null
    rm -rf /tmp/arch_backup_local
    find /tmp -name '*.pw' -exec shred -vfzu -n 3 {} \; 2>/dev/null || true
    # Limpar chave temporária se existir
    [[ -f /tmp/data_disk.key.enc ]] && shred -vfzu -n 3 /tmp/data_disk.key.enc &>/dev/null || true
}
trap secure_cleanup EXIT INT TERM

# =============================================================================
# --- FUNÇÕES DE VALIDAÇÃO ---
# =============================================================================

check_dependencies() {
    local missing=()
    local essential_tools=(
        cryptsetup lvm2 sgdisk mkfs.fat mkfs.ext4 partprobe wipefs
        arch-chroot pacstrap genfstab curl lsblk blkid shred nmcli iwctl
    )
    
    for tool in "${essential_tools[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done

    if (( ${#missing[@]} > 0 )); then
        fatal "Ferramentas essenciais faltando: ${missing[*]}"
    fi
}

check_network() {
    info "Verificando conectividade de rede..."
    if ! ping -c 1 -W 3 archlinux.org >/dev/null 2>&1; then
        warn "Sem conexão com a internet. Tentando continuar com cache local..."
        return 1
    fi
    timedatectl set-ntp true
    return 0
}

detect_boot_mode() {
    [[ -d /sys/firmware/efi/efivars ]] && BOOT_MODE="UEFI" || BOOT_MODE="BIOS"
    [[ "$BOOT_MODE" == "UEFI" ]] || fatal "Somente modo UEFI é suportado"
    info "Modo de boot detectado: $BOOT_MODE"
}

# =============================================================================
# --- MÓDULO INTERATIVO ---
# =============================================================================

select_disks_interactive() {
    # Se discos já definidos por variáveis de ambiente
    if [[ -n "$TARGET_DISK" && -b "$TARGET_DISK" ]]; then
        info "Disco principal definido: $TARGET_DISK"
        if [[ -n "$DATA_DISK" && -b "$DATA_DISK" ]]; then
            info "Disco de dados definido: $DATA_DISK"
            ENABLE_DUAL_ENCRYPTION=1
            handle_data_disk_reuse
        fi
        return
    fi

    # Listar discos disponíveis
    info "Detectando discos disponíveis..."
    local devices=()
    while IFS= read -r line; do
        devices+=("$line")
    done < <(lsblk -d -n -o NAME,MODEL,SIZE,TYPE,TRAN | awk '{
        device="/dev/"$1; 
        $1=""; 
        print device " |" $0
    }' | grep -v "rom")

    (( ${#devices[@]} > 0 )) || fatal "Nenhum disco encontrado"

    # Selecionar disco principal
    PS3="Selecione o disco PRINCIPAL para instalação: "
    select opt in "${devices[@]}" "Cancelar"; do
        [[ "$opt" == "Cancelar" ]] && exit 0
        [[ -n "$opt" ]] && TARGET_DISK="${opt%% |*}" && break
    done
    info "Disco principal selecionado: $TARGET_DISK"

    # Selecionar disco de dados
    PS3="Selecione um disco SECUNDÁRIO para dados (ou 'Nenhum'): "
    select opt in "${devices[@]}" "Nenhum" "Cancelar"; do
        [[ "$opt" == "Cancelar" ]] && exit 0
        if [[ "$opt" == "Nenhum" ]]; then
            DATA_DISK=""
            ENABLE_DUAL_ENCRYPTION=0
            info "Nenhum disco secundário selecionado"
            break
        elif [[ -n "$opt" ]]; then
            DATA_DISK="${opt%% |*}"
            [[ "$DATA_DISK" != "$TARGET_DISK" ]] || {
                warn "Disco secundário não pode ser o mesmo que o principal"
                continue
            }
            ENABLE_DUAL_ENCRYPTION=1
            info "Disco secundário selecionado: $DATA_DISK"
            handle_data_disk_reuse
            break
        fi
    done
}

handle_data_disk_reuse() {
    [[ -n "$DATA_DISK" ]] || return
    local part_suffix=""
    [[ "$DATA_DISK" =~ nvme ]] && part_suffix="p"
    
    if cryptsetup isLuks "${DATA_DISK}${part_suffix}1" &>/dev/null; then
        PS3="Disco de dados já contém criptografia. Escolha ação: "
        select choice in "Manter dados existentes" "Formatar completamente" "Cancelar"; do
            case $REPLY in
                1) REFORMAT_DATA_DISK=0; break ;;
                2) REFORMAT_DATA_DISK=1; break ;;
                3) exit 0 ;;
                *) warn "Opção inválida" ;;
            esac
        done
    else
        REFORMAT_DATA_DISK=1
    fi
    info "Configuração disco dados: $([[ $REFORMAT_DATA_DISK -eq 1 ]] && echo "Formatar" || echo "Manter dados")"
}

collect_user_details() {
    # Coletar nome completo
    while [[ -z "$USER_FULL_NAME" ]]; do
        prompt "Nome completo do usuário: "
        read -r USER_FULL_NAME
    done

    # Sugerir nome de usuário
    local suggested_username
    suggested_username=$(echo "$USER_FULL_NAME" | \
        awk '{first=substr($1,1,1); rest=$2; gsub(/[^a-zA-Z]/, "", rest); 
              print tolower(first rest)}')
    
    prompt "Nome de login [padrão: $suggested_username]: "
    read -r username_input
    USERNAME="${username_input:-$suggested_username}"

    # Hostname
    prompt "Hostname do sistema [padrão: arch-secure]: "
    read -r hostname_input
    HOSTNAME="${hostname_input:-arch-secure}"

    # Senhas
    collect_passwords
}

collect_passwords() {
    local pw_files=()
    
    # Função auxiliar para coletar senha
    collect_pw() {
        local var_name="$1"
        local prompt_text="$2"
        local file_path
        # Usar mktemp para criar arquivos temporários de forma segura
        file_path=$(mktemp /tmp/arch-installer.XXXXXX.pw)
        
        while true; do
            prompt "$prompt_text: "
            read -rs password
            echo
            
            prompt "Confirme a senha: "
            read -rs password_confirm
            echo
            
            if [[ "$password" == "$password_confirm" && -n "$password" ]]; then
                printf "%s" "$password" > "$file_path"
                chmod 600 "$file_path"
                # CORREÇÃO 1: Uso de `printf -v` para atribuir a variável de forma segura,
                # evitando a vulnerabilidade de Command Injection presente no uso de `eval`.
                printf -v "$var_name" '%s' "$(<"$file_path")"
                pw_files+=("$file_path")
                break
            else
                warn "Senhas não coincidem ou estão vazias. Tente novamente."
            fi
        done
    }

    # Coletar todas as senhas necessárias
    collect_pw LUKS_PASS "Senha de criptografia do sistema (LUKS)"
    
    if (( ENABLE_AUTO_DESTRUCTION == 1 )); then
        collect_pw DESTRUCTION_PASS "Senha de auto-destruição (deve ser diferente)"
        [[ "$LUKS_PASS" != "$DESTRUCTION_PASS" ]] || 
            fatal "Senha de destruição deve ser diferente da senha LUKS"
    fi

    collect_pw ROOT_PASS "Senha do usuário root"
    collect_pw USER_PASS "Senha do usuário $USERNAME"
    
    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        collect_pw PIN_DATA "PIN para o disco de dados"
    fi

    # Limpar arquivos temporários
    sleep 1
    for file in "${pw_files[@]}"; do
        shred -fu -z "$file" &>/dev/null || true
    done
}

configure_network() {
    PS3="Selecione o tipo de conexão de rede: "
    select choice in "Ethernet (DHCP automático)" "Wi-Fi (configurar manualmente)" "Pular configuração de rede"; do
        case $REPLY in
            1)
                info "Configurando Ethernet via DHCP..."
                # CORREÇÃO 2: Detectar dinamicamente o nome do dispositivo Ethernet em vez de usar um nome fixo
                # como 'eth0'. Isso garante compatibilidade com hardware moderno (ex: 'enp3s0').
                local eth_device
                eth_device=$(nmcli -t -f DEVICE,TYPE device | awk -F: '/ethernet/{print $1; exit}')
                
                if [[ -n "$eth_device" ]]; then
                    # Reiniciar o NetworkManager pode resolver problemas no ambiente live.
                    if systemctl restart NetworkManager && nmcli device connect "$eth_device"; then
                        success "Conexão Ethernet estabelecida em '$eth_device'"
                        return 0
                    fi
                else
                    warn "Nenhum dispositivo Ethernet encontrado."
                fi
                ;;
            2)
                configure_wifi
                return $?
                ;;
            3)
                warn "Configuração de rede pulada"
                return 0
                ;;
        esac
        warn "Falha na configuração. Tente novamente"
    done
}

configure_wifi() {
    # Verificar dependências
    if ! command -v iwctl &>/dev/null; then
        warn "iwctl não disponível. Instalando iwd..."
        pacman -Sy --noconfirm iwd >/dev/null 2>&1 || {
            err "Falha ao instalar iwd"
            return 1
        }
    fi

    # Iniciar serviço
    systemctl start iwd >/dev/null 2>&1

    # Selecionar dispositivo
    local devices
    mapfile -t devices < <(iwctl device list | awk '/station/{print $2}')
    (( ${#devices[@]} > 0 )) || {
        err "Nenhum dispositivo Wi-Fi encontrado"
        return 1
    }

    PS3="Selecione o dispositivo Wi-Fi: "
    select device in "${devices[@]}" "Cancelar"; do
        [[ "$device" == "Cancelar" ]] && return 1
        [[ -n "$device" ]] && break
    done

    # Escanear redes
    iwctl station "$device" scan
    sleep 5
    
    local networks
    mapfile -t networks < <(iwctl station "$device" get-networks | \
        awk 'NR>3 && NF>0 {print $1}' | sort -u)

    PS3="Selecione a rede Wi-Fi: "
    select network in "${networks[@]}" "Re-escanear" "Cancelar"; do
        case $network in
            "Cancelar") return 1 ;;
            "Re-escanear")
                iwctl station "$device" scan
                sleep 5
                mapfile -t networks < <(iwctl station "$device" get-networks | \
                    awk 'NR>3 && NF>0 {print $1}' | sort -u)
                ;;
            *)
                [[ -n "$network" ]] && break
                ;;
        esac
    done

    # Conectar
    prompt "Senha para '$network': "
    read -rs wifi_pass
    echo
    
    if iwctl --passphrase "$wifi_pass" station "$device" connect "$network"; then
        success "Conectado a $network"
        return 0
    else
        err "Falha ao conectar. Verifique a senha"
        return 1
    fi
}

# =============================================================================
# --- MÓDULO DE BACKUP ---
# =============================================================================

select_usb_device() {
    info "Detectando dispositivos USB..."
    local usb_devices=()
    while IFS= read -r line; do
        usb_devices+=("$line")
    done < <(lsblk -d -o NAME,MODEL,SIZE,TRAN,HOTPLUG | \
             awk '/usb.*1$/ {print "/dev/"$1, "|", $2, $3}')

    (( ${#usb_devices[@]} > 0 )) || {
        warn "Nenhum dispositivo USB encontrado"
        return 1
    }

    PS3="Selecione o dispositivo USB para backup: "
    select device in "${usb_devices[@]}" "Cancelar"; do
        [[ "$device" == "Cancelar" ]] && return 1
        [[ -n "$device" ]] && {
            echo "${device%% |*}"
            return 0
        }
    done
    return 1
}

create_backup() {
    local backup_device
    backup_device=$(select_usb_device) || return 1

    # Montar dispositivo
    local mount_point="/mnt/arch_backup_$(date +%s)"
    mkdir -p "$mount_point"
    
    if ! mount "${backup_device}1" "$mount_point" 2>/dev/null && 
       ! mount "$backup_device" "$mount_point" 2>/dev/null; then
        err "Falha ao montar o dispositivo"
        rmdir "$mount_point"
        return 1
    fi

    # Verificar espaço
    local available_space
    available_space=$(df -m "$mount_point" | awk 'NR==2{print $4}')
    (( available_space > MIN_BACKUP_SPACE )) || {
        err "Espaço insuficiente no dispositivo (mínimo ${MIN_BACKUP_SPACE}MB)"
        umount "$mount_point"
        rmdir "$mount_point"
        return 1
    }

    # Criar estrutura de backup
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${mount_point}/arch_backup_${HOSTNAME}_${timestamp}"
    mkdir -p "$backup_dir"
    
    # Backup cabeçalhos LUKS
    info "Backup cabeçalhos LUKS..."
    local part_suffix
    [[ "$TARGET_DISK" =~ nvme ]] && part_suffix="p" || part_suffix=""
    cryptsetup luksHeaderBackup "${TARGET_DISK}${part_suffix}3" \
        --header-backup-file "${backup_dir}/luks_system.img"
    
    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        [[ "$DATA_DISK" =~ nvme ]] && part_suffix="p" || part_suffix=""
        cryptsetup luksHeaderBackup "${DATA_DISK}${part_suffix}1" \
            --header-backup-file "${backup_dir}/luks_data.img"
    fi

    # Backup GRUB e SecureBoot
    if [[ -d /mnt/boot/grub ]]; then
        info "Backup configuração GRUB..."
        mkdir -p "${backup_dir}/grub"
        cp -r /mnt/boot/grub "${backup_dir}/grub"
        cp /mnt/etc/default/grub "${backup_dir}/grub"
    fi

    if [[ -d /mnt/etc/secureboot ]]; then
        info "Backup chaves SecureBoot..."
        mkdir -p "${backup_dir}/secureboot"
        cp -r /mnt/etc/secureboot "${backup_dir}/secureboot"
    fi

    # Criar checksum
    info "Verificando integridade..."
    (cd "$backup_dir" && sha256sum ./* > "checksum.sha256")

    # Criptografar opcionalmente
    prompt "Criptografar backup com GPG? (s/N) "
    read -n1 -r encrypt_choice
    echo
    if [[ $encrypt_choice =~ ^[Ss]$ ]]; then
        local gpg_file="${backup_dir}.tar.gz.gpg"
        prompt "Senha para criptografia GPG: "
        read -rs gpg_pass
        echo
        
        tar czf - -C "$mount_point" "$(basename "$backup_dir")" | \
            gpg --batch --passphrase-fd 0 -c -o "$gpg_file" <<< "$gpg_pass"
        
        sha256sum "$gpg_file" > "${gpg_file}.sha256"
        rm -rf "$backup_dir"
        success "Backup criptografado salvo: $(basename "$gpg_file")"
    else
        success "Backup completo salvo em: $backup_dir"
    fi

    # Desmontar e limpar
    umount "$mount_point"
    rmdir "$mount_point"
}

# =============================================================================
# --- MÓDULO DE INSTALAÇÃO ---
# =============================================================================

prepare_disk() {
    info "Preparando discos..."
    
    # Limpar discos
    for disk in "$TARGET_DISK" "$DATA_DISK"; do
        [[ -b "$disk" ]] || continue
        wipefs -af "$disk" >/dev/null
        dd if=/dev/zero of="$disk" bs=1M count=100 status=none
    done

    # Particionar disco principal
    part_suffix=""
    [[ "$TARGET_DISK" =~ nvme ]] && part_suffix="p"
    
    sgdisk --zap-all "$TARGET_DISK"
    sgdisk -n 1:0:+${EFI_SIZE_MIB}M -t 1:ef00 -c 1:"EFI" "$TARGET_DISK"
    sgdisk -n 2:0:+${BOOT_SIZE_MIB}M -t 2:8300 -c 2:"Boot" "$TARGET_DISK"
    sgdisk -n 3:0:0 -t 3:8e00 -c 3:"LVM" "$TARGET_DISK"
    partprobe "$TARGET_DISK"

    # Formatar partições
    mkfs.fat -F32 "${TARGET_DISK}${part_suffix}1"
    mkfs.ext4 -F "${TARGET_DISK}${part_suffix}2"

    # Preparar disco secundário se necessário
    if (( ENABLE_DUAL_ENCRYPTION == 1 && REFORMAT_DATA_DISK == 1 )); then
        part_suffix=""
        [[ "$DATA_DISK" =~ nvme ]] && part_suffix="p"
        sgdisk --zap-all "$DATA_DISK"
        sgdisk -n 1:0:0 -t 1:8300 -c 1:"LUKS Data" "$DATA_DISK"
        partprobe "$DATA_DISK"
    fi
}

setup_encryption() {
    info "Configurando criptografia..."
    local part_suffix
    [[ "$TARGET_DISK" =~ nvme ]] && part_suffix="p" || part_suffix=""
    local luks_part="${TARGET_DISK}${part_suffix}3"

    # Configurar LUKS no disco principal
    echo -n "$LUKS_PASS" | cryptsetup luksFormat \
        --type luks2 \
        --cipher "$LUKS_CIPHER" \
        --key-size "$LUKS_KEY_SIZE" \
        --pbkdf "$LUKS_KDF" \
        --pbkdf-memory "$LUKS_PBKDF_MEM" \
        --iter-time "$LUKS_ITER_TIME" \
        --label "cryptsystem" \
        "$luks_part" -

    echo -n "$LUKS_PASS" | cryptsetup open "$luks_part" cryptroot

    # Configurar LVM
    pvcreate /dev/mapper/cryptroot
    vgcreate "$VG_NAME" /dev/mapper/cryptroot
    lvcreate -L "$LV_ROOT_SIZE" -n "$LV_ROOT_NAME" "$VG_NAME"
    lvcreate -L "${SWAP_SIZE_GB}G" -n "$LV_SWAP_NAME" "$VG_NAME"
    lvcreate -l '100%FREE' -n "$LV_HOME_NAME" "$VG_NAME"

    # Formatar volumes lógicos
    mkfs.ext4 "/dev/$VG_NAME/$LV_ROOT_NAME"
    mkfs.ext4 "/dev/$VG_NAME/$LV_HOME_NAME"
    mkswap "/dev/$VG_NAME/$LV_SWAP_NAME"

    # Configurar disco secundário se necessário
    if (( ENABLE_DUAL_ENCRYPTION == 1 )); then
        part_suffix=""
        [[ "$DATA_DISK" =~ nvme ]] && part_suffix="p" || part_suffix=""
        local data_part="${DATA_DISK}${part_suffix}1"
        
        # Criar keyfile
        # CORREÇÃO 3: Uso de /dev/urandom para evitar bloqueios por falta de entropia,
        # que podem ocorrer com /dev/random em VMs ou sistemas recém-iniciados.
        dd if=/dev/urandom of=/tmp/hd_keyfile bs=64 count=1 &>/dev/null
        chmod 600 /tmp/hd_keyfile
        
        # Configurar LUKS
        cryptsetup luksFormat \
            --type luks2 \
            --cipher "$LUKS_CIPHER" \
            --key-size "$LUKS_KEY_SIZE" \
            --key-file /tmp/hd_keyfile \
            --label "cryptdata" \
            "$data_part"
        
        # Criptografar keyfile com PIN
        # CORREÇÃO 4 (Parte 1): Salvar a chave criptografada em /tmp. Ela será movida
        # para o local correto (/mnt/etc/...) após a montagem dos sistemas de arquivos.
        echo -n "$PIN_DATA" | openssl enc -e -aes-256-cbc -pbkdf2 -iter 100000 \
            -pass stdin -in /tmp/hd_keyfile -out /tmp/data_disk.key.enc
        
        shred -u /tmp/hd_keyfile
    fi
}

mount_filesystems() {
    info "Montando sistemas de arquivos..."
    local part_suffix
    [[ "$TARGET_DISK" =~ nvme ]] && part_suffix="p" || part_suffix=""
    
    mount "/dev/$VG_NAME/$LV_ROOT_NAME" /mnt
    mkdir -p /mnt/{boot,home}
    mount "/dev/$VG_NAME/$LV_HOME_NAME" /mnt/home
    mount "${TARGET_DISK}${part_suffix}2" /mnt/boot
    mkdir -p /mnt/boot/efi
    mount "${TARGET_DISK}${part_suffix}1" /mnt/boot/efi
    swapon "/dev/$VG_NAME/$LV_SWAP_NAME"
}

install_system() {
    info "Instalando sistema base..."
    local packages=(
        base base-devel linux linux-firmware lvm2 grub efibootmgr sudo nano 
        networkmanager openssl curl intel-ucode amd-ucode iwd
    )
    
    pacstrap /mnt "${packages[@]}" || {
        err "Falha na instalação. Verifique conexão de rede"
        return 1
    }
    
    info "Gerando fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab
}

configure_chroot() {
    info "Configurando sistema instalado..."
    local system_luks_uuid
    system_luks_uuid=$(blkid -s UUID -o value "${TARGET_DISK}$([[ "$TARGET_DISK" =~ nvme ]] && echo "p3" || echo "3")")
    
    arch-chroot /mnt /bin/bash <<EOF
set -euo pipefail

# Configurações básicas
echo "$HOSTNAME" > /etc/hostname
ln -sf /usr/share/zoneinfo/$TIMEZONE /etc/localtime
hwclock --systohc
sed -i "s/^#$LOCALE/$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
echo "KEYMAP=$KEYMAP" > /etc/vconsole.conf

# Configurar rede
echo "127.0.0.1 localhost" >> /etc/hosts
echo "::1       localhost" >> /etc/hosts
echo "127.0.1.1 $HOSTNAME.localdomain $HOSTNAME" >> /etc/hosts
systemctl enable NetworkManager.service
systemctl enable iwd.service

# Configurar usuários
echo "root:$ROOT_PASS" | chpasswd
useradd -m -s "$USER_SHELL" -G wheel -c "$USER_FULL_NAME" "$USERNAME"
echo "$USERNAME:$USER_PASS" | chpasswd
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

# Configurar bootloader
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck)/' /etc/mkinitcpio.conf
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=$system_luks_uuid:cryptroot root=/dev/$VG_NAME/$LV_ROOT_NAME\"|" /etc/default/grub
sed -i 's/^#GRUB_ENABLE_CRYPTODISK=y/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub

mkinitcpio -P
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable
grub-mkconfig -o /boot/grub/grub.cfg

# Limpar dados sensíveis
# CORREÇÃO 5: Uso de 'history -c' para limpar o histórico da sessão atual.
# É mais seguro e robusto que 'rm /root/.bash_history', que falharia se o arquivo não existisse, abortando o script.
history -c
EOF
}

# =============================================================================
# --- FLUXO PRINCIPAL ---
# =============================================================================

main_flow() {
    require_root
    check_dependencies
    detect_boot_mode
    
    # Interface inicial
    echo -e "\n${GREEN}===== INSTALADOR ARCH LINUX SEGURO v4.2 =====${NC}"
    echo -e "${YELLOW}AVISO: Este script irá modificar seus discos!${NC}\n"
    
    # Seleção interativa
    select_disks_interactive
    collect_user_details
    configure_network
    
    # Confirmação final
    echo -e "\n${RED}===== RESUMO DA INSTALAÇÃO =====${NC}"
    echo "Disco Principal: $TARGET_DISK"
    echo "Disco Dados: ${DATA_DISK:-Nenhum}"
    echo "Hostname: $HOSTNAME"
    echo "Usuário: $USERNAME ($USER_FULL_NAME)"
    echo -e "\n${RED}ESTA AÇÃO É IRREVERSÍVEL E APAGARÁ DADOS!${NC}"
    
    prompt "Digite 'CONFIRMO' para continuar: "
    read -r confirmation
    [[ "$confirmation" == "CONFIRMO" ]] || exit 0
    
    # Processo de instalação
    prepare_disk
    setup_encryption
    mount_filesystems

    # CORREÇÃO 4 (Parte 2): Mover a chave do disco de dados para o local correto.
    # Este passo é crucial para que o disco de dados possa ser desbloqueado no sistema instalado.
    if [[ -f /tmp/data_disk.key.enc ]]; then
        info "Movendo chave do disco de dados para o destino..."
        mkdir -p /mnt/etc/cryptsetup-keys.d
        mv /tmp/data_disk.key.enc /mnt/etc/cryptsetup-keys.d/data_disk.key.enc
        chmod 600 /mnt/etc/cryptsetup-keys.d/data_disk.key.enc
    fi

    install_system
    configure_chroot
    
    # Backup
    prompt "Deseja criar backup de recuperação? (S/n) "
    read -n1 -r backup_choice
    echo
    if [[ ! $backup_choice =~ ^[Nn]$ ]]; then
        create_backup || warn "Backup não concluído"
    fi
    
    # Finalização
    umount -R /mnt
    swapoff -a
    cryptsetup close cryptroot
    
    echo -e "\n${GREEN}Instalação concluída com sucesso!${NC}"
    echo -e "Execute ${CYAN}reboot${NC} para reiniciar o sistema\n"
}

# Ponto de entrada
[[ "${BASH_SOURCE[0]}" == "$0" ]] && {
    # Configurar logging
    if (( SHOW_PASSWORDS == 1 )); then
        LOGFILE="/dev/null"
        warn "Modo de senhas visíveis - Log desabilitado"
    else
        touch "$LOGFILE"
        chmod 600 "$LOGFILE"
        exec > >(tee -a "$LOGFILE") 2>&1
    fi
    
    main_flow
}
