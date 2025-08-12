#!/usr/bin/env bash
#
# /mnt/data/arch.sh
#
# Script de instalação do Arch Linux modificado para incluir interatividade,
# robustez aprimorada e melhores práticas de scripting.
# Este script automatiza a instalação de um sistema Arch Linux com criptografia
# de disco completo (LUKS sobre LVM), com opções para recursos avançados de segurança.

# --- Configuração de Segurança do Script ---
# set -e: Aborta o script imediatamente se um comando falhar.
# set -u: Trata variáveis não definidas como um erro.
# set -o pipefail: Faz com que um pipeline falhe se qualquer comando nele falhar, não apenas o último.
# IFS: Define o separador de campo interno para nova linha e tabulação, tornando o tratamento de nomes de arquivo mais seguro.
set -euo pipefail
IFS=$'\n\t'

# --- Variáveis Globais e Constantes ---
# Cores para a saída do console
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Arquivo de log para registrar toda a saída da instalação
readonly LOGFILE="/var/log/arch-install-$(date +%Y%m%d-%H%M%S).log"

# --- Funções de Utilitários e Logging ---

# Função para configurar o logging para o console e um arquivo de log seguro.
# Garante que o arquivo de log só possa ser lido pelo root.
setup_logging() {
    touch "$LOGFILE"
    chmod 600 "$LOGFILE"
    # Redireciona stdout e stderr para o console (através do tee) e para o arquivo de log.
    exec > >(tee -a "$LOGFILE") 2>&1
    echo "Logging iniciado em: $LOGFILE"
}

# Função para exibir e executar comandos externos de forma segura.
# Prefixa cada comando com '[CMD]' para clareza no log.
run_cmd() {
    echo -e "${BLUE}[CMD]${NC} $@"
    "$@"
}

# Função para validar a existência de todos os comandos necessários para a instalação.
# Se algum comando estiver faltando, o script aborta com uma lista dos ausentes.
check_dependencies() {
    echo "[INFO] Verificando dependências de comandos..."
    local missing_tools=()
    # Lista de comandos essenciais para a execução do script.
    local required_tools=(
        lsblk sgdisk dd pv blockdev cryptsetup wipefs
        pvcreate vgcreate lvcreate mkfs.ext4 mkfs.vfat mkswap
        pacstrap genfstab arch-chroot grub-install grub-mkconfig
        partprobe timedatectl openssl
    )

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if (( ${#missing_tools[@]} > 0 )); then
        echo -e "${RED}[ERRO] As seguintes ferramentas necessárias não foram encontradas: ${missing_tools[*]}${NC}"
        echo -e "${RED}Por favor, instale-as no ambiente live e tente novamente.${NC}"
        exit 1
    fi
    echo "[INFO] Todas as dependências foram encontradas."
}

# --- Funções de Coleta de Dados do Usuário ---

# Função para obter o nome do host (hostname) do usuário.
# Valida que o nome não está vazio.
prompt_for_hostname() {
    local hostname_input
    while true; do
        read -rp "Digite o nome do host (hostname) para o novo sistema: " hostname_input
        if [[ -n "$hostname_input" ]]; then
            HOSTNAME="$hostname_input"
            break
        else
            echo -e "${YELLOW}[AVISO] O nome do host não pode ser vazio.${NC}"
        fi
    done
}

# Função para obter o nome de usuário.
# Valida que o nome não está vazio.
prompt_for_username() {
    local username_input
    while true; do
        read -rp "Digite o nome para o novo usuário (ex: 'operador'): " username_input
        if [[ -n "$username_input" ]]; then
            USERNAME="$username_input"
            break
        else
            echo -e "${YELLOW}[AVISO] O nome de usuário não pode ser vazio.${NC}"
        fi
    done
}

# Função para listar os discos disponíveis e permitir que o usuário escolha um.
# Valida que a escolha é um dispositivo de bloco válido.
prompt_for_disk() {
    echo "[INFO] Discos disponíveis para instalação:"
    # Exibe discos (tipo 'disk') com nome, tamanho e tipo.
    lsblk -d -o NAME,SIZE,TYPE | grep 'disk'
    echo

    local disk_choice
    while true; do
        read -rp "Digite o nome do disco para instalar o Arch Linux (ex: sda, nvme0n1): " disk_choice
        # Constrói o caminho completo do dispositivo.
        local disk_path="/dev/${disk_choice}"

        if [[ -b "$disk_path" ]]; then
            TARGET_DISK="$disk_path"
            echo "[INFO] Disco selecionado: $TARGET_DISK"
            break
        else
            echo -e "${YELLOW}[AVISO] Disco inválido: '$disk_choice'. Por favor, escolha um da lista acima.${NC}"
        fi
    done
}

# --- Funções de Segurança e Confirmação ---

# Função para exibir um aviso crítico e exigir confirmação explícita do usuário
# antes de prosseguir com operações destrutivas.
confirm_destruction() {
    echo -e "\n${RED}=================================================="
    echo -e "            AVISO: OPERAÇÃO DESTRUTIVA"
    echo -e "==================================================${NC}"
    echo "Este script irá ${RED}APAGAR COMPLETAMENTE${NC} todos os dados no disco selecionado."
    echo
    echo -e "  - Disco Alvo: ${YELLOW}${TARGET_DISK}${NC}"
    echo -e "  - Hostname:   ${YELLOW}${HOSTNAME}${NC}"
    echo -e "  - Usuário:    ${YELLOW}${USERNAME}${NC}"
    echo
    echo -e "${RED}ESTA AÇÃO É IRREVERSÍVEL. FAÇA BACKUP DE SEUS DADOS!${NC}"
    echo -e "${RED}==================================================${NC}\n"

    local confirmation
    read -rp "Para confirmar que você entende e deseja continuar, digite 's': " confirmation
    if [[ "${confirmation,,}" != "s" ]]; then
        echo "[INFO] Operação cancelada pelo usuário. Saindo."
        exit 0
    fi
    echo "[INFO] Confirmação recebida. Prosseguindo com a instalação..."
}

# Função para zerar um disco usando 'dd' com uma barra de progresso via 'pv'.
# Isso apaga com segurança os dados antigos e os metadados da tabela de partição.
zero_disk_with_pv() {
    local disk_to_wipe="$1"
    echo "[INFO] Preparando para apagar completamente o disco $disk_to_wipe..."

    # Obtém o tamanho do disco em bytes.
    local disk_size
    disk_size=$(blockdev --getsize64 "$disk_to_wipe")

    if (( disk_size == 0 )); then
        echo -e "${RED}[ERRO] Não foi possível determinar o tamanho do disco $disk_to_wipe.${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[AVISO] A operação a seguir irá sobrescrever ${disk_to_wipe} com zeros. Isso pode levar muito tempo.${NC}"
    
    # Executa dd para ler de /dev/zero, passa por pv para mostrar o progresso, e escreve no disco.
    if ! (dd if=/dev/zero bs=1M status=none | pv -s "$disk_size" | dd of="$disk_to_wipe" bs=1M status=none); then
        echo -e "${RED}[ERRO] Falha ao apagar o disco $disk_to_wipe. Verifique os logs.${NC}"
        exit 1
    fi
    
    echo "[INFO] Disco $disk_to_wipe apagado com sucesso."
    # Força o kernel a reler a tabela de partição.
    run_cmd partprobe "$disk_to_wipe"
}

# --- Funções de Instalação (Modularizadas) ---

# Valida o ambiente de execução (root, modo UEFI).
validate_environment() {
    echo "[INFO] Validando ambiente de instalação..."
    if (( EUID != 0 )); then
        echo -e "${RED}[ERRO] Este script deve ser executado como root.${NC}"
        exit 1
    fi

    if [[ ! -d /sys/firmware/efi/efivars ]]; then
        echo -e "${RED}[ERRO] Sistema não parece ter sido iniciado em modo UEFI. Verifique a configuração da sua BIOS.${NC}"
        exit 1
    fi
    echo "[INFO] Ambiente validado com sucesso (root e UEFI)."
}

# Limpa metadados antigos (LUKS, LVM, partições) do disco alvo.
sanitize_disk() {
    local disk="$1"
    echo "[INFO] Limpando metadados e tabelas de partição em $disk..."
    
    # Desmonta quaisquer partições montadas do disco alvo.
    umount -R "${disk}"* &>/dev/null || true
    
    # Desativa quaisquer volumes LVM ou containers LUKS que possam estar ativos no disco.
    vgchange -an &>/dev/null || true
    cryptsetup close /dev/mapper/* &>/dev/null || true

    # Apaga assinaturas de filesystem, RAID e partições.
    run_cmd wipefs --all "$disk"
    # Apaga a tabela de partição GPT.
    run_cmd sgdisk --zap-all "$disk"
    
    # Zera o início do disco para garantir que o GRUB antigo seja removido.
    run_cmd dd if=/dev/zero of="$disk" bs=1M count=100 status=none
    
    run_cmd partprobe "$disk"
    echo "[INFO] Limpeza de $disk concluída."
}

# Particiona o disco do sistema (EFI, Boot, Sistema LUKS).
partition_disk() {
    local disk="$1"
    echo "[INFO] Particionando o disco $disk..."

    # Define o sufixo da partição ('p' para NVMe/MMC, nada para SATA/SCSI).
    local p_suffix
    [[ "$disk" =~ nvme|mmcblk ]] && p_suffix="p" || p_suffix=""

    # Define variáveis para os caminhos das partições para maior clareza.
    EFI_PART="${disk}${p_suffix}1"
    BOOT_PART="${disk}${p_suffix}2"
    LUKS_PART="${disk}${p_suffix}3"

    # Cria as partições usando sgdisk.
    # 1: Partição de Sistema EFI (512 MiB)
    run_cmd sgdisk -n 1:0:+512M -t 1:ef00 -c 1:"EFI System" "$disk"
    # 2: Partição de Boot (1 GiB)
    run_cmd sgdisk -n 2:0:+1024M -t 2:8300 -c 2:"Boot" "$disk"
    # 3: Partição do Sistema (resto do disco) para LUKS/LVM
    run_cmd sgdisk -n 3:0:0 -t 3:8300 -c 3:"System" "$disk"

    run_cmd partprobe "$disk"
    sleep 2 # Aguarda o kernel reconhecer as novas partições.
    echo "[INFO] Particionamento concluído."
}

# Configura a criptografia LUKS e os volumes LVM.
setup_encryption_and_lvm() {
    echo "[INFO] Configurando criptografia LUKS e LVM..."
    
    # Pede a senha para a partição LUKS.
    local luks_pass
    while true; do
        read -s -p "Digite a senha para a criptografia do disco (LUKS): " luks_pass
        echo
        read -s -p "Confirme a senha: " luks_pass_confirm
        echo
        if [[ "$luks_pass" == "$luks_pass_confirm" ]] && [[ -n "$luks_pass" ]]; then
            break
        else
            echo -e "${YELLOW}[AVISO] Senhas não coincidem ou estão vazias. Tente novamente.${NC}"
        fi
    done

    # Formata a partição do sistema com LUKS2.
    echo "[INFO] Formatando $LUKS_PART com LUKS2..."
    echo -n "$luks_pass" | run_cmd cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id --batch-mode "$LUKS_PART"

    # Abre o container LUKS para criar o LVM dentro dele.
    echo "[INFO] Abrindo o container LUKS..."
    echo -n "$luks_pass" | run_cmd cryptsetup open "$LUKS_PART" cryptroot
    
    # Limpa a variável de senha da memória.
    unset luks_pass luks_pass_confirm

    # Configura o LVM sobre o container LUKS aberto.
    echo "[INFO] Configurando LVM sobre /dev/mapper/cryptroot..."
    run_cmd pvcreate /dev/mapper/cryptroot
    run_cmd vgcreate vg0 /dev/mapper/cryptroot
    run_cmd lvcreate -L 4G -n swap vg0
    run_cmd lvcreate -L 30G -n root vg0
    run_cmd lvcreate -l '100%FREE' -n home vg0
    
    echo "[INFO] Criptografia e LVM configurados."
}

# Formata e monta todos os sistemas de arquivos.
format_and_mount_filesystems() {
    echo "[INFO] Formatando e montando sistemas de arquivos..."

    # Formata as partições e volumes lógicos.
    run_cmd mkfs.vfat -F32 "$EFI_PART"
    run_cmd mkfs.ext4 "$BOOT_PART"
    run_cmd mkfs.ext4 /dev/vg0/root
    run_cmd mkfs.ext4 /dev/vg0/home
    run_cmd mkswap /dev/vg0/swap

    # Monta os sistemas de arquivos na ordem correta.
    run_cmd mount /dev/vg0/root /mnt
    run_cmd mkdir -p /mnt/home
    run_cmd mount /dev/vg0/home /mnt/home
    run_cmd mkdir -p /mnt/boot
    run_cmd mount "$BOOT_PART" /mnt/boot
    run_cmd mkdir -p /mnt/boot/efi
    run_cmd mount "$EFI_PART" /mnt/boot/efi
    run_cmd swapon /dev/vg0/swap

    echo "[INFO] Sistemas de arquivos montados com sucesso."
}

# Instala o sistema base e gera o fstab.
install_base_system() {
    echo "[INFO] Sincronizando relógio do sistema..."
    run_cmd timedatectl set-ntp true

    echo "[INFO] Instalando sistema base com pacstrap (isso pode demorar)..."
    run_cmd pacstrap /mnt base base-devel linux linux-firmware lvm2 grub efibootmgr sudo nano networkmanager

    echo "[INFO] Gerando fstab..."
    # Gera o fstab usando UUIDs para maior robustez.
    genfstab -U /mnt >> /mnt/etc/fstab
    echo "[INFO] fstab gerado."
}

# Executa comandos de configuração dentro do novo sistema via arch-chroot.
configure_chroot() {
    echo "[INFO] Entrando no chroot para configurar o sistema instalado..."
    
    # Obtém o UUID da partição LUKS para configurar o GRUB.
    local luks_uuid
    luks_uuid=$(blkid -s UUID -o value "$LUKS_PART")

    # Copia variáveis necessárias para dentro do chroot.
    # O heredoc permite executar um script complexo dentro do chroot.
    arch-chroot /mnt /bin/bash -s -- "$HOSTNAME" "$USERNAME" "$luks_uuid" <<'EOF'
        # Este bloco de código é executado dentro do novo sistema.
        set -euo pipefail

        # Recebe argumentos do comando arch-chroot.
        readonly HOSTNAME="$1"
        readonly USERNAME="$2"
        readonly LUKS_UUID="$3"
        readonly TIMEZONE="America/Sao_Paulo"
        readonly LOCALE="pt_BR.UTF-8"
        readonly KEYMAP="br-abnt2"

        echo "[CHROOT] Configurando fuso horário, locale e hostname..."
        ln -sf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime
        hwclock --systohc
        echo "${HOSTNAME}" > /etc/hostname
        echo "LANG=${LOCALE}" > /etc/locale.conf
        echo "KEYMAP=${KEYMAP}" > /etc/vconsole.conf
        sed -i "s/^#${LOCALE}/${LOCALE}/" /etc/locale.gen
        locale-gen

        echo "[CHROOT] Configurando senhas de root e usuário..."
        # Pede as senhas de forma interativa dentro do chroot.
        echo "Defina a senha de root:"
        passwd root
        
        echo "Criando usuário '${USERNAME}' e definindo senha..."
        useradd -m -G wheel -s /bin/bash "${USERNAME}"
        echo "Defina a senha para o usuário '${USERNAME}':"
        passwd "${USERNAME}"

        # Permite que membros do grupo 'wheel' usem sudo.
        echo "[CHROOT] Habilitando privilégios de sudo para o grupo 'wheel'..."
        sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

        echo "[CHROOT] Configurando mkinitcpio com hooks para boot criptografado..."
        # Adiciona os hooks 'encrypt' e 'lvm2' para que o initramfs possa desbloquear o disco e ativar o LVM.
        sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck)/' /etc/mkinitcpio.conf
        mkinitcpio -P

        echo "[CHROOT] Configurando o bootloader GRUB..."
        # Configura o GRUB para pedir a senha LUKS no boot.
        sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"|" /etc/default/grub
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=${LUKS_UUID}:cryptroot root=/dev/vg0/root\"|" /etc/default/grub
        
        # Habilita o suporte a disco criptografado no GRUB.
        sed -i 's/^#GRUB_ENABLE_CRYPTODISK=y/GRUB_ENABLE_CRYPTODISK=y/' /etc/default/grub

        echo "[CHROOT] Instalando GRUB no disco EFI..."
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ARCH --removable
        grub-mkconfig -o /boot/grub/grub.cfg

        echo "[CHROOT] Habilitando serviços essenciais (NetworkManager)..."
        systemctl enable NetworkManager

        echo "[CHROOT] Configuração finalizada."
EOF
    echo "[INFO] Saída do chroot."
}

# Desmonta todos os sistemas de arquivos e fecha os containers LUKS.
final_cleanup() {
    echo "[INFO] Limpeza final: desmontando sistemas de arquivos..."
    umount -R /mnt &>/dev/null || true
    swapoff -a &>/dev/null || true
    cryptsetup close cryptroot &>/dev/null || true
    vgchange -an vg0 &>/dev/null || true
    echo "[INFO] Limpeza concluída."
}

# Exibe um resumo da instalação e os próximos passos.
display_summary() {
    echo -e "\n${GREEN}=================================================="
    echo -e "      🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! 🎉"
    echo -e "==================================================${NC}"
    echo -e "  - Hostname:      ${YELLOW}${HOSTNAME}${NC}"
    echo -e "  - Usuário Criado:  ${YELLOW}${USERNAME}${NC}"
    echo -e "  - Disco Usado:     ${YELLOW}${TARGET_DISK}${NC}"
    echo -e "  - Criptografia:  ${GREEN}Ativada (LUKS2 + LVM)${NC}"
    echo
    echo -e "${GREEN}O sistema está pronto para ser reiniciado.${NC}"
    echo "Após reiniciar, você será solicitado a digitar sua senha LUKS para descriptografar o disco."
    echo
    echo -e "Para reiniciar o sistema agora, execute o comando:"
    echo -e "  ${YELLOW}reboot${NC}"
    echo -e "=================================================="
}

# --- Função Principal (main) ---
# Orquestra todo o processo de instalação.
main() {
    setup_logging
    check_dependencies
    validate_environment

    # Coleta de informações do usuário
    prompt_for_hostname
    prompt_for_username
    prompt_for_disk

    # Confirmação final antes de apagar o disco
    confirm_destruction

    # Etapas da instalação
    zero_disk_with_pv "$TARGET_DISK"
    sanitize_disk "$TARGET_DISK"
    partition_disk "$TARGET_DISK"
    setup_encryption_and_lvm
    format_and_mount_filesystems
    install_base_system
    configure_chroot
    final_cleanup

    # Exibição do resumo
    display_summary
}

# Ponto de entrada do script: executa a função main.
# Isso permite que o script seja "sourced" sem executar a instalação.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
