#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# make_cloud_ova_ssh_once_fixed.sh
# Usage: ./make_cloud_ova_ssh_once_fixed.sh input.ova [root_password]
# Output: input_modified.ova

INPUT_OVA="${1:-}"
[ -n "$INPUT_OVA" ] || { echo "Usage: $0 <input.ova> [root_password]"; exit 1; }
[ -f "$INPUT_OVA" ] || { echo "Error: '$INPUT_OVA' not found"; exit 1; }

ROOT_PASSWORD="${2:-1234QQQQQQQ\$}"

# цвета
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'

error() { echo -e "${RED}[ОШИБКА] $*${NC}" >&2; exit 1; }

check_deps() {
  local deps=(tar qemu-img virt-customize jq)
  local missing=()
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    echo -e "${YELLOW}[!] Отсутствуют: ${missing[*]}${NC}"
    echo "Установите: sudo apt-get update && sudo apt-get install -y libguestfs-tools qemu-utils jq"
    exit 2
  fi
}

debug_file() {
  local f="$1"
  if [ -f "$f" ]; then
    echo -e "${GREEN}[DEBUG] Found: $f${NC}"
    ls -lh "$f" || true
  else
    echo -e "${RED}[DEBUG] Not found: $f${NC}"
  fi
}

update_ovf() {
  local ovf_file="$1"
  local vmdk_file="$2"

  echo -e "${YELLOW}[*] Обновление OVF метаданных...${NC}"
  
  # Получаем новые параметры диска
  local file_size=$(stat -c%s "$vmdk_file")
  local disk_capacity=$(qemu-img info --output=json "$vmdk_file" | jq -r '.["virtual-size"]')

  # Временный файл для модификаций
  local tmp_file=$(mktemp)

  # Модифицируем OVF
  awk -v new_size="$file_size" -v new_capacity="$disk_capacity" -v disk_ref="$(basename "$vmdk_file")" '
    BEGIN { OFS=FS }
    {
      # Обновляем ссылки на VMDK
      if ($0 ~ /ovf:href=/) sub(/ovf:href="[^"]*"/, "ovf:href=\"" disk_ref "\"")
      
      # Обновляем размеры диска
      if ($0 ~ /ovf:size=/) sub(/ovf:size="[^"]*"/, "ovf:size=\"" new_size "\"")
      if ($0 ~ /ovf:capacity=/) sub(/ovf:capacity="[^"]*"/, "ovf:capacity=\"" new_capacity "\"")
      if ($0 ~ /ovf:populatedSize=/) sub(/ovf:populatedSize="[^"]*"/, "ovf:populatedSize=\"" new_size "\"")
      
      if ($0 ~ /<Item>/) in_item=1
      if (in_item && $0 ~ /<rasd:Connection>/) has_connection=1
      if (in_item && has_connection && $0 ~ /<rasd:ResourceSubType>/) 
        sub(/<rasd:ResourceSubType>[^<]*<\/rasd:ResourceSubType>/, "<rasd:ResourceSubType>E1000</rasd:ResourceSubType>")
      if ($0 ~ /<\/Item>/) { in_item=0; has_connection=0 }      
      print
    }
  ' "$ovf_file" > "$tmp_file" && mv "$tmp_file" "$ovf_file"

  echo -e "${GREEN}[+] OVF метаданные обновлены${NC}"
}

setup_system() {
  echo -e "${YELLOW}[*] Подготовка файлов и загрузка в образ (virt-customize)...${NC}"

  # host-side files in TMP_DIR (TMP_DIR is created in main before calling setup_system)
  local host_fb_script="$TMP_DIR/firstboot-setup.sh"
  local host_fb_unit="$TMP_DIR/firstboot-setup.service"
  local host_cloud_disable="$TMP_DIR/99-disable-cloud-init.cfg"

  # create firstboot script on host (no expansion inside)
  cat > "$host_fb_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PASSFILE=/etc/firstboot_pass
LOG=/var/log/firstboot-setup.log

exec >>"$LOG" 2>&1
date --iso-8601=seconds
echo "[firstboot] starting"

PASSWORD=""
if [ -f "$PASSFILE" ]; then
  PASSWORD="$(cat "$PASSFILE" || true)"
fi

if ! id -u ubuntu >/dev/null 2>&1; then
  echo "[firstboot] creating user ubuntu"
  useradd -m -s /bin/bash ubuntu || true
  if [ -n "$PASSWORD" ]; then
    echo "ubuntu:$PASSWORD" | chpasswd || true
  fi
  usermod -aG sudo ubuntu 2>/dev/null || true
  echo "ubuntu ALL=(ALL) ALL" >/etc/sudoers.d/90-ubuntu || true
  chmod 440 /etc/sudoers.d/90-ubuntu || true
else
  echo "[firstboot] ubuntu exists - updating password & sudo"
  if [ -n "$PASSWORD" ]; then
    echo "ubuntu:$PASSWORD" | chpasswd || true
  fi
  usermod -aG sudo ubuntu 2>/dev/null || true
fi

if [ -n "$PASSWORD" ]; then
  echo "root:$PASSWORD" | chpasswd || true
fi

echo "[firstboot] bringing up network interfaces"
if [ -d /sys/class/net ]; then
  for iface in $(ls /sys/class/net | grep -vE "^lo$"); do
    ip link set dev $iface up || true
    sleep 0.3
    if command -v dhclient >/dev/null 2>&1; then
      dhclient -1 -v $iface || true
    fi
  done
  if command -v netplan >/dev/null 2>&1; then
    netplan generate || true
    netplan apply || true
  fi
fi

echo "[firstboot] generating ssh host keys (ssh-keygen -A)"
if command -v ssh-keygen >/dev/null 2>&1; then
  ssh-keygen -A || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable ssh || systemctl enable sshd || true
  systemctl start ssh || systemctl start sshd || true
else
  if [ -x /etc/init.d/ssh ]; then
    /etc/init.d/ssh start || true
  fi
fi

if [ -f "$PASSFILE" ]; then
  shred -u "$PASSFILE" 2>/dev/null || rm -f "$PASSFILE" || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable firstboot-setup.service || true
  systemctl daemon-reload || true
fi
echo nameserver 8.8.8.8 >>/etc/resolv.conf
rm -f /etc/systemd/system/firstboot-setup.service || true
rm -f /usr/local/sbin/firstboot-setup.sh || true

echo "[firstboot] finished"
exit 0
EOF
  chmod 0755 "$host_fb_script"

  # create unit on host
  cat > "$host_fb_unit" <<'UNIT'
[Unit]
Description=Firstboot one-time setup (create ubuntu user, gen ssh keys, bring up network)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/firstboot-setup.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$host_fb_unit"

  # cloud-init disable file
  cat > "$host_cloud_disable" <<'CLOUD'
datasource_list: [ None ]
network: {config: disabled}
cloud_init_modules: []
cloud_config_modules: []
cloud_final_modules: []
CLOUD
  chmod 0644 "$host_cloud_disable"

  # Now upload into the image (virt-customize)
  virt-customize -a "$TMP_DIR/disk.raw" \
    --root-password "password:${ROOT_PASSWORD}" \
    --upload "$host_fb_script:/usr/local/sbin/firstboot-setup.sh" \
    --upload "$host_fb_unit:/etc/systemd/system/firstboot-setup.service" \
    --upload "$host_cloud_disable:/etc/cloud/cloud.cfg.d/99-disable-cloud-init.cfg" \
    --run-command "printf '%s' '${ROOT_PASSWORD}' > /etc/firstboot_pass; chmod 600 /etc/firstboot_pass" \
    --run-command "chmod 0755 /usr/local/sbin/firstboot-setup.sh; chmod 0644 /etc/systemd/system/firstboot-setup.service" \
    --run-command "mkdir -p /etc/systemd/system/multi-user.target.wants || true; ln -sf /etc/systemd/system/firstboot-setup.service /etc/systemd/system/multi-user.target.wants/firstboot-setup.service || true" \
    --run-command "if command -v systemctl >/dev/null 2>&1; then systemctl enable firstboot-setup.service || true; fi" \
    --run-command "if [ -f /etc/ssh/sshd_config ]; then sed -i '/^PermitRootLogin/ d' /etc/ssh/sshd_config || true; echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config; sed -i '/^PasswordAuthentication/ d' /etc/ssh/sshd_config || true; echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config; fi" \
    --run-command "apt-get remove -y cloud-init cloud-initramfs-growroot ufw || true; apt-get autoremove -y || true; rm -rf /var/lib/cloud/* /var/log/cloud-init* || true" \
    --run-command "if [ -f /usr/share/doc/util-linux/examples/securetty ]; then cp /usr/share/doc/util-linux/examples/securetty /etc/securetty || true; fi" \
    --run-command "sync" \
    || error "virt-customize failed"
  echo -e "${GREEN}[+] Системные файлы подготовлены и загружены в образ${NC}"
}

main() {
  check_deps

  echo -e "${GREEN}[*] Используем пароль для root/ubuntu: ${ROOT_PASSWORD}${NC}"

  local BASENAME
  BASENAME="$(basename "$INPUT_OVA" .ova)"
  local OUTPUT_OVA="${BASENAME}_modified.ova"
  local CURRENT_DIR="$PWD"

  TMP_DIR="$(mktemp -d "${CURRENT_DIR}/${BASENAME}_tmp.XXXXXXXX")"
  if [ ! -d "$TMP_DIR" ]; then error "Не удалось создать временную директорию"; fi

  trap 'rc=$?; rm -rf "$TMP_DIR" || true; exit $rc' EXIT

  echo -e "${YELLOW}[*] Распаковка OVA в $TMP_DIR ...${NC}"
  tar -xf "$INPUT_OVA" -C "$TMP_DIR" || error "Ошибка распаковки OVA"

  local VMDK OVF_FILE
  VMDK=$(find "$TMP_DIR" -maxdepth 1 -type f -iname '*.vmdk' -print -quit || true)
  OVF_FILE=$(find "$TMP_DIR" -maxdepth 1 -type f -iname '*.ovf' -print -quit || true)

  if [ -z "$VMDK" ] || [ -z "$OVF_FILE" ]; then
    ls -la "$TMP_DIR"
    error "Неполный OVA: VMDK или OVF не найдены"
  fi

  echo -e "${YELLOW}[*] Конвертация VMDK -> RAW ...${NC}"
  qemu-img convert -p -O raw "$VMDK" "$TMP_DIR/disk.raw" || error "Ошибка конвертации в RAW"
  rm -f "$VMDK" || true

  setup_system

  echo -e "${YELLOW}[*] Конвертация RAW -> VMDK (streamOptimized) ...${NC}"
  NEW_VMDK="$TMP_DIR/$(basename "$VMDK")"
  qemu-img convert -p -O vmdk -o subformat=streamOptimized "$TMP_DIR/disk.raw" "$NEW_VMDK" || error "Ошибка конвертации в VMDK"
  debug_file "$NEW_VMDK"

  update_ovf "$OVF_FILE" "$NEW_VMDK"

  echo -e "${YELLOW}[*] Создание OVA ${OUTPUT_OVA} ...${NC}"
  pushd "$TMP_DIR" >/dev/null
  if sh -c 'ls -1 *.ovf *.vmdk *.mf >/dev/null 2>&1'; then
    tar -cvf "$CURRENT_DIR/$OUTPUT_OVA" --format=ustar -- *.ovf *.vmdk *.mf || error "Ошибка упаковки OVA"
  else
    tar -cvf "$CURRENT_DIR/$OUTPUT_OVA" --format=ustar . || error "Ошибка упаковки OVA"
  fi
  popd >/dev/null

  echo -e "${GREEN}[+] Готово: ${CURRENT_DIR}/${OUTPUT_OVA}${NC}"
  echo -e "${GREEN}Логин: root / Пароль: ${ROOT_PASSWORD}${NC}"
  echo -e "${GREEN}Пользователь 'ubuntu' будет создан при первом запуске и получит тот же пароль.${NC}"
  echo -e "${YELLOW}Примечание: cloud-init удалён/замаскирован и создан конфиг для отключения.${NC}"
}

main "$@"

