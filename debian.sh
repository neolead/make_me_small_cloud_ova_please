#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# make_debian_ova.sh
# Usage: ./debian.sh input.qcow2 [root_password]
# Output: <basename>_modified.ova

INPUT_QCOW2="${1:-}"
[ -n "$INPUT_QCOW2" ] || { echo "Usage: $0 <image.qcow2> [root_password]"; exit 1; }
[ -f "$INPUT_QCOW2" ] || { echo "Error: '$INPUT_QCOW2' not found"; exit 1; }

ROOT_PASSWORD="${2:-1234QQQQQQQ\$}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'

error() { echo -e "${RED}[ОШИБКА] $*${NC}" >&2; exit 1; }

check_deps() {
  local deps=(qemu-img virt-customize jq tar sha256sum)
  local missing=()
  for cmd in "${deps[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [ "${#missing[@]}" -eq 0 ] || {
    echo -e "${YELLOW}[!] Missing: ${missing[*]}${NC}"
    echo "Install: sudo apt-get update && sudo apt-get install -y libguestfs-tools qemu-utils jq coreutils"
    exit 2
  }
}

debug_file() {
  [ -f "$1" ] && { echo -e "${GREEN}[DEBUG] Found: $1${NC}"; ls -lh "$1"; } \
    || echo -e "${RED}[DEBUG] Not found: $1${NC}"
}

prepare_host_files() {
  cat > "$TMP_DIR/firstboot-setup.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PASSFILE=/etc/firstboot_pass
LOG=/var/log/firstboot-setup.log
exec >>"$LOG" 2>&1
echo "[firstboot] starting"
PASSWORD=""
[ -f "$PASSFILE" ] && PASSWORD="$(cat "$PASSFILE")"
[ -n "$PASSWORD" ] && echo "root:$PASSWORD" | chpasswd
for iface in $(ls /sys/class/net|grep -v lo); do
  ip link set dev "$iface" up || true
  sleep 0.3
  dhclient -1 -v "$iface" || true
done
ssh-keygen -A || true
if systemctl >/dev/null 2>&1; then
  systemctl enable ssh || systemctl enable sshd || true
  systemctl start ssh || systemctl start sshd || true
else
  [ -x /etc/init.d/ssh ] && /etc/init.d/ssh start
fi
rm -f "$PASSFILE"
rm -f /etc/systemd/system/firstboot-setup.service /usr/local/sbin/firstboot-setup.sh
echo "[firstboot] finished"
EOF
  chmod 0755 "$TMP_DIR/firstboot-setup.sh"

  cat > "$TMP_DIR/firstboot-setup.service" <<'UNIT'
[Unit]
Description=Firstboot one-time setup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/firstboot-setup.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$TMP_DIR/firstboot-setup.service"

  cat > "$TMP_DIR/99-disable-cloud-init.cfg" <<'CLOUD'
datasource_list: [ None ]
network: {config: disabled}
CLOUD
  chmod 0644 "$TMP_DIR/99-disable-cloud-init.cfg"
}

debian_flow() {
  local qcow2="$INPUT_QCOW2"
  local base="$(basename "$qcow2" .qcow2)"
  local out="${base}_modified.ova"

  echo -e "${YELLOW}[*] QCOW2 → RAW${NC}"
  qemu-img convert -p -O raw "$qcow2" "$TMP_DIR/disk.raw" || error "convert RAW failed"

  prepare_host_files

  echo -e "${YELLOW}[*] Customizing (virt-customize)${NC}"
  virt-customize -a "$TMP_DIR/disk.raw" \
    --root-password "password:${ROOT_PASSWORD}" \
    --upload "$TMP_DIR/firstboot-setup.sh:/usr/local/sbin/firstboot-setup.sh" \
    --upload "$TMP_DIR/firstboot-setup.service:/etc/systemd/system/firstboot-setup.service" \
    --upload "$TMP_DIR/99-disable-cloud-init.cfg:/etc/cloud/cloud.cfg.d/99-disable-cloud-init.cfg" \
    --run-command "echo nameserver 8.8.8.8 >>/etc/resolv.conf" \
    --run-command "apt-get update && apt-get install -y isc-dhcp-client ssh" \
    --run-command "apt-get install -y open-vm-tools" \
    --run-command "printf '%s' '${ROOT_PASSWORD}' > /etc/firstboot_pass; chmod 600 /etc/firstboot_pass" \
    --run-command "chmod 0755 /usr/local/sbin/firstboot-setup.sh" \
    --run-command "ln -sf /etc/systemd/system/firstboot-setup.service /etc/systemd/system/multi-user.target.wants/" \
    --run-command "sed -i '/^PermitRootLogin/ d' /etc/ssh/sshd_config; echo 'PermitRootLogin yes' >>/etc/ssh/sshd_config; sed -i '/^PasswordAuthentication/ d' /etc/ssh/sshd_config; echo 'PasswordAuthentication yes' >>/etc/ssh/sshd_config" \
    --run-command "apt-get purge -y cloud-init ufw; apt-get autoremove -y" \
    --run-command "sync" \
    || error "virt-customize failed"

  echo -e "${YELLOW}[*] RAW → VMDK${NC}"
  qemu-img convert -p -O vmdk -o subformat=streamOptimized "$TMP_DIR/disk.raw" "$TMP_DIR/${base}.vmdk" \
    || error "convert VMDK failed"
  debug_file "$TMP_DIR/${base}.vmdk"

  echo -e "${YELLOW}[*] Building OVF${NC}"
  local size=$(stat -c%s "$TMP_DIR/${base}.vmdk")
  local cap=$(qemu-img info --output=json "$TMP_DIR/${base}.vmdk" | jq -r '."virtual-size"')

cat > "$TMP_DIR/${base}.ovf" <<OVF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${base}.vmdk" ovf:id="file1" ovf:size="${size}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="${cap}"
          ovf:capacityAllocationUnits="byte"
          ovf:diskId="vmdisk1"
          ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"
          ovf:populatedSize="${size}"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="${base}">
    <Info>A virtual machine</Info>
    <Name>${base}</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="debian64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Debian GNU/Linux (64-bit)</Description>
    </OperatingSystemSection>

    <ProductSection ovf:required="false">
      <Info>Cloud-Init customization</Info>
      <Product>Debian genericcloud</Product>
      <Property ovf:key="instance-id" ovf:type="string" ovf:userConfigurable="true" ovf:value="id-ovf">
          <Label>A Unique Instance ID for this instance</Label>
          <Description>Specifies the instance id.  This is required and used to determine if the machine should take "first boot" actions</Description>
      </Property>
      <Property ovf:key="hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="debianguest">
          <Description>Specifies the hostname for the appliance</Description>
      </Property>
      <Property ovf:key="seedfrom" ovf:type="string" ovf:userConfigurable="true">
          <Label>Url to seed instance data from</Label>
          <Description>This field is optional, but indicates that the instance should 'seed' user-data and meta-data from the given url.  If set to 'http://tinyurl.com/sm-' is given, meta-data will be pulled from http://tinyurl.com/sm-meta-data and user-data from http://tinyurl.com/sm-user-data.  Leave this empty if you do not want to seed from a url.</Description>
      </Property>
      <Property ovf:key="public-keys" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
          <Label>ssh public keys</Label>
          <Description>This field is optional, but indicates that the instance should populate the default user's 'authorized_keys' with this value</Description>
      </Property>
      <Property ovf:key="user-data" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
          <Label>Encoded user-data</Label>
          <Description>In order to fit into a xml attribute, this value is base64 encoded . It will be decoded, and then processed normally as user-data.</Description>
      </Property>
      <Property ovf:key="password" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
          <Label>Default User's password</Label>
          <Description>If set, the default user's password will be set to this value to allow password based login.  The password will be good for only a single login.  If set to the string 'RANDOM' then a random password will be generated, and written to the console.</Description>
      </Property>
    </ProductSection>

    <VirtualHardwareSection ovf:transport="iso">
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>${base}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-10</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>1 virtual CPU</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>1</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>1024MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>1024</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:Address>1</rasd:Address>
        <rasd:Description>IDE Controller</rasd:Description>
        <rasd:ElementName>VirtualIDEController 1</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>IDE Controller</rasd:Description>
        <rasd:ElementName>VirtualIDEController 0</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>
      <Item ovf:required="false">
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>VirtualVideoCard</rasd:ElementName>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:ResourceType>24</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="enable3DSupport" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="enableMPTSupport" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="use3dRenderer" vmw:value="automatic"/>
        <vmw:Config ovf:required="false" vmw:key="useAutoDetect" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="videoRamSizeInKB" vmw:value="4096"/>
      </Item>
      <Item ovf:required="false">
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>VirtualVMCIDevice</rasd:ElementName>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.vmci</rasd:ResourceSubType>
        <rasd:ResourceType>1</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="allowUnrestrictedCommunication" vmw:value="false"/>
      </Item>
      <Item ovf:required="false">
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>CD-ROM 1</rasd:ElementName>
        <rasd:InstanceID>8</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceSubType>vmware.cdrom.remotepassthrough</rasd:ResourceSubType>
        <rasd:ResourceType>15</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="backing.exclusive" vmw:value="false"/>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>9</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="backing.writeThrough" vmw:value="false"/>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>e1000</rasd:Description>
        <rasd:ElementName>Ethernet 1</rasd:ElementName>
        <rasd:InstanceID>11</rasd:InstanceID>
        <rasd:ResourceSubType>e1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="wakeOnLanEnabled" vmw:value="true"/>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="cpuHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="cpuHotRemoveEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="bios"/>
      <vmw:Config ovf:required="false" vmw:key="virtualICH7MPresent" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="virtualSMCPresent" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="memoryHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="nestedHVEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.powerOffType" vmw:value="preset"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.resetType" vmw:value="preset"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.standbyAction" vmw:value="checkpoint"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.suspendType" vmw:value="preset"/>
      <vmw:Config ovf:required="false" vmw:key="tools.afterPowerOn" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="tools.afterResume" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="tools.beforeGuestShutdown" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="tools.beforeGuestStandby" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="tools.syncTimeWithHost" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="tools.toolsUpgradePolicy" vmw:value="manual"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF
  echo -e "${YELLOW}[*] Building manifest${NC}"
  pushd "$TMP_DIR" >/dev/null
    sha256sum "${base}.vmdk" | awk '{print "SHA256("$2")= "$1}' > "${base}.mf"
    sha256sum "${base}.ovf" | awk '{print "SHA256("$2")= "$1}' >> "${base}.mf"
  popd >/dev/null

  echo -e "${YELLOW}[*] Packaging OVA${NC}"
  pushd "$TMP_DIR" >/dev/null
    tar -cvf "$CURRENT_DIR/$out" --format=ustar *.ovf *.vmdk *.mf || error "OVA packing failed"
  popd >/dev/null

  echo -e "${GREEN}[+] Created: $CURRENT_DIR/$out${NC}"
  echo -e "${GREEN}Login: root / Password: $ROOT_PASSWORD${NC}"
}

# main
check_deps
CURRENT_DIR="$PWD"
TMP_DIR="$(mktemp -d "$CURRENT_DIR/debian_tmp.XXXXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "${GREEN}[*] Using root password: $ROOT_PASSWORD${NC}"
debian_flow

