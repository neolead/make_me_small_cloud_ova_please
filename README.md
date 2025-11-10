Mini linux ova creation tool

Pre install:
apt install qemu-utils libguestfs-tools whois -y

[ubuntu]
wget https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-20.10-server-cloudimg-amd64.ova

/// 22,24...



wget https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.ova


wget https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.ova

[debian]
wget https://mirror.accum.se/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2

for ubuntu and debian
running
[password can be set when running or in the script]



default user for debian - root:1234QQQQQQQ$


default user for ubuntu - ubuntu,root:1234QQQQQQQ$




Usage: ./debian.sh input.qcow2 [root_password]
Usage: ./ubuntu.sh input.ova [root_password]

bash ubuntu.sh ubuntu-20.10-server-cloudimg-amd64.ova 
bash debian.sh debian-13-nocloud-amd64.qcow2

The scripts create users... the password can be specified when starting the script or adjusted in the script... they deploy dhcplient... repackage the images... etc.
The end result is a ready-made small ova for clean deployment.
The deployment can be further written within the bash script.
The output is a modified mini image for deployment to VirtualBox, etc., in ova format.


results[]
529M 2025-11-09 07:41 debian-13-nocloud-amd64_modified.ova
538M 2025-11-09 05:48 ubuntu-20.10-server-cloudimg-amd64_modified.ova
