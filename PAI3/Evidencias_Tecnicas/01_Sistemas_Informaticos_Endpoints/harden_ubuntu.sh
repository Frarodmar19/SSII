#!/bin/bash
set -e

echo "[+] 1. Instalando herramientas de seguridad y auditoria..."
sudo apt update
sudo apt install -y ufw libpam-pwquality auditd fail2ban apt-show-versions debsums sysstat acct

echo "[+] 2. Bastionado de autenticacion y cuentas..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
sudo sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" | sudo tee -a /etc/profile
fi

sudo tee /etc/security/pwquality.conf > /dev/null <<EOF
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
EOF

echo "[+] 3. Configuracion del Cortafuegos (UFW)..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw --force enable

echo "[+] 4. Estableciendo Banners Legales..."
BANNER="ACCESO RESTRINGIDO. Sistema monitorizado de la Universidad."
echo "$BANNER" | sudo tee /etc/issue
echo "$BANNER" | sudo tee /etc/issue.net

echo "[+] 5. Ajustes de Kernel y Red (sysctl)..."
sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
EOF
sudo sysctl --system

echo "[+] 6. Restriccion de controladores de almacenamiento..."
sudo tee /etc/modprobe.d/blacklist-storage.conf > /dev/null <<EOF
blacklist usb-storage
blacklist firewire-core
EOF

echo "[+] 7. Habilitando servicios de monitorizacion y auditoria..."
sudo systemctl enable --now auditd
sudo systemctl enable --now fail2ban

echo "[+] Bastionado completado con exito."
