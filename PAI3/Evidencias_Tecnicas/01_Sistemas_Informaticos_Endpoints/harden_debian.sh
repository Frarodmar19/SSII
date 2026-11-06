#!/bin/bash
sudo apt update
sudo apt install -y ufw libpam-pwquality auditd fail2ban debsums
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw --force enable
sudo sed -i 's/^password.*requisite.*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password || true
sudo chmod 600 /etc/crontab 2>/dev/null || true
echo "Acceso restringido a personal autorizado." | sudo tee /etc/issue /etc/issue.net
