#!/bin/bash

# CyberPatriot Ubuntu Security Script
# Author: [Your Name]
# Date: $(date +"%Y-%m-%d")
# Version: 2.1

# ==================================================
# Variables
# ==================================================

LOG_FILE="/var/log/cyberpatriot_security_script.log"
SSH_CONFIG="/etc/ssh/sshd_config"
PAM_PASSWORD_FILE="/etc/pam.d/common-password"

# Unnecessary packages to remove
UNNECESSARY_PACKAGES=(
    "telnet"
    "rsh-client"
    "rsh-redone-client"
    "xinetd"
    "ypbind"
    "ypserv"
    "nis"
    "tftp"
    "tftpd"
    "talk"
    "talkd"
)

# Services to check and secure
SERVICES_TO_SECURE=(
    "apache2"
    "mysql"
    "nginx"
    "postgresql"
)

# Services to disable if unnecessary
SERVICES_TO_DISABLE=(
    "cups"
    "avahi-daemon"
    "bluetooth"
)

# ==================================================
# Functions
# ==================================================

log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

update_system() {
    log "Updating the system..."
    apt update && apt upgrade -y
    if [[ $? -ne 0 ]]; then
        log "System update failed."
        # Continue execution even if update fails
    else
        log "System updated successfully."
    fi
}

remove_unnecessary_packages() {
    log "Removing unnecessary packages..."
    for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
        if dpkg -l | grep -qw "$pkg"; then
            apt purge -y "$pkg"
            log "Removed package: $pkg"
        else
            log "Package not installed: $pkg"
        fi
    done
    apt autoremove -y
    log "Package removal completed."
}

secure_user_accounts() {
    log "Securing user accounts..."
    # Lock inactive user accounts
    awk -F: '($7 !~ /(false|nologin|halt|sync|shutdown)$/ && $1 != "root") {print $1}' /etc/passwd | while read -r user; do
        chage --inactive 30 "$user"
        log "Set inactivity lock for user: $user"
    done

    # Lock accounts with empty passwords
    awk -F: '($2 == "" && $1 != "root") {print $1}' /etc/shadow | while read -r user; do
        passwd -l "$user"
        log "Locked user with empty password: $user"
    done
    log "User account security completed."
}

configure_password_policies() {
    log "Configuring password policies..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    log "Updated /etc/login.defs"

    # Install libpam-pwquality for password strength checking
    apt install -y libpam-pwquality
    if ! grep -q "pam_pwquality.so" "$PAM_PASSWORD_FILE"; then
        sed -i '/pam_unix.so/ i password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' "$PAM_PASSWORD_FILE"
        log "Inserted pam_pwquality.so into PAM configuration"
    else
        sed -i 's|^password\s*requisite\s*pam_pwquality\.so.*|password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1|' "$PAM_PASSWORD_FILE"
        log "Updated pam_pwquality.so settings in PAM configuration"
    fi
    log "Password policy configuration completed."
}

secure_ssh_configuration() {
    log "Securing SSH configuration..."
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"

    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="yes"
        ["X11Forwarding"]="no"
    )

    for key in "${!ssh_settings[@]}"; do
        if grep -q "^[#\s]*$key" "$SSH_CONFIG"; then
            sed -i "s|^[#\s]*$key.*|$key ${ssh_settings[$key]}|" "$SSH_CONFIG"
        else
            echo "$key ${ssh_settings[$key]}" >> "$SSH_CONFIG"
        fi
        log "Set $key to ${ssh_settings[$key]}"
    done

    systemctl reload sshd
    if [[ $? -ne 0 ]]; then
        log "Failed to reload SSH daemon."
        # Continue execution even if SSH reload fails
    else
        log "SSH configuration secured."
    fi
}

configure_firewall() {
    log "Configuring the firewall..."
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit ssh/tcp
    ufw --force enable
    log "Firewall configured and enabled."
}

configure_automatic_updates() {
    log "Setting up automatic updates..."
    apt install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
    log "Automatic updates configured."
}

check_suid_sgid_files() {
    log "Checking for SUID/SGID files..."
    find / -path /proc -prune -o -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null > /var/log/suid_sgid_files.log
    log "SUID/SGID files logged to /var/log/suid_sgid_files.log"
}

audit_file_permissions() {
    log "Auditing file permissions..."
    # Fix permissions on critical files only
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
    log "Critical file permissions audited."
}

secure_services() {
    log "Securing detected services..."
    for service in "${SERVICES_TO_SECURE[@]}"; do
        if dpkg -l | grep -qw "$service"; then
            "secure_${service}"
        else
            log "Service not installed: $service"
        fi
    done
    log "Service hardening completed."
}

secure_apache2() {
    log "Securing Apache2..."
    # Backup configuration
    cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak
    # Disable directory listing
    sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/apache2.conf
    # Disable unnecessary modules
    a2dismod autoindex -f
    # Restart Apache
    systemctl restart apache2
    log "Apache2 secured."
}

secure_nginx() {
    log "Securing Nginx..."
    # Backup configuration
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    # Modify server tokens to off
    sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf
    # Restart Nginx
    systemctl restart nginx
    log "Nginx secured."
}

secure_mysql() {
    log "Securing MySQL..."
    # Secure MySQL installation
    mysql_secure_installation <<EOF

y
n
y
y
y
EOF
    log "MySQL secured."
}

secure_postgresql() {
    log "Securing PostgreSQL..."
    # Disable remote connections
    PG_HBA_FILE=$(find /etc/postgresql/ -name pg_hba.conf)
    if [[ -f "$PG_HBA_FILE" ]]; then
        echo "host all all 0.0.0.0/0 reject" >> "$PG_HBA_FILE"
        systemctl restart postgresql
        log "PostgreSQL secured."
    else
        log "PostgreSQL pg_hba.conf not found."
    fi
}

install_malware_scanners() {
    log "Installing malware and rootkit scanners..."
    apt install -y rkhunter chkrootkit clamav
    log "Malware scanners installed."
}

run_malware_scans() {
    log "Running malware scans..."
    # Update ClamAV database
    freshclam
    # Run ClamAV scan
    clamscan -r / --quiet --log=/var/log/clamav_scan.log
    log "ClamAV scan completed. Log at /var/log/clamav_scan.log"
    # Run rkhunter
    rkhunter --update
    rkhunter --checkall --skip-keypress --nocolors > /var/log/rkhunter_scan.log
    log "Rkhunter scan completed. Log at /var/log/rkhunter_scan.log"
    # Run chkrootkit
    chkrootkit > /var/log/chkrootkit_scan.log
    log "Chkrootkit scan completed. Log at /var/log/chkrootkit_scan.log"
}

install_aide() {
    log "Installing and configuring AIDE..."
    apt install -y aide
    aideinit -y -f
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    log "AIDE installed and database initialized."
}

harden_network_parameters() {
    log "Hardening network parameters..."
    SYSCTL_CONF="/etc/sysctl.conf"
    cp "$SYSCTL_CONF" "${SYSCTL_CONF}.bak"

    declare -A sysctl_settings=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
    )

    for key in "${!sysctl_settings[@]}"; do
        if grep -q "^#*$key" "$SYSCTL_CONF"; then
            sed -i "s|^#*$key.*|$key = ${sysctl_settings[$key]}|" "$SYSCTL_CONF"
        else
            echo "$key = ${sysctl_settings[$key]}" >> "$SYSCTL_CONF"
        fi
        log "Set $key to ${sysctl_settings[$key]}"
    done

    sysctl -p
    log "Network parameters hardened."
}

audit_and_remove_services() {
    log "Auditing and removing unnecessary services..."
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl list-unit-files | grep -qw "$service"; then
            systemctl disable "$service" 2>/dev/null
            systemctl stop "$service" 2>/dev/null
            log "Disabled and stopped service: $service"
        else
            log "Service not found or not installed: $service"
        fi
    done
    log "Service audit and removal completed."
}

configure_ssh_key_authentication() {
    log "Configuring SSH key-based authentication..."
    # Ensure SSH directory exists
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    # Generate SSH key pair if not existing
    if [[ ! -f /root/.ssh/id_rsa ]]; then
        ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa
        log "Generated SSH key pair for root user."
    fi

    # Set up authorized_keys
    if [[ ! -f /root/.ssh/authorized_keys ]]; then
        cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        log "Set up authorized_keys for root user."
    fi

    # Disable password authentication in SSH config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"

    systemctl reload sshd
    log "SSH key-based authentication configured."
}

audit_user_and_groups() {
    log "Auditing users and groups..."
    # Check for users with UID 0 other than root
    awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | while read -r user; do
        log "User with UID 0 found: $user"
    done

    # List all users
    log "Listing all user accounts:"
    awk -F: '{print $1}' /etc/passwd | tee -a "$LOG_FILE"

    # List members of sudo and adm groups
    log "Users in sudo group:"
    getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | tee -a "$LOG_FILE"
    log "Users in adm group:"
    getent group adm | awk -F: '{print $4}' | tr ',' '\n' | tee -a "$LOG_FILE"

    log "User and group audit completed."
}

configure_system_banners() {
    log "Configuring system banners..."
    echo "Unauthorized access is prohibited. All activity may be monitored and reported." > /etc/issue
    echo "Unauthorized access is prohibited. All activity may be monitored and reported." > /etc/motd
    log "System banners configured."
}

audit_cron_jobs() {
    log "Auditing cron jobs..."
    # List cron jobs for all users
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l &>/dev/null
        if [[ $? -eq 0 ]]; then
            log "Cron jobs for user: $user"
            crontab -u "$user" -l | tee -a "$LOG_FILE"
        fi
    done

    # List cron jobs in cron directories
    log "System cron jobs:"
    ls -la /etc/cron.*/* 2>/dev/null | tee -a "$LOG_FILE"

    log "Cron job audit completed."
}

# ==================================================
# Main Script Execution
# ==================================================

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "This script must be run as root."
   exit 1
fi

# Create log file
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
log "Script started."

# Execute functions
update_system
remove_unnecessary_packages
secure_user_accounts
configure_password_policies
secure_ssh_configuration
configure_firewall
configure_automatic_updates
check_suid_sgid_files
audit_file_permissions

# New functions
secure_services
install_malware_scanners
run_malware_scans
install_aide
harden_network_parameters
audit_and_remove_services
configure_ssh_key_authentication
audit_user_and_groups
configure_system_banners
audit_cron_jobs

log "Security script execution completed."
