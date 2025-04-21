#!/bin/bash

# Determine distribution type
if [ -f /etc/debian_version ]; then
    DISTRO="debian" # Ubuntu is Debian-based
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat" # CentOS is RedHat-based
else
    DISTRO="unknown"
    echo "Unknown distribution, some checks may not work properly."
fi

# Create output directory with timestamp
OUTDIR="/tmp/security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/security_audit.log"

log() {
    echo "[*] $1"
    echo "[*] $1" >> "$LOGFILE"
}

log "Starting comprehensive security audit. Results will be in $OUTDIR"

# --- 1. Installed packages and changes ---
log "→ Exporting installed packages (with dates)..."
if [ "$DISTRO" == "redhat" ]; then
    rpm -qa --last > "$OUTDIR/installed_packages.txt"
    log "→ Checking system package integrity..."
    rpm -Va --noscripts > "$OUTDIR/package_integrity.txt"
else
    dpkg -l > "$OUTDIR/installed_packages.txt"
    # For Debian/Ubuntu, we can use debsums for integrity check
    if command -v debsums &> /dev/null; then
        log "→ Checking system package integrity..."
        debsums -c > "$OUTDIR/package_integrity.txt" 2>&1
    else
        log "→ debsums not found, skipping package integrity check"
    fi
fi

# --- 2. Cron jobs ---
log "→ Gathering all cron jobs..."
mkdir -p "$OUTDIR/cron"
crontab -l > "$OUTDIR/cron/root_cron.txt" 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l > "$OUTDIR/cron/cron_$user.txt" 2>/dev/null
done
cp -r /etc/cron* "$OUTDIR/cron/" 2>/dev/null
cp -r /var/spool/cron "$OUTDIR/cron/" 2>/dev/null

# --- 3. Auto-start services ---
log "→ Gathering information about auto-starting services..."
if command -v systemctl &> /dev/null; then
    systemctl list-unit-files --type=service | grep enabled > "$OUTDIR/autostart_services.txt"
fi

# Copy rc.local and init scripts
cp /etc/rc.local "$OUTDIR/" 2>/dev/null || cp /etc/rc.d/rc.local "$OUTDIR/" 2>/dev/null
if [ -d /etc/init.d ]; then
    cp -r /etc/init.d "$OUTDIR/" 2>/dev/null
fi

log "→ Checking systemd services for suspicious commands..."
find /etc/systemd/system /lib/systemd/system -type f -exec grep -i 'bash\|exec\|curl\|wget' {} \; -print > "$OUTDIR/suspicious_systemd_services.txt" 2>/dev/null

# --- 4. SUID / SGID files ---
log "→ Looking for SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -lah {} \; 2>/dev/null > "$OUTDIR/suid_sgid_files.txt"

# --- 5. Strange libraries and LD_ variables ---
log "→ Collecting suspicious environment variables..."
env | grep LD_ > "$OUTDIR/env_ld_variables.txt"

log "→ Looking for suspicious .so files..."
find / -name "*.so" 2>/dev/null > "$OUTDIR/shared_objects.txt"

# --- 6. Potential backdoors in archives ---
log "→ Looking for archives that might hide backdoors..."
find / -type f \( -iname "*.tar" -o -iname "*.gz" -o -iname "*.zip" -o -iname "*.xz" -o -iname "*.bz2" \) -exec file {} \; 2>/dev/null | grep -v "data" > "$OUTDIR/suspicious_archives.txt"

# --- 7. SSH keys ---
log "→ Looking for SSH keys..."
find /root /home -name "authorized_keys" -o -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" 2>/dev/null > "$OUTDIR/ssh_keys.txt"

# --- 8. Suspicious executables with dangerous strings ---
log "→ Checking executable files for malicious strings..."
find / -type f -executable -size +100k -exec strings -f {} \; 2>/dev/null | grep -Ei "connect|curl|wget|base64|eval|bash|socket" > "$OUTDIR/suspicious_exec_strings.txt"

# --- 9. Users ---
log "→ Getting list of users..."
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$OUTDIR/user_accounts.txt"

# --- 10. Important logs ---
log "→ Collecting logs..."
mkdir -p "$OUTDIR/logs"

# Copy common logs with distribution-specific paths
if [ "$DISTRO" == "redhat" ]; then
    cp /var/log/{secure,messages,cron,yum.log,maillog} "$OUTDIR/logs/" 2>/dev/null
else
    cp /var/log/{auth.log,syslog,cron.log,dpkg.log,mail.log} "$OUTDIR/logs/" 2>/dev/null
fi

# Copy service logs
cp -r /var/log/httpd "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/apache2 "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/nginx "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/audit "$OUTDIR/logs/" 2>/dev/null

# --- 11. Web shells check ---
log "→ Checking for web shells in web directories..."
find /var/www /usr/share/nginx/html /var/www/html -type f -iname "*.php" -exec grep -Ei "base64_decode|eval|shell_exec|system|passthru|exec" {} \; -print > "$OUTDIR/potential_webshells.txt" 2>&1

# --- 12. Running processes and open ports ---
log "→ Checking running processes..."
ps auxf > "$OUTDIR/running_processes.txt" 2>&1

log "→ Checking open ports..."
if command -v ss &> /dev/null; then
    ss -tulnp > "$OUTDIR/open_ports_ss.txt" 2>&1
elif command -v netstat &> /dev/null; then
    netstat -tulnp > "$OUTDIR/open_ports_netstat.txt" 2>&1
fi

# --- 13. Rootkit checks ---
log "→ Checking for rootkits..."
if command -v chkrootkit &> /dev/null; then
    chkrootkit > "$OUTDIR/chkrootkit_results.txt" 2>&1
else
    log "chkrootkit not installed, skipping this check"
fi

if command -v rkhunter &> /dev/null; then
    rkhunter --check --skip-keypress > "$OUTDIR/rkhunter_results.txt" 2>&1
else
    log "rkhunter not installed, skipping this check"
fi

# --- 14. PowerDNS checks (if installed) ---
log "→ Checking PowerDNS configuration (if installed)..."
if [ -f /etc/powerdns/pdns.conf ]; then
    cat /etc/powerdns/pdns.conf > "$OUTDIR/powerdns_config.txt" 2>&1
    
    if command -v journalctl &> /dev/null; then
        journalctl -u pdns.service > "$OUTDIR/powerdns_journalctl.txt" 2>&1
    fi
    
    if [ "$DISTRO" == "debian" ]; then
        tail -n 100 /var/log/syslog | grep pdns > "$OUTDIR/powerdns_syslog.txt" 2>&1
    else
        tail -n 100 /var/log/messages | grep pdns > "$OUTDIR/powerdns_messages.txt" 2>&1
    fi
fi

# --- 15. SSH connections and authentication logs ---
log "→ Checking SSH connections..."
last -a | grep -i ssh > "$OUTDIR/ssh_connections.txt" 2>&1

log "→ Checking authentication logs..."
if [ "$DISTRO" == "debian" ]; then
    grep -i "Accepted" /var/log/auth.log > "$OUTDIR/auth_accepted.txt" 2>&1
    grep -i "Failed" /var/log/auth.log > "$OUTDIR/auth_failed.txt" 2>&1
else
    grep -i "Accepted" /var/log/secure > "$OUTDIR/auth_accepted.txt" 2>&1
    grep -i "Failed" /var/log/secure > "$OUTDIR/auth_failed.txt" 2>&1
fi

# --- 16. Specific user activity check ---
log "→ Checking activity of Administrator user (if exists)..."
if id Administrator &>/dev/null; then
    if command -v ausearch &> /dev/null; then
        ausearch -ua $(id -u Administrator) > "$OUTDIR/administrator_audit.txt" 2>&1
    fi
    
    if [ "$DISTRO" == "debian" ]; then
        grep "Administrator" /var/log/auth.log > "$OUTDIR/administrator_auth.txt" 2>&1
    else
        grep "Administrator" /var/log/secure > "$OUTDIR/administrator_auth.txt" 2>&1
    fi
fi

# --- 17. Network traffic check (brief sample) ---
log "→ Taking a brief sample of DNS traffic (will run for 10 seconds)..."
if command -v tcpdump &> /dev/null; then
    timeout 10 tcpdump -nn -i any port 53 -c 100 > "$OUTDIR/dns_traffic_sample.txt" 2>&1
else
    log "tcpdump not installed, skipping network traffic check"
fi

# --- 18. File checksum verification ---
log "→ Creating checksums of system files for future comparison..."
mkdir -p "$OUTDIR/checksums"
find /bin /sbin /usr/bin /usr/sbin -type f -executable -exec sha256sum {} \; > "$OUTDIR/checksums/system_binaries.txt" 2>/dev/null
find /etc -type f -exec sha256sum {} \; > "$OUTDIR/checksums/etc_files.txt" 2>/dev/null

# --- 19. Kernel modules ---
log "→ Checking loaded kernel modules..."
lsmod > "$OUTDIR/loaded_kernel_modules.txt"

# --- 20. Scheduled tasks (at) ---
log "→ Checking 'at' scheduled tasks..."
if command -v atq &> /dev/null; then
    atq > "$OUTDIR/at_scheduled_tasks.txt" 2>&1
fi

log "✅ Audit completed. Check results in: $OUTDIR"
echo "Full audit results available in $OUTDIR"

# Create a summary report
{
    echo "==============================================="
    echo "SECURITY AUDIT SUMMARY REPORT"
    echo "==============================================="
    echo "Date: $(date)"
    echo "System: $(hostname) ($(uname -a))"
    echo "Distribution: $DISTRO"
    echo "==============================================="
    echo "Key findings:"
    echo ""
    
    # Count suspicious webshells
    WEB_SHELL_COUNT=$(wc -l < "$OUTDIR/potential_webshells.txt" 2>/dev/null || echo "0")
    echo "- Potential web shells: $WEB_SHELL_COUNT"
    
    # Count SUID/SGID files
    SUID_COUNT=$(wc -l < "$OUTDIR/suid_sgid_files.txt" 2>/dev/null || echo "0")
    echo "- SUID/SGID files: $SUID_COUNT"
    
    # Count failed logins
    if [ -f "$OUTDIR/auth_failed.txt" ]; then
        FAILED_LOGINS=$(wc -l < "$OUTDIR/auth_failed.txt" 2>/dev/null || echo "0")
        echo "- Failed login attempts: $FAILED_LOGINS"
    fi
    
    # Count suspicious executables
    SUSP_EXEC=$(wc -l < "$OUTDIR/suspicious_exec_strings.txt" 2>/dev/null || echo "0")
    echo "- Suspicious executable strings: $SUSP_EXEC"
    
    echo ""
    echo "==============================================="
    echo "Check complete audit results in $OUTDIR"
    echo "==============================================="
} > "$OUTDIR/audit_summary.txt"

# Consolidate all findings into a single file
log "→ Consolidating all findings into a single file..."
{
    echo "====================================================="
    echo "COMPREHENSIVE SECURITY AUDIT - ALL FINDINGS"
    echo "====================================================="
    echo "Date: $(date)"
    echo "System: $(hostname) ($(uname -a))"
    echo "Distribution: $DISTRO"
    echo "====================================================="
    echo ""
    
    # Include the summary first
    echo "SUMMARY:"
    echo "-----------------------------------------------------"
    cat "$OUTDIR/audit_summary.txt"
    echo ""
    echo "====================================================="
    
    # Include all individual files with clear section headers
    
    echo ""
    echo "INSTALLED PACKAGES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/installed_packages.txt" ]; then
        cat "$OUTDIR/installed_packages.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "PACKAGE INTEGRITY ISSUES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/package_integrity.txt" ]; then
        cat "$OUTDIR/package_integrity.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "CRON JOBS (ROOT):"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/cron/root_cron.txt" ]; then
        cat "$OUTDIR/cron/root_cron.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "AUTO-STARTING SERVICES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/autostart_services.txt" ]; then
        cat "$OUTDIR/autostart_services.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SUSPICIOUS SYSTEMD SERVICES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/suspicious_systemd_services.txt" ]; then
        cat "$OUTDIR/suspicious_systemd_services.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SUID/SGID FILES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/suid_sgid_files.txt" ]; then
        cat "$OUTDIR/suid_sgid_files.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SUSPICIOUS ENVIRONMENT VARIABLES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/env_ld_variables.txt" ]; then
        cat "$OUTDIR/env_ld_variables.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "POTENTIALLY SUSPICIOUS ARCHIVES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/suspicious_archives.txt" ]; then
        cat "$OUTDIR/suspicious_archives.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SSH KEYS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/ssh_keys.txt" ]; then
        cat "$OUTDIR/ssh_keys.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SUSPICIOUS EXECUTABLE STRINGS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/suspicious_exec_strings.txt" ]; then
        head -n 100 "$OUTDIR/suspicious_exec_strings.txt"
        SUSP_EXEC_LINES=$(wc -l < "$OUTDIR/suspicious_exec_strings.txt")
        if [ $SUSP_EXEC_LINES -gt 100 ]; then
            echo "... (showing first 100 of $SUSP_EXEC_LINES lines)"
        fi
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "USER ACCOUNTS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/user_accounts.txt" ]; then
        cat "$OUTDIR/user_accounts.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "POTENTIAL WEB SHELLS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/potential_webshells.txt" ]; then
        cat "$OUTDIR/potential_webshells.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "RUNNING PROCESSES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/running_processes.txt" ]; then
        cat "$OUTDIR/running_processes.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "OPEN PORTS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/open_ports_ss.txt" ]; then
        cat "$OUTDIR/open_ports_ss.txt"
    elif [ -f "$OUTDIR/open_ports_netstat.txt" ]; then
        cat "$OUTDIR/open_ports_netstat.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "ROOTKIT CHECK RESULTS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/chkrootkit_results.txt" ]; then
        cat "$OUTDIR/chkrootkit_results.txt"
    fi
    if [ -f "$OUTDIR/rkhunter_results.txt" ]; then
        cat "$OUTDIR/rkhunter_results.txt"
    fi
    if [ ! -f "$OUTDIR/chkrootkit_results.txt" ] && [ ! -f "$OUTDIR/rkhunter_results.txt" ]; then
        echo "No data collected"
    fi
    
    echo ""
    echo "SSH CONNECTIONS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/ssh_connections.txt" ]; then
        cat "$OUTDIR/ssh_connections.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SUCCESSFUL AUTHENTICATION ATTEMPTS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/auth_accepted.txt" ]; then
        cat "$OUTDIR/auth_accepted.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "FAILED AUTHENTICATION ATTEMPTS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/auth_failed.txt" ]; then
        cat "$OUTDIR/auth_failed.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "DNS TRAFFIC SAMPLE:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/dns_traffic_sample.txt" ]; then
        cat "$OUTDIR/dns_traffic_sample.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "LOADED KERNEL MODULES:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/loaded_kernel_modules.txt" ]; then
        cat "$OUTDIR/loaded_kernel_modules.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "SCHEDULED AT TASKS:"
    echo "-----------------------------------------------------"
    if [ -f "$OUTDIR/at_scheduled_tasks.txt" ]; then
        cat "$OUTDIR/at_scheduled_tasks.txt"
    else
        echo "No data collected"
    fi
    
    echo ""
    echo "====================================================="
    echo "END OF CONSOLIDATED AUDIT REPORT"
    echo "====================================================="
    
} > "$OUTDIR/all_information"

log "✅ Consolidated all findings into: $OUTDIR/all_information"
#cat "$OUTDIR/audit_summary.txt"
