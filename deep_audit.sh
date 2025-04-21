#!/bin/bash
OUTDIR="/tmp/blue_team_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

log() {
  echo "[*] $1"
}

log "Починаємо глибокий аудит. Результати будуть у $OUTDIR"

# --- 1. Встановлені пакети та зміни ---
log "→ Вивантажуємо встановлені пакети (з датами)..."
rpm -qa --last > "$OUTDIR/installed_packages.txt"

log "→ Перевіряємо цілісність системних пакетів..."
rpm -Va --noscripts > "$OUTDIR/package_integrity.txt"

# --- 2. Cron ---
log "→ Збираємо всі cron-завдання..."
mkdir -p "$OUTDIR/cron"
crontab -l > "$OUTDIR/cron/root_cron.txt" 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -u $user -l > "$OUTDIR/cron/cron_$user.txt" 2>/dev/null
done
cp -r /etc/cron* "$OUTDIR/cron/" 2>/dev/null
cp -r /var/spool/cron "$OUTDIR/cron/" 2>/dev/null

# --- 3. Автозапуск ---
log "→ Збираємо інформацію про автозапуск..."
systemctl list-unit-files --type=service | grep enabled > "$OUTDIR/autostart_services.txt"
cp /etc/rc.d/rc.local "$OUTDIR/" 2>/dev/null
cp -r /etc/init.d "$OUTDIR/" 2>/dev/null

# --- 4. SUID / SGID ---
log "→ Шукаємо SUID/SGID файли..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -lah {} \; 2>/dev/null > "$OUTDIR/suid_sgid_files.txt"

# --- 5. Дивні бібліотеки і LD_ змінні ---
log "→ Збираємо підозрілі змінні середовища..."
env | grep LD_ > "$OUTDIR/env_ld_variables.txt"

log "→ Шукаємо підозрілі .so файли..."
find / -name "*.so" 2>/dev/null > "$OUTDIR/shared_objects.txt"

# --- 6. Потенційні бекдори в архівах ---
log "→ Шукаємо архіви, що можуть ховати бекдори..."
find / -type f \( -iname "*.tar" -o -iname "*.gz" -o -iname "*.zip" -o -iname "*.xz" -o -iname "*.bz2" \) -exec file {} \; 2>/dev/null | grep -v "data" > "$OUTDIR/suspicious_archives.txt"

# --- 7. SSH ключі ---
log "→ Шукаємо SSH ключі..."
find /root /home -name "authorized_keys" 2>/dev/null > "$OUTDIR/ssh_keys.txt"

# --- 8. Підозрілі виконувані файли з небезпечними рядками ---
log "→ Перевіряємо виконувані файли на наявність шкідливих рядків..."
find / -type f -executable -size +100k -exec strings -f {} \; 2>/dev/null | grep -Ei "connect|curl|wget|base64|eval|bash|socket" > "$OUTDIR/suspicious_exec_strings.txt"

# --- 9. Користувачі ---
log "→ Отримуємо список користувачів..."
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$OUTDIR/user_accounts.txt"

# --- 10. Важливі журнали ---
log "→ Збираємо журнали..."
mkdir -p "$OUTDIR/logs"
cp /var/log/{secure,messages,cron,yum.log,maillog} "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/httpd "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/audit "$OUTDIR/logs/" 2>/dev/null

log "✅ Аудит завершено. Перевір результати у: $OUTDIR"
