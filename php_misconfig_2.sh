# Перевірка конфігурації SSH
section "АУДИТ SSH"
if [ -f "/etc/ssh/sshd_config" ]; then
  subsection "Перевірка налаштувань SSH"
  cp "/etc/ssh/sshd_config" "$OUTPUT_DIR/sshd_config"
  log "Конфігурація SSH збережена в файлі: sshd_config"

  # Перевірка ключових налаштувань SSH
  SSH_CHECKS=("PermitRootLogin" "PasswordAuthentication" "X11Forwarding" "AllowTcpForwarding" "PermitEmptyPasswords" "Protocol")

  for check in "${SSH_CHECKS[@]}"; do
    value=$(grep "^$check " /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$value" ]; then
      value="(використовується значення за замовчуванням)"
    fi

    case $check in
      "PermitRootLogin")
        if [ "$value" == "yes" ]; then
          result "$check = $value (рекомендується: no)" "WARNING"
        else
          result "$check = $value" "OK"
        fi
        ;;
      "PasswordAuthentication")
        if [ "$value" == "yes" ]; then
          result "$check = $value (рекомендується: використання ключів)" "WARNING"
        else
          result "$check = $value" "OK"
        fi
        ;;
      "X11Forwarding")
        if [ "$value" == "yes" ]; then
          result "$check = $value (рекомендується: no)" "WARNING"
        else
          result "$check = $value" "OK"
        fi
        ;;
      "AllowTcpForwarding")
        if [ "$value" == "yes" ]; then
          result "$check = $value (рекомендується: no)" "WARNING"
        else
          result "$check = $value" "OK"
        fi
        ;;
      "PermitEmptyPasswords")
        if [ "$value" == "yes" ]; then
          result "$check = $value (рекомендується: no)" "CRITICAL"
        else
          result "$check = $value" "OK"
        fi
        ;;
      "Protocol")
        if [ "$value" == "1" ] || [ "$value" == "1,2" ] || [ "$value" == "2,1" ]; then
          result "$check = $value (рекомендується: 2)" "WARNING"
        else
          result "$check = $value" "OK"
        fi
        ;;
    esac
  done

  # Перевірка авторизованих ключів
  subsection "Перевірка авторизованих ключів SSH"
  AUTHORIZED_KEYS_FILES=$(find /home -name "authorized_keys" -o -name "authorized_keys2" 2>/dev/null)

  if [ -n "$AUTHORIZED_KEYS_FILES" ]; then
    echo "$AUTHORIZED_KEYS_FILES" > "$OUTPUT_DIR/authorized_keys_files.txt"
    log "Знайдені файли authorized_keys збережені в файлі: authorized_keys_files.txt"

    # Підрахунок ключів для кожного користувача
    echo "Підрахунок ключів для користувачів:" | tee -a "$LOG_FILE"
    for keyfile in $AUTHORIZED_KEYS_FILES; do
      user=$(echo "$keyfile" | awk -F '/' '{print $3}')
      count=$(wc -l < "$keyfile")
      echo "$user: $count ключів" | tee -a "$LOG_FILE"
    done
  else
    log "Файлів authorized_keys не знайдено"
  fi
fi

# Перевірка конфігурації sudo
section "АУДИТ SUDO"
subsection "Перевірка налаштувань sudo"
if [ -f "/etc/sudoers" ]; then
  # Перевірка налаштувань sudoers (безпечно, без прямого копіювання)
  grep -v "^#" /etc/sudoers | grep -v "^$" | grep -v "^Defaults" > "$OUTPUT_DIR/sudoers_entries.txt"
  log "Активні записи sudoers збережено в файлі: sudoers_entries.txt"

  # Пошук потенційно небезпечних налаштувань sudo
  grep "NOPASSWD\|!authenticate" "$OUTPUT_DIR/sudoers_entries.txt" > "$OUTPUT_DIR/sudo_nopasswd.txt"
  COUNT=$(wc -l < "$OUTPUT_DIR/sudo_nopasswd.txt")
  if [ "$COUNT" -gt 0 ]; then
    result "Виявлено $COUNT записів sudo без автентифікації" "WARNING"
    cat "$OUTPUT_DIR/sudo_nopasswd.txt" | tee -a "$LOG_FILE"
  else
    result "Записів sudo без автентифікації не виявлено" "OK"
  fi

  # Копіювання додаткових конфігурацій sudo
  if [ -d "/etc/sudoers.d" ]; then
    for file in /etc/sudoers.d/*; do
      if [ -f "$file" ] && [ "$file" != "/etc/sudoers.d/README" ]; then
        grep -v "^#" "$file" | grep -v "^$" > "$OUTPUT_DIR/sudo_$(basename "$file")"
      fi
    done
    log "Додаткові конфігурації sudo скопійовано"
  fi
fi

# Перевірка наявності шкідливих пакетів
section "ПЕРЕВІРКА ПАКЕТІВ"
subsection "Пошук нещодавно встановлених пакетів"

# Визначення пакетного менеджера
if command -v rpm &>/dev/null; then
  # CentOS/RHEL
  rpm -qa --last | head -50 > "$OUTPUT_DIR/recent_packages.txt"
  log "Останні 50 встановлених пакетів (RPM) збережено в файлі: recent_packages.txt"
elif command -v dpkg &>/dev/null; then
  # Debian/Ubuntu
  grep " install " /var/log/dpkg.log | tail -50 > "$OUTPUT_DIR/recent_packages.txt"
  log "Останні 50 встановлених пакетів (DPKG) збережено в файлі: recent_packages.txt"
fi

# Пошук модифікованих файлів пакетів
if command -v rpm &>/dev/null; then
  # Перевірка цілісності пакетів для RPM
  rpm -Va | grep -v "^\.\.\.\.\.\.\.\.\ " | head -100 > "$OUTPUT_DIR/modified_package_files.txt"
  COUNT=$(wc -l < "$OUTPUT_DIR/modified_package_files.txt")
  if [ "$COUNT" -gt 0 ]; then
    result "Виявлено $COUNT модифікованих файлів пакетів" "WARNING"
    head -10 "$OUTPUT_DIR/modified_package_files.txt" | tee -a "$LOG_FILE"
    log "Повний список у файлі: modified_package_files.txt"
  else
    result "Модифікованих файлів пакетів не виявлено" "OK"
  fi
fi

# Перевірка системного часу на синхронізацію
section "ПЕРЕВІРКА СИСТЕМНОГО ЧАСУ"
subsection "Налаштування NTP"
if [ -f "/etc/ntp.conf" ]; then
  cp "/etc/ntp.conf" "$OUTPUT_DIR/ntp.conf"
  log "Конфігурація NTP збережена в файлі: ntp.conf"

  # Перевірка статусу NTP
  if command -v ntpq &>/dev/null; then
    ntpq -p > "$OUTPUT_DIR/ntp_status.txt" 2>&1
    log "Статус NTP збережено в файлі: ntp_status.txt"
  fi
elif [ -f "/etc/chrony.conf" ]; then
  cp "/etc/chrony.conf" "$OUTPUT_DIR/chrony.conf"
  log "Конфігурація Chrony збережена в файлі: chrony.conf"

  # Перевірка статусу Chrony
  if command -v chronyc &>/dev/null; then
    chronyc sources > "$OUTPUT_DIR/chrony_status.txt" 2>&1
    log "Статус Chrony збережено в файлі: chrony_status.txt"
  fi
else
  log "Конфігурацію NTP/Chrony не знайдено"
fi

# Перевірка відкритих файлів
section "ПЕРЕВІРКА ВІДКРИТИХ ФАЙЛІВ"
if command -v lsof &>/dev/null; then
  subsection "Відкриті файли і з'єднання"
  lsof -i > "$OUTPUT_DIR/lsof_network.txt"
  log "Список відкритих мережевих файлів збережено в файлі: lsof_network.txt"

  # Пошук підозрілих відкритих файлів
  lsof -i | grep -E "ESTABLISHED|LISTEN" | grep -v "127.0.0.1\|192.168.\|10." > "$OUTPUT_DIR/lsof_suspicious.txt"
  COUNT=$(wc -l < "$OUTPUT_DIR/lsof_suspicious.txt")
  if [ "$COUNT" -gt 0 ]; then
    result "Виявлено $COUNT підозрілих мережевих з'єднань" "WARNING"
    head -10 "$OUTPUT_DIR/lsof_suspicious.txt" | tee -a "$LOG_FILE"
    log "Повний список у файлі: lsof_suspicious.txt"
  else
    result "Підозрілих мережевих з'єднань не виявлено" "OK"
  fi
fi

# Перевірка аномалій у бібліотеках
section "ПЕРЕВІРКА БІБЛІОТЕК"
subsection "Перевірка завантажених бібліотек"

# Збереження списку завантажених бібліотек
ldconfig -p > "$OUTPUT_DIR/libraries.txt"
log "Список завантажених бібліотек збережено в файлі: libraries.txt"

# Перевірка LD_PRELOAD
if [ -n "$LD_PRELOAD" ]; then
  result "Виявлено використання LD_PRELOAD: $LD_PRELOAD" "WARNING"
else
  result "LD_PRELOAD не використовується" "OK"
fi

# Перевірка файлів /etc/ld.so.*
if [ -f "/etc/ld.so.preload" ]; then
  cat "/etc/ld.so.preload" > "$OUTPUT_DIR/ld_preload_file.txt"
  result "Виявлено файл /etc/ld.so.preload" "WARNING"
  cat "$OUTPUT_DIR/ld_preload_file.txt" | tee -a "$LOG_FILE"
else
  result "Файл /etc/ld.so.preload не знайдено" "OK"
fi

# Перевірка точок підключення RAM дисків
grep -E "tmpfs|ramfs" /proc/mounts > "$OUTPUT_DIR/ram_mounts.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/ram_mounts.txt")
log "Виявлено $COUNT точок підключення RAM дисків. Деталі в файлі: ram_mounts.txt"

# Перевірка наявності контейнерів та віртуальних машин
section "ПЕРЕВІРКА КОНТЕЙНЕРІВ І ВІРТУАЛІЗАЦІЇ"
if command -v docker &>/dev/null; then
  subsection "Аудит Docker"
  docker ps -a > "$OUTPUT_DIR/docker_containers.txt" 2>&1
  log "Список контейнерів Docker збережено в файлі: docker_containers.txt"

  docker images > "$OUTPUT_DIR/docker_images.txt" 2>&1
  log "Список образів Docker збережено в файлі: docker_images.txt"
fi

if command -v virsh &>/dev/null; then
  subsection "Аудит віртуальних машин"
  virsh list --all > "$OUTPUT_DIR/virsh_vms.txt" 2>&1
  log "Список віртуальних машин збережено в файлі: virsh_vms.txt"
fi

# Додаткова перевірка для пошуку бекдорів і вразливостей в PHP файлах
section "РОЗШИРЕНИЙ АУДИТ PHP"
if command -v php &>/dev/null; then
  subsection "Пошук зашифрованого PHP коду"

  # Створення тимчасового скрипту для виявлення зашифрованого/обфускованого коду
  cat > "$OUTPUT_DIR/detect_encoded.php" << 'EOF'
<?php
function checkForObfuscation($file) {
    $content = file_get_contents($file);
    $suspicious = false;
    $reasons = [];

    // Перевірка на довгі рядки base64
    if (preg_match('/base64_decode\s*\(\s*[\'"][^\'"]{100,}[\'"]\s*\)/', $content)) {
        $suspicious = true;
        $reasons[] = "base64_decode з довгим рядком";
    }

    // Перевірка на закодовані функції (функції як рядки)
    if (preg_match('/\$[a-zA-Z0-9_]+\s*=\s*[\'"]assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec[\'"]/', $content)) {
        $suspicious = true;
        $reasons[] = "Рядкові імена небезпечних функцій";
    }

    // Перевірка на зсув символів (chr)
    if (preg_match('/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/', $content)) {
        $suspicious = true;
        $reasons[] = "Використання chr() для обфускації";
    }

    // Перевірка на використання символів для формування імен функцій
    if (preg_match('/\$[a-zA-Z0-9_]+\s*\.\s*\$[a-zA-Z0-9_]+/', $content) &&
        preg_match('/\$[a-zA-Z0-9_]+\([\'"][^\'"]*[\'"]\)/', $content)) {
        $suspicious = true;
        $reasons[] = "Динамічні імена функцій";
    }

    // Перевірка на непрозорі умови
    if (preg_match('/if\s*\(\s*[\'"][^\'"]{20,}[\'"]\s*===\s*[\'"][^\'"]{20,}[\'"]\s*\)/', $content)) {
        $suspicious = true;
        $reasons[] = "Непрозорі порівняння у if";
    }

    // Перевірка на використання gzinflate/gzdecode з base64
    if (preg_match('/gzinflate\s*\(\s*base64_decode\s*\(|gzuncompress\s*\(\s*base64_decode\s*\(|gzdecode\s*\(\s*base64_decode\s*\(/', $content)) {
        $suspicious = true;
        $reasons[] = "Подвійне кодування (gzip+base64)";
    }

    // Перевірка на надто багато str_rot13/strrev
    if (preg_match_all('/str_rot13\s*\(/', $content, $matches) && count($matches[0]) > 3) {
        $suspicious = true;
        $reasons[] = "Багаторазове використання str_rot13()";
    }

    // Перевірка на нестандартну обробку $_POST, $_GET, $_REQUEST
    if (preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*[^\s\'"]{10,}\s*\]/', $content)) {
        $suspicious = true;
        $reasons[] = "Нестандартний доступ до змінних запиту";
    }

    // Перевірка на приховування від WAF за допомогою регулярних виразів
    if (preg_match('/preg_replace\s*\(\s*[\'"]\\/[^\'"]*\\/e[\'"]/', $content)) {
        $suspicious = true;
        $reasons[] = "Використання небезпечного прапора /e в preg_replace()";
    }

    return ['is_suspicious' => $suspicious, 'reasons' => $reasons];
}

$webDirs = ['/var/www', '/var/www/html', '/usr/share/nginx', '/usr/local/apache2/htdocs'];
$results = [];

foreach ($webDirs as $dir) {
    if (!is_dir($dir)) continue;

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $filepath = $file->getPathname();
            $check = checkForObfuscation($filepath);

            if ($check['is_suspicious']) {
                $results[$filepath] = $check['reasons'];
            }
        }
    }
}

// Виведення результатів
echo "Виявлено " . count($results) . " підозрілих файлів\n\n";

foreach ($results as $file => $reasons) {
    echo "Файл: $file\n";
    echo "Причини підозри:\n";
    foreach ($reasons as $reason) {
        echo "- $reason\n";
    }
    echo "\n";
}
EOF

  # Запуск скрипту перевірки
  php "$OUTPUT_DIR/detect_encoded.php" > "$OUTPUT_DIR/encoded_php_results.txt"
  log "Результати пошуку обфускованого PHP коду збережено в файлі: encoded_php_results.txt"

  # Пошук незвичайних патернів в PHP файлах
  subsection "Перевірка PHP захисту від модифікації"
  find /var/www -type f -name "*.php" -exec grep -l "die(" {} \; | xargs grep -l "modified" > "$OUTPUT_DIR/php_modification_checks.txt" 2>/dev/null
  COUNT=$(wc -l < "$OUTPUT_DIR/php_modification_checks.txt" 2>/dev/null || echo "0")
  if [ "$COUNT" -gt 0 ]; then
    result "Виявлено $COUNT PHP файлів з перевіркою модифікацій" "WARNING"
    head -10 "$OUTPUT_DIR/php_modification_checks.txt" | tee -a "$LOG_FILE"
    log "Повний список у файлі: php_modification_checks.txt"
  else
    result "PHP файлів з перевіркою модифікацій не виявлено" "OK"
  fi

  # Перевірка на ознаки PHP веб-шелів
  subsection "Пошук веб-шелів за сигнатурами"
  for path in "${WEB_PATHS[@]}"; do
    if [ -d "$path" ]; then
      # Пошук типових веб-шелів за їх сигнатурами
      grep -r --include="*.php" -l "uname -a" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l "phpinfo()" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l '\$_POST\["cmd"\]' "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l '\$_GET\["cmd"\]' "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l "r57shell" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l "c99shell" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l "WSO" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
      grep -r --include="*.php" -l "FilesMan" "$path" >> "$OUTPUT_DIR/webshell_signatures.txt" 2>/dev/null
    fi
  done

  # Видалення дублікатів
  if [ -f "$OUTPUT_DIR/webshell_signatures.txt" ]; then
    sort -u "$OUTPUT_DIR/webshell_signatures.txt" > "$OUTPUT_DIR/webshell_signatures_unique.txt"
    mv "$OUTPUT_DIR/webshell_signatures_unique.txt" "$OUTPUT_DIR/webshell_signatures.txt"

    COUNT=$(wc -l < "$OUTPUT_DIR/webshell_signatures.txt")
    if [ "$COUNT" -gt 0 ]; then
      result "Виявлено $COUNT потенційних веб-шелів за сигнатурами" "WARNING"
      head -10 "$OUTPUT_DIR/webshell_signatures.txt" | tee -a "$LOG_FILE"
      log "Повний список у файлі: webshell_signatures.txt"
    else
      result "Потенційних веб-шелів за сигнатурами не виявлено" "OK"
    fi
  fi
fi

# Перевірка можливих прихованих файлів та процесів, які приховані за допомогою rootkit'ів
section "ПОШУК ПРИХОВАНИХ ОБ'ЄКТІВ"
subsection "Перевірка прихованих процесів"

# Порівняння виводу ps і /proc
ps_pids=$(ps -ef | awk '{print $2}' | sort -n | uniq)
proc_pids=$(find /proc -maxdepth 1 -type d -regex "/proc/[0-9]+" | awk -F "/" '{print $3}' | sort -n | uniq)

echo "$ps_pids" > "$OUTPUT_DIR/ps_pids.txt"
echo "$proc_pids" > "$OUTPUT_DIR/proc_pids.txt"

# Знаходження PID у /proc, але не у ps
comm -13 "$OUTPUT_DIR/ps_pids.txt" "$OUTPUT_DIR/proc_pids.txt" > "$OUTPUT_DIR/hidden_pids.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/hidden_pids.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT потенційно прихованих процесів" "WARNING"
  for pid in $(cat "$OUTPUT_DIR/hidden_pids.txt"); do
    cmdline=""
    if [ -f "/proc/$pid/cmdline" ]; then
      cmdline=$(cat "/proc/$pid/cmdline" | tr '\0' ' ')
    fi
    echo "PID: $pid, cmdline: $cmdline" | tee -a "$LOG_FILE"
  done
else
  result "Прихованих процесів не виявлено" "OK"
fi

# Перевірка підробних мережевих з'єднань через порівняння ss/netstat і /proc/net
subsection "Перевірка прихованих мережевих з'єднань"
ss -antup > "$OUTPUT_DIR/ss_connections.txt"
cat /proc/net/tcp /proc/net/tcp6 | awk 'NR>1 {print $2, $3, $4}' > "$OUTPUT_DIR/proc_connections.txt"
log "Мережеві з'єднання збережено в файлах: ss_connections.txt і proc_connections.txt"

# Перевірка наявності баннерів доступу
section "ПЕРЕВІРКА БАНЕРІВ ДОСТУПУ"
if [ -f "/etc/issue" ]; then
  cp "/etc/issue" "$OUTPUT_DIR/issue.txt"
  log "Баннер входу в систему збережено в файлі: issue.txt"
fi

if [ -f "/etc/motd" ]; then
  cp "/etc/motd" "$OUTPUT_DIR/motd.txt"
  log "Повідомлення дня збережено в файлі: motd.txt"
fi

# Перевірка на наявність бінарних файлів з SUID/SGID бітами
section "ПЕРЕВІРКА SUID/SGID БІНАРНИХ ФАЙЛІВ"
subsection "Пошук файлів з SUID/SGID бітами"
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > "$OUTPUT_DIR/suid_sgid_files.txt"
log "Список файлів з SUID/SGID бітами збережено в файлі: suid_sgid_files.txt"

# Порівняння з очікуваним списком SUID/SGID файлів
cat > "$OUTPUT_DIR/common_suid_files.txt" << EOF
/bin/mount
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/sbin/mount.nfs
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
EOF

# Знаходження нестандартних SUID/SGID файлів
grep -v -f "$OUTPUT_DIR/common_suid_files.txt" "$OUTPUT_DIR/suid_sgid_files.txt" > "$OUTPUT_DIR/unusual_suid_sgid.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/unusual_suid_sgid.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT нестандартних SUID/SGID файлів" "WARNING"
  head -10 "$OUTPUT_DIR/unusual_suid_sgid.txt" | tee -a "$LOG_FILE"
  log "Повний список у файлі: unusual_suid_sgid.txt"
else
  result "Нестандартних SUID/SGID файлів не виявлено" "OK"
fi

# Пошук файлів з незвичайними часовими штампами
section "ПЕРЕВІРКА ЧАСОВИХ ШТАМПІВ"
subsection "Пошук файлів з підозрілими часовими мітками"

# Пошук файлів з часом модифікації у неробочий час (22:00-06:00)
find /bin /sbin /usr/bin /usr/sbin /etc -type f -not -path "*/\.*" -printf "%T+ %p\n" | grep -E "^[0-9]+-[0-9]+-[0-9]+ (22|23|00|01|02|03|04|05):" | head -100 > "$OUTPUT_DIR/suspicious_timestamps.txt"

# Пошук файлів з часом доступу в майбутньому
find /bin /sbin /usr/bin /usr/sbin /etc -type f -not -path "*/\.*" -anewer /proc/1/stat 2>/dev/null > "$OUTPUT_DIR/future_timestamps.txt"

COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_timestamps.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT файлів з підозрілими часовими мітками" "WARNING"
  head -10 "$OUTPUT_DIR/suspicious_timestamps.txt" | tee -a "$LOG_FILE"
  log "Повний список у файлі: suspicious_timestamps.txt"
else
  result "Файлів з підозрілими часовими мітками не виявлено" "OK"
fi

# Перевірка інтеграції з Active Directory / Domain Controller
section "АУДИТ ДОМЕННОЇ ІНТЕГРАЦІЇ"
if command -v realm &>/dev/null || [ -f "/etc/sssd/sssd.conf" ] || [ -f "/etc/krb5.conf" ]; then
  subsection "Перевірка інтеграції з доменом"

  # Перевірка статусу realm
  if command -v realm &>/dev/null; then
    realm list > "$OUTPUT_DIR/realm_status.txt" 2>&1
    log "Статус realm збережено в файлі: realm_status.txt"
  fi

  # Перевірка конфігурації SSSD
  if [ -f "/etc/sssd/sssd.conf" ]; then
    cp "/etc/sssd/sssd.conf" "$OUTPUT_DIR/sssd.conf" 2>/dev/null || echo "Не вдалося скопіювати /etc/sssd/sssd.conf" | tee -a "$LOG_FILE"
    log "Конфігурація SSSD збережена в файлі: sssd.conf"
  fi

  # Перевірка конфігурації Kerberos
  if [ -f "/etc/krb5.conf" ]; then
    cp "/etc/krb5.conf" "$OUTPUT_DIR/krb5.conf"
    log "Конфігурація Kerberos збережена в файлі: krb5.conf"
  fi

  # Перев
