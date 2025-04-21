#!/bin/bash
# Комплексний скрипт для аудиту безпеки серверів CentOS
# Спеціалізується на перевірці PHP, DNS (PowerDNS), HTTP та пошуку індикаторів компрометації

# Налаштування кольорів для виводу
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
CYAN="\033[1;36m"
NC="\033[0m" # No Color

# Створення каталогу для результатів
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_DIR="security_audit_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/audit_log.txt"

# Функція для логування
log() {
  echo -e "${1}" | tee -a "$LOG_FILE"
}

# Функція для заголовків розділів
section() {
  log "\n${BLUE}============================================================${NC}"
  log "${BLUE}= ${1}${NC}"
  log "${BLUE}============================================================${NC}"
}

# Функція для підрозділів
subsection() {
  log "\n${CYAN}>>> ${1}${NC}"
  log "${CYAN}-----------------------------------------------------------${NC}"
}

# Функція для результатів тестів
result() {
  if [ "$2" = "OK" ]; then
    log "${GREEN}[OK]${NC} $1"
  elif [ "$2" = "WARNING" ]; then
    log "${YELLOW}[ПОПЕРЕДЖЕННЯ]${NC} $1"
  else
    log "${RED}[КРИТИЧНО]${NC} $1"
  fi
}

# Початок аудиту
log "Комплексний аудит безпеки сервера"
log "Початок: $(date)"
log "Хост: $(hostname)"
log "IP-адреси: $(hostname -I)"
log "ОС: $(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d '"' -f2)"

# Збереження системної інформації
section "СИСТЕМНА ІНФОРМАЦІЯ"
subsection "Системні деталі"
uname -a > "$OUTPUT_DIR/system_info.txt"
log "Версія ядра: $(uname -r)"
log "Час роботи: $(uptime)"

subsection "Дисковий простір"
df -h > "$OUTPUT_DIR/disk_usage.txt"
log "Деталі в файлі: disk_usage.txt"

subsection "Використання пам'яті"
free -m > "$OUTPUT_DIR/memory_usage.txt"
log "Деталі в файлі: memory_usage.txt"

# Перевірка активних користувачів
section "АУДИТ КОРИСТУВАЧІВ"
subsection "Поточні активні сесії"
w > "$OUTPUT_DIR/active_users.txt"
log "Деталі в файлі: active_users.txt"

subsection "Історія входів в систему"
last -n 50 > "$OUTPUT_DIR/last_logins.txt"
log "Останні 50 входів збережено в файлі: last_logins.txt"

lastlog > "$OUTPUT_DIR/lastlog.txt"
log "Остання активність користувачів збережена в файлі: lastlog.txt"

# Пошук підозрілих облікових записів користувачів
subsection "Аналіз облікових записів"
awk -F: '$3 == 0 && $1 != "root"' /etc/passwd > "$OUTPUT_DIR/suspicious_accounts.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_accounts.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Знайдено $COUNT облікових записів з UID=0 (крім root)" "CRITICAL"
  cat "$OUTPUT_DIR/suspicious_accounts.txt" | tee -a "$LOG_FILE"
else
  result "Облікових записів з UID=0 (крім root) не знайдено" "OK"
fi

# Користувачі з правами sudo
grep -v "^#" /etc/sudoers | grep -v "^$" > "$OUTPUT_DIR/sudoers.txt"
log "Налаштування sudoers збережено в файлі: sudoers.txt"

ls -la /etc/sudoers.d/ > "$OUTPUT_DIR/sudoers_d.txt"
log "Вміст /etc/sudoers.d/ збережено в файлі: sudoers_d.txt"

# Перевірка мережевих налаштувань
section "АУДИТ МЕРЕЖІ"
subsection "Відкриті порти і з'єднання"
ss -tulpn > "$OUTPUT_DIR/listening_ports.txt"
log "Відкриті порти збережено в файлі: listening_ports.txt"

# Перевірка активних з'єднань
ss -ntp > "$OUTPUT_DIR/active_connections.txt"
log "Активні з'єднання збережено в файлі: active_connections.txt"

# Виявлення підозрілих вихідних з'єднань
ss -antp | grep ESTABLISHED | grep -v "127.0.0.1\|192.168.\|10." > "$OUTPUT_DIR/suspicious_connections.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_connections.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT підозрілих вихідних з'єднань" "WARNING"
  head -5 "$OUTPUT_DIR/suspicious_connections.txt" | tee -a "$LOG_FILE"
  log "Повний список у файлі: suspicious_connections.txt"
else
  result "Підозрілих вихідних з'єднань не виявлено" "OK"
fi

# Перевірка налаштувань фаєрволу
subsection "Налаштування фаєрволу"
if command -v firewall-cmd &>/dev/null; then
  firewall-cmd --list-all > "$OUTPUT_DIR/firewalld_config.txt"
  log "Налаштування firewalld збережено в файлі: firewalld_config.txt"
fi

iptables -L -n -v > "$OUTPUT_DIR/iptables_rules.txt"
log "Правила iptables збережено в файлі: iptables_rules.txt"

# Перевірка запущених процесів
section "АНАЛІЗ ПРОЦЕСІВ"
subsection "Запущені процеси"
ps auxf > "$OUTPUT_DIR/processes.txt"
log "Список процесів збережено в файлі: processes.txt"

# Пошук підозрілих процесів
ps aux | grep -i "nc\|netcat\|ncat\|cryptominer\|kworker" | grep -v grep > "$OUTPUT_DIR/suspicious_processes.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_processes.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT потенційно підозрілих процесів" "WARNING"
  cat "$OUTPUT_DIR/suspicious_processes.txt" | tee -a "$LOG_FILE"
else
  result "Підозрілих процесів не виявлено" "OK"
fi

# Перевірка системного завантаження
subsection "Елементи автозавантаження"
systemctl list-unit-files | grep enabled > "$OUTPUT_DIR/enabled_services.txt"
log "Увімкнені сервіси збережено в файлі: enabled_services.txt"

# Перевірка нестандартних сервісів
find /etc/systemd/system/ /usr/lib/systemd/system/ -type f -name "*.service" -mtime -30 > "$OUTPUT_DIR/new_services.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/new_services.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT нових системних сервісів (створених за останні 30 днів)" "WARNING"
  head -10 "$OUTPUT_DIR/new_services.txt" | tee -a "$LOG_FILE"
  log "Повний список у файлі: new_services.txt"
else
  result "Нових системних сервісів не виявлено" "OK"
fi

# Перевірка cron завдань
subsection "Заплановані завдання (cron)"
# Створення тимчасового файлу для всіх завдань cron
CRONFILE="$OUTPUT_DIR/all_cron_jobs.txt"
touch $CRONFILE

# Системні cron-завдання
echo "=== Системні cron завдання ===" > $CRONFILE
for file in /etc/cron.d/* /etc/crontab /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  if [ -f "$file" ]; then
    echo "--- $file ---" >> $CRONFILE
    cat "$file" | grep -v "^#" | grep -v "^$" >> $CRONFILE
    echo "" >> $CRONFILE
  fi
done

# Користувацькі cron-завдання
echo "=== Користувацькі cron завдання ===" >> $CRONFILE
for user in $(cut -f1 -d: /etc/passwd); do
  crontab_content=$(crontab -u $user -l 2>/dev/null)
  if [ $? -eq 0 ]; then
    echo "--- Користувач: $user ---" >> $CRONFILE
    echo "$crontab_content" | grep -v "^#" | grep -v "^$" >> $CRONFILE
    echo "" >> $CRONFILE
  fi
done

# Пошук підозрілих завдань cron
grep -E "curl|wget|nc|bash.*base64|perl -e|python -c" $CRONFILE > "$OUTPUT_DIR/suspicious_cron.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_cron.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT потенційно підозрілих cron завдань" "WARNING"
  cat "$OUTPUT_DIR/suspicious_cron.txt" | tee -a "$LOG_FILE"
else
  result "Підозрілих cron завдань не виявлено" "OK"
fi

log "Всі cron завдання збережено в файлі: all_cron_jobs.txt"

# Перевірка PHP налаштувань
section "АУДИТ PHP"
if command -v php &>/dev/null; then
  subsection "Налаштування PHP"

  # Визначення файлу php.ini
  PHP_INI=$(php -i | grep "Loaded Configuration File" | awk '{print $5}')
  log "Використовується PHP конфігураційний файл: $PHP_INI"

  # Копіювання php.ini для аналізу
  if [ -f "$PHP_INI" ]; then
    cp "$PHP_INI" "$OUTPUT_DIR/php.ini"
    log "php.ini скопійовано в файл: php.ini"
  fi

  # Перевірка критичних налаштувань PHP
  log "Критичні налаштування безпеки PHP:"
  DANGEROUS_SETTINGS=("allow_url_fopen" "allow_url_include" "display_errors" "expose_php" "enable_dl" "open_basedir" "disable_functions")

  for setting in "${DANGEROUS_SETTINGS[@]}"; do
    value=$(php -r "echo ini_get('$setting');")
    case $setting in
      "allow_url_fopen"|"allow_url_include"|"display_errors"|"expose_php"|"enable_dl")
        if [ "$value" == "1" ] || [ "$value" == "On" ]; then
          result "$setting = $value (рекомендується: Off)" "WARNING"
        else
          result "$setting = $value" "OK"
        fi
        ;;
      "open_basedir")
        if [ -z "$value" ]; then
          result "$setting не налаштовано (рекомендується: вказати обмежений шлях)" "WARNING"
        else
          result "$setting = $value" "OK"
        fi
        ;;
      "disable_functions")
        if [ -z "$value" ]; then
          result "$setting не налаштовано (рекомендується: заборонити небезпечні функції)" "WARNING"
        else
          result "$setting = $value" "OK"
        fi
        ;;
    esac
  done

  # Збереження всіх налаштувань PHP
  php -i > "$OUTPUT_DIR/php_info.txt"
  log "Повна інформація про PHP збережена в файлі: php_info.txt"

  # Список встановлених модулів PHP
  php -m > "$OUTPUT_DIR/php_modules.txt"
  log "Модулі PHP збережено в файлі: php_modules.txt"

  # Пошук веб-директорій для сканування
  subsection "Перевірка PHP файлів на наявність шкідливого коду"
  WEB_PATHS=("/var/www" "/var/www/html" "/usr/share/nginx" "/usr/local/apache2/htdocs")

  # Файл для результатів сканування
  SCAN_RESULTS="$OUTPUT_DIR/php_scan_results.txt"
  touch $SCAN_RESULTS

  for path in "${WEB_PATHS[@]}"; do
    if [ -d "$path" ]; then
      log "Сканування директорії: $path"

      # Пошук файлів з підозрілим кодом
      echo "=== Файли з потенційно небезпечними функціями в $path ===" >> $SCAN_RESULTS
      echo "--- eval() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "eval *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- base64_decode() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "base64_decode *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- system() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "system *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- exec() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "exec *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- shell_exec() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "shell_exec *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- passthru() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "passthru *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- assert() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "assert *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- preg_replace() з /e ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "preg_replace *(.*/e" "$path" 2>/dev/null >> $SCAN_RESULTS

      echo "--- create_function() ---" >> $SCAN_RESULTS
      grep -r --include="*.php" -l "create_function *(" "$path" 2>/dev/null >> $SCAN_RESULTS

      # Пошук файлів з підозрілими іменами
      echo "=== Файли з підозрілими іменами в $path ===" >> $SCAN_RESULTS
      find "$path" -type f -name "*.php" | grep -i -E 'shell|back|door|c99|r57|webshell|cmd|alfa|wso|mini|simple|b374k|c100' >> $SCAN_RESULTS

      # Пошук нещодавно модифікованих PHP файлів
      echo "=== Нещодавно модифіковані PHP файли в $path (останні 7 днів) ===" >> $SCAN_RESULTS
      find "$path" -name "*.php" -type f -mtime -7 -ls >> $SCAN_RESULTS

      # Пошук прихованих PHP файлів
      echo "=== Приховані PHP файли в $path ===" >> $SCAN_RESULTS
      find "$path" -name ".*php*" -type f -ls >> $SCAN_RESULTS

      # Пошук файлів з підозрілими дозволами
      echo "=== PHP файли з небезпечними дозволами (777) в $path ===" >> $SCAN_RESULTS
      find "$path" -name "*.php" -type f -perm -777 -ls >> $SCAN_RESULTS

      # Створення хешів PHP файлів
      find "$path" -name "*.php" -type f -exec md5sum {} \; > "$OUTPUT_DIR/php_files_hashes.txt"
    fi
  done

  # Підрахунок підозрілих PHP файлів
  SUSPICIOUS_COUNT=$(grep -v "===" "$SCAN_RESULTS" | grep -v "^$" | wc -l)
  if [ "$SUSPICIOUS_COUNT" -gt 0 ]; then
    result "Виявлено $SUSPICIOUS_COUNT потенційно підозрілих PHP файлів" "WARNING"
    log "Детальні результати сканування в файлі: php_scan_results.txt"
  else
    result "Підозрілих PHP файлів не виявлено" "OK"
  fi
else
  log "PHP не встановлено на сервері"
fi

# Аудит HTTP сервера
section "АУДИТ ВЕБ-СЕРВЕРА"
# Перевірка Apache
if [ -d "/etc/httpd" ] || [ -d "/etc/apache2" ]; then
  subsection "Перевірка Apache"

  if [ -d "/etc/httpd" ]; then
    # CentOS / RHEL
    APACHE_DIR="/etc/httpd"
    APACHE_LOGS="/var/log/httpd"
  else
    # Debian / Ubuntu
    APACHE_DIR="/etc/apache2"
    APACHE_LOGS="/var/log/apache2"
  fi

  # Збереження конфігурації Apache
  find "$APACHE_DIR" -type f -name "*.conf" -exec cp {} "$OUTPUT_DIR/" \; 2>/dev/null
  log "Конфігураційні файли Apache скопійовано"

  # Перевірка нестандартних модулів
  if [ -f "$APACHE_DIR/conf/httpd.conf" ]; then
    grep "LoadModule" "$APACHE_DIR/conf/httpd.conf" > "$OUTPUT_DIR/apache_modules.txt"
  elif [ -f "$APACHE_DIR/conf/apache2.conf" ]; then
    ls -la "$APACHE_DIR/mods-enabled/" > "$OUTPUT_DIR/apache_modules.txt"
  fi
  log "Інформація про модулі Apache збережена в файлі: apache_modules.txt"

  # Пошук підозрілих правил перезапису
  grep -r "RewriteRule" "$APACHE_DIR/" > "$OUTPUT_DIR/apache_rewrites.txt"
  log "Правила перезапису Apache збережено в файлі: apache_rewrites.txt"

  # Пошук підозрілих правил проксі
  grep -r "ProxyPass\|ProxyPassReverse" "$APACHE_DIR/" > "$OUTPUT_DIR/apache_proxy.txt"
  log "Правила проксі Apache збережено в файлі: apache_proxy.txt"

  # Аналіз логів Apache
  if [ -d "$APACHE_LOGS" ]; then
    # Пошук потенційно шкідливих запитів в логах
    grep -E "POST|PUT" "$APACHE_LOGS/access_log" | grep -E '\.php|\.cgi' | tail -1000 > "$OUTPUT_DIR/apache_suspect_requests.txt"
    log "Підозрілі запити до Apache збережено в файлі: apache_suspect_requests.txt"

    # Пошук помилок в логах
    grep -i "error\|warning\|critical" "$APACHE_LOGS/error_log" | tail -1000 > "$OUTPUT_DIR/apache_errors.txt"
    log "Останні 1000 помилок Apache збережено в файлі: apache_errors.txt"
  fi
fi

# Перевірка Nginx
if [ -d "/etc/nginx" ]; then
  subsection "Перевірка Nginx"

  # Збереження конфігурації Nginx
  find "/etc/nginx" -type f -name "*.conf" -exec cp {} "$OUTPUT_DIR/" \; 2>/dev/null
  log "Конфігураційні файли Nginx скопійовано"

  # Пошук підозрілих правил перезапису та проксі
  grep -r "proxy_pass" "/etc/nginx/" > "$OUTPUT_DIR/nginx_proxy.txt"
  log "Правила проксі Nginx збережено в файлі: nginx_proxy.txt"

  grep -r "rewrite" "/etc/nginx/" > "$OUTPUT_DIR/nginx_rewrites.txt"
  log "Правила перезапису Nginx збережено в файлі: nginx_rewrites.txt"

  # Аналіз логів Nginx
  if [ -d "/var/log/nginx" ]; then
    # Пошук потенційно шкідливих запитів в логах
    grep -E "POST|PUT" "/var/log/nginx/access.log" | grep -E '\.php|\.cgi' | tail -1000 > "$OUTPUT_DIR/nginx_suspect_requests.txt"
    log "Підозрілі запити до Nginx збережено в файлі: nginx_suspect_requests.txt"

    # Пошук помилок в логах
    grep -i "error\|warning\|critical" "/var/log/nginx/error.log" | tail -1000 > "$OUTPUT_DIR/nginx_errors.txt"
    log "Останні 1000 помилок Nginx збережено в файлі: nginx_errors.txt"
  fi
fi

# Аудит PowerDNS
section "АУДИТ DNS"
if command -v pdns_server &>/dev/null || [ -d "/etc/powerdns" ]; then
  subsection "Перевірка PowerDNS"

  # Збереження конфігурації PowerDNS
  if [ -f "/etc/powerdns/pdns.conf" ]; then
    cp "/etc/powerdns/pdns.conf" "$OUTPUT_DIR/pdns.conf"
    cat "/etc/powerdns/pdns.conf" | grep -v "^#" | grep -v "^$" > "$OUTPUT_DIR/pdns_clean.conf"
    log "Конфігурація PowerDNS збережена в файлах: pdns.conf і pdns_clean.conf"
  fi

  if [ -f "/var/log/pdns.log" ]; then
    # Пошук помилок в логах PowerDNS
    grep -i "error\|warning\|critical" "/var/log/pdns.log" | tail -1000 > "$OUTPUT_DIR/pdns_errors.txt"
    log "Останні 1000 помилок PowerDNS збережено в файлі: pdns_errors.txt"
  fi

  # Перевірка зон DNS
  if command -v pdnsutil &>/dev/null; then
    pdnsutil list-all-zones > "$OUTPUT_DIR/pdns_zones.txt"
    log "Список зон PowerDNS збережено в файлі: pdns_zones.txt"

    # Перевірка кожної зони
    while read zone; do
      pdnsutil list-zone "$zone" > "$OUTPUT_DIR/zone_${zone}.txt"
    done < "$OUTPUT_DIR/pdns_zones.txt"
    log "Вміст зон DNS збережено в окремих файлах"

    # Пошук підозрілих записів DNS
    grep -r -E "\.ru|\.cn|\.su|pastebin|gist|githubusercontent|bit\.ly|tinyurl|goo\.gl" "$OUTPUT_DIR/zone_*" > "$OUTPUT_DIR/suspicious_dns_records.txt"
    COUNT=$(wc -l < "$OUTPUT_DIR/suspicious_dns_records.txt")
    if [ "$COUNT" -gt 0 ]; then
      result "Виявлено $COUNT потенційно підозрілих DNS записів" "WARNING"
      head -10 "$OUTPUT_DIR/suspicious_dns_records.txt" | tee -a "$LOG_FILE"
      log "Повний список у файлі: suspicious_dns_records.txt"
    else
      result "Підозрілих DNS записів не виявлено" "OK"
    fi
  fi
else
  log "PowerDNS не виявлено на сервері"
fi

# Аналіз системних логів
section "АУДИТ СИСТЕМНИХ ЛОГІВ"
subsection "Аналіз логів автентифікації"
if [ -f "/var/log/secure" ]; then
  # CentOS/RHEL
  grep "authentication failure\|Failed password" /var/log/secure | tail -100 > "$OUTPUT_DIR/auth_failures.txt"
elif [ -f "/var/log/auth.log" ]; then
  # Debian/Ubuntu
  grep "authentication failure\|Failed password" /var/log/auth.log | tail -100 > "$OUTPUT_DIR/auth_failures.txt"
fi
log "Останні 100 невдалих спроб автентифікації збережено в файлі: auth_failures.txt"

subsection "Аналіз системних логів"
if [ -f "/var/log/messages" ]; then
  grep -i "error\|failed\|warning\|critical" /var/log/messages | tail -100 > "$OUTPUT_DIR/system_errors.txt"
  log "Останні 100 системних помилок збережено в файлі: system_errors.txt"
fi

# Перевірка auditd, якщо він встановлений
if command -v ausearch &>/dev/null; then
  ausearch -ts today -i > "$OUTPUT_DIR/audit_today.txt"
  log "Сьогоднішні події аудиту збережено в файлі: audit_today.txt"

  # Пошук підозрілих подій аудиту
  ausearch -i -k delete | tail -100 > "$OUTPUT_DIR/audit_delete.txt"
  log "Події видалення збережено в файлі: audit_delete.txt"

  ausearch -i -m execve | grep -E 'wget|curl|nc|bash.*-i' | tail -100 > "$OUTPUT_DIR/audit_execve.txt"
  log "Підозрілі виконання команд збережено в файлі: audit_execve.txt"
fi

# Пошук нещодавно створених файлів
section "ПОШУК НЕЩОДАВНО СТВОРЕНИХ ФАЙЛІВ"
subsection "Файли, створені за останні 24 годин"
find / -type f -mtime -1 -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" -not -path "/dev/*" -not -path "/tmp/*" -ls 2>/dev/null > "$OUTPUT_DIR/recent_files.txt"
log "Список нещодавно створених файлів збережено в файлі: recent_files.txt"

# Пошук підозрілих файлів у тимчасових каталогах
subsection "Перевірка тимчасових каталогів"
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null > "$OUTPUT_DIR/temp_files.txt"
log "Список файлів у тимчасових каталогах збережено в файлі: temp_files.txt"

# Пошук скриптів у тимчасових каталогах
find /tmp /var/tmp /dev/shm -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" 2>/dev/null > "$OUTPUT_DIR/temp_scripts.txt"
COUNT=$(wc -l < "$OUTPUT_DIR/temp_scripts.txt")
if [ "$COUNT" -gt 0 ]; then
  result "Виявлено $COUNT скриптів у тимчасових каталогах" "WARNING"
  cat "$OUTPUT_DIR/temp_scripts.txt" | tee -a "$LOG_FILE"
else
  result "Скриптів у тимчасових каталогах не виявлено" "OK"
fi

# Перевірка наявності rootkit'ів
section "ПЕРЕВІРКА НА ROOTKIT"
if command -v rkhunter &>/dev/null; then
  subsection "Запуск rkhunter"
  rkhunter --check --skip-keypress > "$OUTPUT_DIR/rkhunter_results.txt" 2>&1
  log "Результати перевірки rkhunter збережено в файлі: rkhunter_results.txt"

  # Пошук тривог у результатах rkhunter
  grep -i "warning\|infected" "$OUTPUT_DIR/rkhunter_results.txt" > "$OUTPUT_DIR/rkhunter_warnings.txt"
  COUNT=$(wc -l < "$OUTPUT_DIR/rkhunter_warnings.txt")
  if [ "$COUNT" -gt 0 ]; then
    result "rkhunter виявив $COUNT потенційних загроз" "WARNING"
    cat "$OUTPUT_DIR/rkhunter_warnings.txt" | tee -a "$LOG_FILE"
  else
    result "rkhunter не виявив загроз" "OK"
  fi
else
  log "rkhunter не встановлено"
fi
