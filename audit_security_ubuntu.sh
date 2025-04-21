#!/bin/bash

# Визначимо файл для запису результатів
LOGFILE="/var/log/security_audit_$(date +%F_%T).log"
echo "Збір результатів перевірки безпеки..." > $LOGFILE

# Перевірка на наявність веб-шелів у веб-директоріях
echo "Перевірка на наявність веб-шелів..." >> $LOGFILE
find /var/www /usr/share/nginx/html /var/www/html -type f -iname "*.php" -exec grep -Ei "base64_decode|eval|shell_exec|system|passthru|exec" {} \; -print >> $LOGFILE 2>&1

# Перевірка незвичних cron-задач та скриптів
echo "Перевірка cron-задач..." >> $LOGFILE
crontab -l >> $LOGFILE 2>&1
echo "Перевірка системних cron-задач..." >> $LOGFILE
ls -al /etc/cron* /var/spool/cron/ >> $LOGFILE 2>&1
echo "Перевірка /etc/rc.local..." >> $LOGFILE
cat /etc/rc.local >> $LOGFILE 2>&1
echo "Перевірка systemd-сервісів..." >> $LOGFILE
find /etc/systemd/system /lib/systemd/system -type f -exec grep -i 'bash' {} \; -print >> $LOGFILE 2>&1

# Перевірка на наявність незвичних процесів
echo "Перевірка запущених процесів..." >> $LOGFILE
ps auxf >> $LOGFILE 2>&1
echo "Перевірка відкритих портів..." >> $LOGFILE
ss -tulnp >> $LOGFILE 2>&1

# Перевірка руткітів
echo "Перевірка на руткіти..." >> $LOGFILE
chkrootkit >> $LOGFILE 2>&1
rkhunter --check >> $LOGFILE 2>&1

# Перевірка конфігурації PowerDNS
echo "Перевірка конфігурації PowerDNS..." >> $LOGFILE
cat /etc/powerdns/pdns.conf >> $LOGFILE 2>&1
echo "Логи PowerDNS..." >> $LOGFILE
journalctl -u pdns.service >> $LOGFILE 2>&1
tail -n 100 /var/log/syslog | grep pdns >> $LOGFILE 2>&1

# Перевірка SSH підключень та логів автентифікації
echo "Перевірка SSH підключень..." >> $LOGFILE
last -a | grep -i ssh >> $LOGFILE 2>&1
echo "Перевірка логів автентифікації..." >> $LOGFILE
grep -i "Accepted" /var/log/auth.log >> $LOGFILE 2>&1
grep -i "Failed" /var/log/auth.log >> $LOGFILE 2>&1

# Перевірка активності користувача "Administrator"
echo "Перевірка активності користувача 'Administrator'..." >> $LOGFILE
ausearch -ua $(id -u Administrator) >> $LOGFILE 2>&1
grep "Administrator" /var/log/auth.log >> $LOGFILE 2>&1

# Перевірка на підозрілі мережеві з'єднання (DNS тунелювання або атаки)
echo "Перевірка аномальних DNS запитів..." >> $LOGFILE
tcpdump -nn -i any port 53 >> $LOGFILE 2>&1

# Перевірка на незвичні зміни системних файлів
echo "Перевірка на незвичні зміни системних файлів..." >> $LOGFILE
find /etc /var /home -type f -exec sha256sum {} \; > /tmp/current_checksums.txt
diff /tmp/current_checksums.txt /tmp/last_checksums.txt >> $LOGFILE 2>&1

echo "Перевірка завершена." >> $LOGFILE
