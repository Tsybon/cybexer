#!/bin/bash

# Перевірка MySQL на доступ без пароля (root користувач)
echo "Перевірка MySQL на наявність root без пароля..."

# Перевірка, чи має root доступ без пароля
MYSQL_STATUS=$(mysql -u root -e "SHOW VARIABLES LIKE 'skip-grant-tables';" 2>/dev/null)

if [[ -z "$MYSQL_STATUS" ]]; then
    echo "Загроза: MySQL має доступ до root без пароля!"
else
    echo "MySQL має захист від доступу без пароля."
fi

# Перевірка прав Apache на sudo без пароля
echo "Перевірка sudoers для Apache..."

# Перевіряємо, чи є запис про apache з правами NOPASSWD
SUDO_APACHE=$(sudo grep -E '^apache\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL' /etc/sudoers 2>/dev/null)

if [[ -n "$SUDO_APACHE" ]]; then
    echo "Загроза: apache має права на виконання команд з sudo без пароля!"
    echo "Видаляємо NOPASSWD для apache з файлу sudoers..."
    #sudo sed -i '/apache\s\+ALL=(ALL)\s\+NOPASSWD:\s\+ALL/d' /etc/sudoers
    echo "NOPASSWD для apache видалено."
else
    echo "apache не має прав на виконання команд з sudo без пароля."
fi

echo "Перевірка завершена."
