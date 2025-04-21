#!/bin/bash

# ✅ 1. Видалення вебшела та пошук інших

# Пошук всіх потенційних шелоподібних файлів (з використанням небезпечних функцій PHP)
echo "Пошук можливих вебшелів (shell_exec, eval, base64_decode, system, exec, passthru) у PHP файлах..."
grep -r --include="*.php" -E "shell_exec|eval|base64_decode|system|exec|passthru" /var/www/

# Перевірка прав на нові або підозрілі PHP файли (які змінені за останні 7 днів)
echo "Перевірка прав на підозрілі файли, змінені за останні 7 днів..."
find /var/www/ -type f -name "*.php" -mtime -7 -exec ls -l {} \;

# Видалення знайдених вебшелів (створюємо резервну копію перед видаленням)
echo "Створення резервної копії підозрілих PHP файлів у /tmp..."
grep -r --include="*.php" -E "shell_exec|eval|base64_decode|system|exec|passthru" /var/www/ | awk '{print $1}' | xargs -I {} cp {} /tmp/

echo "Видалення знайдених вебшелів..."
grep -r --include="*.php" -E "shell_exec|eval|base64_decode|system|exec|passthru" /var/www/ | awk '{print $1}' | xargs rm -f

# 🛡️ 2. Обмеження виконання (конфігурації та пермішени)

# Заборона виконання PHP в директорії uploads та інших публічних директоріях
#echo "Створення .htaccess файлу для заборони виконання PHP у /var/www/uploads/..."
#echo -e "<FilesMatch \"\\.php$\">\n  Deny from all\n</FilesMatch>" > /var/www/uploads/.htaccess

# Або через Apache конфігурацію для заборони виконання PHP у /var/www/uploads
#echo "Заборона виконання PHP в /var/www/uploads через конфігурацію Apache..."
#echo -e "<Directory /var/www/uploads>\n    php_admin_flag engine off\n</Directory>" >> /etc/apache2/apache2.conf

# Перезавантаження Apache для застосування змін
#echo "Перезавантаження Apache..."
#systemctl reload apache2

# 🗂️ 3. Пермішени: зменшення прав на запис

# Встановлення прав тільки на читання для всіх PHP файлів
#echo "Зміна прав доступу для PHP файлів на 644..."
#find /var/www/ -type f -name "*.php" -exec chmod 644 {} \;

# 🔒 1. Заборона створення файлів та папок через права доступу

# Обмеження прав на запис у директорії /var/www/uploads
echo "Обмеження прав на запис у директорії /var/www/uploads..."
chmod 555 /var/www/uploads

echo "Завершено налаштування безпеки для веб-сервера."
