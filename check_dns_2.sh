#!/bin/bash

# 🛠️ Перевірка проблемних файлів

# Перевірка наявності вразливого pkexec (CVE-2021-4034)
echo "Перевірка наявності вразливого pkexec (CVE-2021-4034)..."
if [ -f "/usr/bin/pkexec" ]; then
    echo "/usr/bin/pkexec знайдено!"
else
    echo "/usr/bin/pkexec не знайдено."
fi

# Перевірка наявності вразливого snap-confine (CVE-2019-7304)
echo "Перевірка наявності вразливого snap-confine (CVE-2019-7304)..."
if [ -f "/usr/lib/snapd/snap-confine" ]; then
    echo "/usr/lib/snapd/snap-confine знайдено!"
else
    echo "/usr/lib/snapd/snap-confine не знайдено."
fi

# Перевірка на версію файлів /usr/bin/at, /usr/bin/passwd, /usr/bin/newgrp, /usr/bin/chfn, /usr/bin/sudo
echo "Перевірка версій файлів /usr/bin/at, /usr/bin/passwd, /usr/bin/newgrp, /usr/bin/chfn, /usr/bin/sudo..."
for file in /usr/bin/at /usr/bin/passwd /usr/bin/newgrp /usr/bin/chfn /usr/bin/sudo; do
    if [ -f "$file" ]; then
        echo "$file знайдено, перевірка версії:"
        $file --version 2>/dev/null || echo "Не вдалося отримати версію для $file"
    else
        echo "$file не знайдено."
    fi
done

# Перевірка на наявність підозрілих writable залежностей для ldap_child
echo "Перевірка writable залежностей для /usr/lib/x86_64-linux-gnu/sssd/ldap_child..."
if [ -f "/usr/lib/x86_64-linux-gnu/sssd/ldap_child" ]; then
    W_PARAMS=$(ldd /usr/lib/x86_64-linux-gnu/sssd/ldap_child | grep 'writable')
    if [ -n "$W_PARAMS" ]; then
        echo "Знайдено writable залежності для ldap_child!"
    else
        echo "Writable залежностей не знайдено для ldap_child."
    fi
else
    echo "/usr/lib/x86_64-linux-gnu/sssd/ldap_child не знайдено."
fi

# 📜 Перевірка наявності небезпечного скрипту gettext.sh в PATH
echo "Перевірка наявності небезпечного скрипту gettext.sh..."
if [ -f "/usr/bin/gettext.sh" ]; then
    echo "/usr/bin/gettext.sh знайдено! Перевіряємо вміст:"
    less /usr/bin/gettext.sh
else
    echo "/usr/bin/gettext.sh не знайдено."
fi

# 🧬 Перевірка потенційної уразливості sudo (CVE-2019-18634)
echo "Перевірка на наявність уразливості sudo (CVE-2019-18634)..."
grep "pwfeedback" /etc/sudoers /etc/sudoers.d/* 2>/dev/null

if [ $? -eq 0 ]; then
    echo "Виявлено використання pwfeedback в sudoers!"
else
    echo "pwfeedback не знайдено в sudoers."
fi

echo "Перевірка завершена."
