#!/bin/bash

# Функция для установки и настройки ClamAV на CentOS
install_clamav_centos() {
    echo "Установка ClamAV на CentOS..."
    sudo yum -y update
    sudo yum -y install epel-release
    sudo yum -y install clamav clamav-update
    sudo systemctl enable clamd@scan
    sudo systemctl start clamd@scan

    echo "Обновление базы данных ClamAV..."
    sudo freshclam

    echo "Настройка автоматической проверки..."
    sudo systemctl enable clamav-freshclam
    sudo systemctl start clamav-freshclam

    echo "ClamAV установлен и настроен на CentOS!"
}

# Функция для установки и настройки ClamAV на Ubuntu
install_clamav_ubuntu() {
    echo "Установка ClamAV на Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y clamav clamav-daemon

    echo "Обновление базы данных ClamAV..."
    sudo freshclam

    echo "Настройка автоматической проверки..."
    sudo systemctl enable clamav-freshclam
    sudo systemctl start clamav-freshclam

    echo "ClamAV установлен и настроен на Ubuntu!"
}

# Проверка на ОС и выполнение соответствующей функции
if [ -f /etc/centos-release ]; then
    install_clamav_centos
elif [ -f /etc/lsb-release ]; then
    install_clamav_ubuntu
else
    echo "Операционная система не поддерживается в этом скрипте."
    exit 1
fi

echo "Антивирус установлен и настроен."
