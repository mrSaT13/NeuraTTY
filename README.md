# 🔐 NeuraTTY — SSH-клиент для разработчиков и сисадминов

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://github.com/mrSaT13/NeuraTTY)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15-green.svg)](https://pypi.org/project/PyQt5/)

Современное приложение на PyQt5 для подключения к удалённым серверам по SSH: вкладки, SFTP-браузер, темы терминала, шифрование паролей и PIN-защита.

<img width="1000" height="732" alt="изображение" src="https://github.com/user-attachments/assets/8884aa0f-0748-4b50-9aaf-e9a0c5ef1962" />


## ✨ Возможности

- 🔐 PIN-защита приложения (блокировка без потери сворачивания окна)
- 📌 Системный трей: иконка с меню, крестик сворачивает в трей
- 💾 Сохранение сессий (пароли шифруются Fernet, ключ — в keyring или локально 0600)
- 🛡 Проверка host key: `known_hosts` + диалог SHA256/MD5, защита от MITM
- 📂 SFTP-браузер (загрузка/скачивание/mkdir/удаление)
- 🎨 Темы терминала (9): Dracula, Solarized Dark, Monokai, Nord, One Dark, Gruvbox Dark, Tokyo Night, Catppuccin Mocha, GitHub Light
- ⏱️ Автоотключение при неактивности
- 📤 Экспорт логов сессии в `.txt`
- 🖥️ Многовкладочный интерфейс (●/◌/○ статусы + переподключение)
- 🔍 Поиск по терминалу (`Ctrl+F`)
- ⌨️ Горячие клавиши: `Ctrl+T` — новая сессия, `Ctrl+W` — закрыть вкладку

## 📦 Установка (Windows)

1. Скачайте `NeuraTTY_Installer_v1.7.exe` из [Releases](https://github.com/mrSaT13/NeuraTTY/releases)
2. Запустите и следуйте инструкциям
3. Запуск: меню «Пуск» → **NeuraTTY**

Данные хранятся в `%AppData%\NeuraTTY\` (`sessions.json`, `settings.json`, `known_hosts`).

> Пароли в `sessions.json` шифруются (`enc:...`). Без библиотеки `cryptography` — остаются открытым текстом. Ключ Fernet — в системном keyring, fallback — `.fernet_key` (0600).

## 🛠 Запуск из исходников

Требуется Python 3.10+ (зависимости зафиксированы в `requirements.txt`):

```bash
pip install -r requirements.txt
python NeuraTTY.py
```

## 📦 Сборка

```bash
pyinstaller --onefile --windowed --name NeuraTTY --icon resources/icon.ico --add-data "resources;resources" --version-file version.txt NeuraTTY.py
```

Инсталлятор (Inno Setup):

```bash
iscc setup.iss
```

## 🗺 Roadmap / TODO

- [x] Шифрование паролей (keyring / Fernet)
- [x] SFTP-браузер
- [x] Переподключение + индикатор статуса в табах
- [x] Трей с иконкой и меню
- [x] Немодальная блокировка (окно сворачивается)
- [x] Поддержка Ctrl+C/V, Esc, F-клавиш
- [x] Настройка шрифта терминала
- [x] known_hosts с подтверждением отпечатка
- [ ] Полноценный Split View

## 👤 Автор

[mrSaT13](https://github.com/mrSaT13)

## 📄 Лицензия

MIT — см. файл `LICENSE`.
