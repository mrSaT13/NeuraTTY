import os
import sys
import json
import base64
import socket
import stat as statmod
import threading
import time
import hashlib
from pathlib import Path
from functools import partial

from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QEvent
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QTextCursor, QKeySequence, QPainter
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QTabWidget, QScrollArea, QFileDialog, QMessageBox,
    QStatusBar, QToolBar, QPlainTextEdit, QSpinBox, QDialog, QFormLayout,
    QMenu, QShortcut, QCompleter, QAction, QSystemTrayIcon,
    QTreeWidget, QTreeWidgetItem, QAbstractItemView, QHeaderView, QStyle
)

import paramiko
import pyte
from pyte.screens import Char

# -----------------------------
# Paths
# -----------------------------
APP_NAME = "NeuraTTY"


def get_app_data_dir():
    """Папка для хранения данных приложения (AppData\\Roaming\\NeuraTTY на Windows)."""
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Roaming" / "NeuraTTY"
    else:
        # Для Linux/macOS (на случай кроссплатформенности)
        return Path.home() / ".config" / "NeuraTTY"


APP_DATA_DIR = get_app_data_dir()
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

SESSIONS_FILE = APP_DATA_DIR / "sessions.json"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"
KNOWN_HOSTS_FILE = APP_DATA_DIR / "known_hosts"
FERNET_KEY_FILE = APP_DATA_DIR / ".fernet_key"

# -----------------------------
# Secrets: Fernet + keyring (с fallback на локальный ключ 0600)
# -----------------------------
_FERNET = None
_FERNET_TRIED = False


def _read_key_file():
    try:
        if FERNET_KEY_FILE.exists():
            return FERNET_KEY_FILE.read_bytes().strip()
    except Exception:
        pass
    return None


def _write_key_file(key_bytes: bytes):
    try:
        FERNET_KEY_FILE.write_bytes(key_bytes)
        try:
            os.chmod(FERNET_KEY_FILE, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False


def get_fernet():
    """Возвращает Fernet или None (если нет библиотеки cryptography)."""
    global _FERNET, _FERNET_TRIED
    if _FERNET_TRIED:
        return _FERNET
    _FERNET_TRIED = True
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    key_b64 = None
    # 1) пробуем системный keyring
    try:
        import keyring
        key_b64 = keyring.get_password(APP_NAME, "fernet-key")
        if not key_b64:
            key_b64 = Fernet.generate_key().decode()
            keyring.set_password(APP_NAME, "fernet-key", key_b64)
    except Exception:
        key_b64 = None
    # 2) fallback — локальный файл
    if not key_b64:
        raw = _read_key_file()
        if raw:
            key_b64 = raw.decode()
        else:
            key_b64 = Fernet.generate_key().decode()
            _write_key_file(key_b64.encode())
    try:
        _FERNET = Fernet(key_b64.encode())
    except Exception:
        _FERNET = None
    return _FERNET


def crypto_status():
    f = get_fernet()
    if f is None:
        return "plain (установите cryptography)"
    try:
        import keyring  # noqa
        return "fernet+keyring"
    except Exception:
        return "fernet+local-key"


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    f = get_fernet()
    if f is None:
        return plain  # legacy, честно без шифрования
    try:
        return "enc:" + f.encrypt(plain.encode()).decode()
    except Exception:
        return plain


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith("enc:"):
        return value  # legacy plain
    f = get_fernet()
    if f is None:
        return ""
    try:
        return f.decrypt(value[4:].encode()).decode()
    except Exception:
        return ""


# -----------------------------
# known_hosts helpers (OpenSSH-стиль)
# -----------------------------
def host_id_for(host: str, port: int) -> str:
    try:
        port = int(port)
    except Exception:
        port = 22
    host = (host or "").strip()
    if port == 22:
        return host
    return f"[{host}]:{port}"


def fingerprint_sha256(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return "SHA256:" + b64


def fingerprint_md5(key) -> str:
    digest = hashlib.md5(key.asbytes()).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def load_host_keys():
    """Загружает known_hosts (пустой, если файла нет)."""
    hk = paramiko.HostKeys()
    try:
        if KNOWN_HOSTS_FILE.exists():
            hk.load(str(KNOWN_HOSTS_FILE))
    except Exception:
        pass
    return hk


def save_host_keys(hk):
    try:
        KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        hk.save(str(KNOWN_HOSTS_FILE))
        return True
    except Exception:
        return False


def build_connect_kwargs(host, port, username, password, key_path, use_key=False):
    """kwargs для SSHClient.connect: только то, что настроил юзер.

    allow_agent=False / look_for_keys=False обязательны: иначе paramiko
    сначала перебирает ключи агента и ~/.ssh/id_* и только потом пробует
    пароль (а при MaxAuthTries / шифрованном локальном ключе пароль может
    вообще не дойти до сервера).

    Ключ используется ТОЛЬКО при включённом тумблере use_key, иначе —
    всегда чистый логин/пароль.
    """
    kwargs = dict(hostname=host, port=port, username=username, timeout=10,
                  allow_agent=False, look_for_keys=False)
    if use_key and key_path and os.path.isfile(key_path):
        # пароль в поле = passphrase от ключа, если задан
        if password:
            kwargs["passphrase"] = password
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    return kwargs

# Иконка — берётся из папки установки (или рядом с .exe)
if getattr(sys, 'frozen', False):
    # Запуск из .exe (PyInstaller)
    SCRIPT_DIR = Path(sys.executable).parent
else:
    # Запуск из .py
    SCRIPT_DIR = Path(__file__).parent

ICON_PATH = SCRIPT_DIR / "resources" / "icon.ico"
# -----------------------------
# Modern Palette
# -----------------------------
MODERN_STYLE = """
/* Современный стиль */
QWidget {
    font-family: "Segoe UI", "Cantarell", "Ubuntu", sans-serif;
    font-size: 10pt;
}
QPushButton {
    background-color: #4A6FA5;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #3A5A80;
}
QPushButton:pressed {
    background-color: #2A4560;
}
QPushButton:disabled {
    background-color: #555;
    color: #aaa;
}
QLineEdit, QSpinBox {
    background: #2d2d2d;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 5px;
    color: white;
}
QLabel {
    color: #e0e0e0;
}
QMainWindow {
    background: #1a1a25;
}
QMainWindow > QWidget {
    background: #1a1a25;
}
QTabWidget::pane {
    border: none;
    background: #1e1e2e;
    border-radius: 8px;
}
QTabWidget::tab-bar {
    background: #1a1a25;
    border: none;
}
QTabWidget {
    background: #1a1a25;
    border: none;
}
QStackedWidget {
    background: #1e1e2e;
}
/* Внутренний stacked-виджет QTabWidget имеет имя qt_tabwidget_stackedwidget:
   без этого селектора пустая область вкладок красится нативным (белым). */
QWidget#qt_tabwidget_stackedwidget {
    background: #1e1e2e;
}
QTabBar {
    background: #1a1a25;
    border: none;
    qproperty-drawBase: 0;
}
QTabBar::tab {
    background: #2d2d3d;
    color: #ccc;
    padding: 8px 16px;
    margin: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected {
    background: #4A6FA5;
    color: white;
}
QTabBar::tab:hover {
    background: #3a3a4a;
}
/* Кнопки прокрутки таб-бара (иначе остаются белыми нативными) */
QTabBar::scroller {
    width: 20px;
}
QTabBar QToolButton {
    background: #2d2d3d;
    color: #ccc;
    border: none;
    border-radius: 4px;
}
QTabBar QToolButton:hover {
    background: #3a3a4a;
    color: white;
}
QTabBar::close-button {
    subcontrol-position: right;
}
QTabBar::close-button:hover {
    background: #ff4d4d;
    border-radius: 4px;
}
QStatusBar {
    background: #1a1a25;
    color: #aaa;
}
QToolBar {
    background: #1a1a25;
    spacing: 8px;
    padding: 6px;
    border: none;
}
QToolBar QToolButton {
    color: #e0e0e0;
    background: transparent;
    border: none;
    padding: 6px 10px;
    border-radius: 6px;
    font-weight: 600;
}
QToolBar QToolButton:hover {
    background: #3A5A80;
    color: white;
}
QToolBar QToolButton:pressed {
    background: #2A4560;
    color: white;
}
QToolBar QToolButton:disabled {
    color: #777;
}
QMenuBar {
    background: #1a1a25;
    color: #e0e0e0;
}
QMenuBar::item:selected {
    background: #3A5A80;
    color: white;
}
QMenu {
    background-color: #1e1e2e;
    color: #e0e0e0;
    border: 1px solid #444;
}
QMenu::item:selected {
    background-color: #4A6FA5;
    color: white;
}
QDialog {
    background-color: #1e1e2e;
}
QComboBox {
    background: #2d2d2d;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 4px;
    color: white;
}
QCheckBox {
    color: #e0e0e0;
}
QScrollBar:vertical {
    background: #2a2a3a;
    width: 12px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #4A6FA5;
    min-height: 20px;
    border-radius: 6px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

# -----------------------------
# Themes (for terminal)
# -----------------------------
THEMES = {
    "Dracula": {
        "bg": "#282a36",
        "fg": "#f8f8f2",
        "ansi": {
            0: "#21222c", 1: "#ff5555", 2: "#50fa7b", 3: "#f1fa8c",
            4: "#bd93f9", 5: "#ff79c6", 6: "#8be9fd", 7: "#f8f8f2",
            8: "#6272a4", 9: "#ff6e6e", 10: "#69ff94", 11: "#ffffa5",
            12: "#d6acff", 13: "#ff92df", 14: "#a4ffff", 15: "#ffffff",
        }
    },
    "Solarized Dark": {
        "bg": "#002b36",
        "fg": "#839496",
        "ansi": {
            0: "#073642", 1: "#dc322f", 2: "#859900", 3: "#b58900",
            4: "#268bd2", 5: "#d33682", 6: "#2aa198", 7: "#eee8d5",
            8: "#002b36", 9: "#cb4b16", 10: "#586e75", 11: "#657b83",
            12: "#839496", 13: "#6c71c4", 14: "#93a1a1", 15: "#fdf6e3",
        }
    },
    "Monokai": {
        "bg": "#272822",
        "fg": "#f8f8f2",
        "ansi": {
            0: "#272822", 1: "#f92672", 2: "#a6e22e", 3: "#e6db74",
            4: "#66d9ef", 5: "#ae81ff", 6: "#a1efe4", 7: "#f8f8f2",
            8: "#75715e", 9: "#f92672", 10: "#a6e22e", 11: "#e6db74",
            12: "#66d9ef", 13: "#ae81ff", 14: "#a1efe4", 15: "#f9f8f5",
        }
    },
    "Nord": {
        "bg": "#2E3440",
        "fg": "#D8DEE9",
        "ansi": {
            0: "#3B4252", 1: "#BF616A", 2: "#A3BE8C", 3: "#EBCB8B",
            4: "#81A1C1", 5: "#B48EAD", 6: "#88C0D0", 7: "#E5E9F0",
            8: "#4C566A", 9: "#BF616A", 10: "#A3BE8C", 11: "#EBCB8B",
            12: "#81A1C1", 13: "#B48EAD", 14: "#8FBCBB", 15: "#ECEFF4",
        }
    },
    "One Dark": {
        "bg": "#282C34",
        "fg": "#ABB2BF",
        "ansi": {
            0: "#282C34", 1: "#E06C75", 2: "#98C379", 3: "#E5C07B",
            4: "#61AFEF", 5: "#C678DD", 6: "#56B6C2", 7: "#ABB2BF",
            8: "#5C6370", 9: "#E06C75", 10: "#98C379", 11: "#E5C07B",
            12: "#61AFEF", 13: "#C678DD", 14: "#56B6C2", 15: "#FFFFFF",
        }
    },
    "Gruvbox Dark": {
        "bg": "#282828",
        "fg": "#EBDBB2",
        "ansi": {
            0: "#282828", 1: "#CC241D", 2: "#98971A", 3: "#D79921",
            4: "#458588", 5: "#B16286", 6: "#689D6A", 7: "#A89984",
            8: "#928374", 9: "#FB4934", 10: "#B8BB26", 11: "#FABD2F",
            12: "#83A598", 13: "#D3869B", 14: "#8EC07C", 15: "#EBDBB2",
        }
    },
    "Tokyo Night": {
        "bg": "#1A1B26",
        "fg": "#C0CAF5",
        "ansi": {
            0: "#15161E", 1: "#F7768E", 2: "#9ECE6A", 3: "#E0AF68",
            4: "#7AA2F7", 5: "#BB9AF7", 6: "#7DCFFF", 7: "#A9B1D6",
            8: "#414868", 9: "#F7768E", 10: "#9ECE6A", 11: "#E0AF68",
            12: "#7AA2F7", 13: "#BB9AF7", 14: "#7DCFFF", 15: "#C0CAF5",
        }
    },
    "Catppuccin Mocha": {
        "bg": "#1E1E2E",
        "fg": "#CDD6F4",
        "ansi": {
            0: "#45475A", 1: "#F38BA8", 2: "#A6E3A1", 3: "#F9E2AF",
            4: "#89B4FA", 5: "#F5C2E7", 6: "#94E2D5", 7: "#BAC2DE",
            8: "#585B70", 9: "#F38BA8", 10: "#A6E3A1", 11: "#F9E2AF",
            12: "#89B4FA", 13: "#F5C2E7", 14: "#94E2D5", 15: "#A6ADC8",
        }
    },
    "GitHub Light": {
        "bg": "#FFFFFF",
        "fg": "#24292F",
        "ansi": {
            0: "#24292F", 1: "#D73A49", 2: "#22863A", 3: "#B08800",
            4: "#0366D6", 5: "#6F42C1", 6: "#0598C3", 7: "#6A737D",
            8: "#959DA5", 9: "#CB2431", 10: "#22863A", 11: "#B08800",
            12: "#0366D6", 13: "#6F42C1", 14: "#0598C3", 15: "#24292F",
        }
    },
}

# -----------------------------
# Load Settings
# -----------------------------
DEFAULT_SETTINGS = {
    "theme": "Dracula",
    "inactivity_timeout": 0,
    "pin_enabled": False,
    "pin_hash": "",
    "font_family": "Consolas",
    "font_size": 11,
    "language": "ru",
    "show_toolbar": False,
}

def load_settings():
    data = dict(DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data.update(loaded)
        except:
            pass
    return data

def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)

# -----------------------------
# I18N: RU / EN
# -----------------------------
LANG = {
    "ru": {
        "menu_file": "Файл", "menu_view": "Вид", "menu_prefs": "Настройки",
        "menu_help": "Справка", "toolbar_title": "Главная",
        "act_new": "Новая сессия…", "act_saved": "Сохранённые сессии…",
        "act_sftp": "SFTP-браузер…", "act_close_tab": "Закрыть вкладку",
        "act_quit": "Выход", "act_reconnect": "Переподключить текущую",
        "act_toolbar": "Показывать панель инструментов",
        "act_prefs": "Параметры…", "act_lock": "Заблокировать",
        "act_about": "О программе",
        "status_ready": "Готово",
        "dlg_new_title": "Новая SSH-сессия",
        "fld_name": "Имя сессии:", "fld_host": "Хост:", "fld_port": "Порт:",
        "fld_user": "Имя пользователя:", "fld_pass": "Пароль:",
        "fld_key": "Приватный ключ:",
        "fld_use_key": "Использовать SSH-ключ",
        "pass_ph": "Пароль или passphrase от ключа",
        "pass_ph_plain": "Пароль",
        "btn_browse": "Обзор…",
        "btn_save_connect": "💾 Сохранить и подключиться",
        "btn_connect": "🔌 Подключиться",
        "btn_cancel": "❌ Отмена", "btn_save": "✅ Сохранить",
        "btn_close": "Закрыть", "btn_ok": "OK",
        "err_host_user": "Хост и имя пользователя обязательны.",
        "title_error": "Ошибка", "title_info": "Инфо",
        "title_success": "Успех", "title_warning": "Предупреждение",
        "dlg_saved_title": "Сохранённые сессии",
        "saved_title": "Сохранённые сессии:",
        "saved_filter": "🔍 Фильтр по имени/хосту…",
        "msg_deleted": "Сессия '{name}' удалена.",
        "dlg_edit_title": "Редактировать сессию: {name}",
        "err_no_log": "Сессия не активна. Невозможно экспортировать.",
        "dlg_prefs_title": "Настройки",
        "pref_theme": "Тема терминала:", "pref_font": "Шрифт терминала:",
        "pref_fontsize": "Размер шрифта:", "pref_timeout": "Таймаут неактивности:",
        "pref_timeout_suffix": " мин (0 = откл.)",
        "pref_pin": "Включить PIN-защиту", "pref_pin_btn": "Изменить PIN",
        "pref_lang": "Язык / Language:", "pref_toolbar": "Показывать панель инструментов",
        "pref_crypto": "Шифрование паролей:",
        "btn_save_plain": "Сохранить", "btn_cancel_plain": "Отмена",
        "yes": "Да", "no": "Нет",
        "lock_text": "🔒 Приложение заблокировано\nВведите PIN для разблокировки",
        "btn_unlock": "Разблокировать",
        "btn_minimize": "Свернуть",
        "err_bad_pin": "Неверный PIN!",
        "pin_title": "PIN",
        "pin_new": "Введите PIN (4+ цифр):",
        "pin_set_ok": "PIN установлен и защита включена!",
        "pin_bad": "PIN должен быть из 4+ цифр.",
        "pin_ask": "Введите PIN:",
        "lock_retry": "Приложение останется заблокированным. Попробовать снова?",
        "lock_title2": "Блокировка",
        "pin_not_set": "PIN не настроен. Зайдите в Настройки.",
        "hk_new_title": "Новый host key",
        "hk_changed_title": "Host key изменился!",
        "hk_new_text": "Неизвестный сервер:\n\n{host}:{port} [{keytype}]\n{fp256}\nMD5: {fpmd5}\n\nДоверяете этому серверу?",
        "hk_changed_text": "⚠️ КЛЮЧ СЕРВЕРА ИЗМЕНИЛСЯ (возможен MITM)!\n\n{host}:{port} [{keytype}]\nБыл: {old}\nСтал: {fp256}\nMD5: {fpmd5}\n\nПродолжить только если вы сами переустановили сервер.",
        "hk_once": "Доверять разово", "hk_save": "Доверять и сохранить",
        "hk_connect_once": "Подключить разово", "hk_update": "Обновить и сохранить",
        "msg_hk_reject": "Подключение отклонено: неизвестный host key",
        "msg_no_route": "Нет связи с {host}:{port}: {e}",
        "sftp_go": "Перейти", "sftp_up": "⬆ Вверх",
        "sftp_refresh": "🔄 Обновить", "sftp_upload": "⬆ Загрузить…",
        "sftp_download": "⬇ Скачать", "sftp_mkdir": "📁 Новая папка",
        "sftp_delete": "🗑 Удалить", "sftp_no_conn": "Нет SFTP-соединения",
        "sftp_no_session": "Нет активного SSH-соединения в текущей вкладке.",
        "sftp_pick_file": "Выберите файл в списке.",
        "sftp_dir_no_dl": "Скачивание папок не поддерживается — зайдите внутрь.",
        "sftp_name": "Имя:", "sftp_new_folder": "Новая папка",
        "sftp_del_q": "Удалить", "sftp_del_text": "Удалить {name}?",
        "sftp_save_as": "Сохранить как", "sftp_open": "Выбрать файл для загрузки",
        "sftp_ready": "Готово",
        "col_name": "Имя", "col_size": "Размер", "col_type": "Тип",
        "col_mtime": "Изменён",
        "type_dir": "папка", "type_file": "файл",
        "st_connected": "Подключено к {host}",
        "st_connecting": "Подключение к {host}...",
        "st_off": "Не подключено — нажмите «Переподключить»",
        "st_gone": "Отключено от {host}",
        "st_gone_err": "Отключено от {host}: {error}",
        "msg_conn_closed": "\n[Соединение закрыто]\n",
        "msg_conn_closed_err": "\n[Соединение закрыто: {error}]\n",
        "msg_idle": "\n[Автоотключение: нет активности {n} мин]\n",
        "msg_send_err": "Ошибка отправки",
        "search_title": "Поиск", "search_label": "Введите текст для поиска:",
        "search_notfound": "Текст не найден.",
        "msg_no_tab": "Нет активной вкладки.",
        "key_title": "Выберите приватный ключ",
        "log_title": "Сохранить лог", "msg_log_saved": "Лог сохранён!",
        "msg_log_fail": "Не удалось сохранить:\n{e}",
        "about_title": "О программе NeuraTTY",
        "ctx_copy": "Копировать", "ctx_paste": "Вставить",
        "tip_conn": "Подключено: {host}", "tip_ing": "Подключение: {host}",
        "tip_off": "Отключено: {host}", "anim_connecting": "Подключение",
        "untitled": "Безымянная сессия", "new_session": "Новая сессия",
        "old_unknown": "(неизвестен)", "app_title": "NeuraTTY — SSH-клиент",
        "btn_connect_plain": "Подключиться",
        "tray_show": "Показать", "tray_hide": "Скрыть в трей",
        "tray_quit": "Выход",
        "tray_tip": "NeuraTTY — SSH-клиент",
        "msg_tray_hide": "NeuraTTY свёрнут в трей. Правый клик по иконке — меню.",
        "msg_tray_title": "NeuraTTY",
        "tip_edit": "Редактировать", "tip_del": "Удалить",
        "tip_export": "Экспорт лога активной вкладки",
        "sftp_no_link": "Нет соединения.",
        "sftp_read_err": "Ошибка чтения: {e}",
        "sftp_n_objects": "{n} объектов — {path}",
        "sftp_uploaded": "Загружено: {path}",
        "sftp_downloaded": "Скачано: {path}",
        "sftp_fail_up": "Не удалось загрузить:\n{e}",
        "sftp_fail_down": "Не удалось скачать:\n{e}",
        "sftp_fail_mk": "Не удалось создать:\n{e}",
        "sftp_fail_del": "Не удалось удалить:\n{e}",
        "sftp_no_sftp": "SFTP недоступен: нет активного соединения",
    },
    "en": {
        "menu_file": "File", "menu_view": "View", "menu_prefs": "Settings",
        "menu_help": "Help", "toolbar_title": "Main",
        "act_new": "New session…", "act_saved": "Saved sessions…",
        "act_sftp": "SFTP browser…", "act_close_tab": "Close tab",
        "act_quit": "Quit", "act_reconnect": "Reconnect current",
        "act_toolbar": "Show toolbar",
        "act_prefs": "Preferences…", "act_lock": "Lock",
        "act_about": "About",
        "status_ready": "Ready",
        "dlg_new_title": "New SSH session",
        "fld_name": "Session name:", "fld_host": "Host:", "fld_port": "Port:",
        "fld_user": "Username:", "fld_pass": "Password:",
        "fld_key": "Private key:",
        "fld_use_key": "Use SSH key",
        "pass_ph": "Password or key passphrase",
        "pass_ph_plain": "Password",
        "btn_browse": "Browse…",
        "btn_save_connect": "💾 Save & connect",
        "btn_connect": "🔌 Connect",
        "btn_cancel": "❌ Cancel", "btn_save": "✅ Save",
        "btn_close": "Close", "btn_ok": "OK",
        "err_host_user": "Host and username are required.",
        "title_error": "Error", "title_info": "Info",
        "title_success": "Success", "title_warning": "Warning",
        "dlg_saved_title": "Saved sessions",
        "saved_title": "Saved sessions:",
        "saved_filter": "🔍 Filter by name/host…",
        "msg_deleted": "Session '{name}' deleted.",
        "dlg_edit_title": "Edit session: {name}",
        "err_no_log": "Session is not active. Cannot export.",
        "dlg_prefs_title": "Settings",
        "pref_theme": "Terminal theme:", "pref_font": "Terminal font:",
        "pref_fontsize": "Font size:", "pref_timeout": "Inactivity timeout:",
        "pref_timeout_suffix": " min (0 = off)",
        "pref_pin": "Enable PIN protection", "pref_pin_btn": "Change PIN",
        "pref_lang": "Language / Язык:", "pref_toolbar": "Show toolbar",
        "pref_crypto": "Password encryption:",
        "btn_save_plain": "Save", "btn_cancel_plain": "Cancel",
        "yes": "Yes", "no": "No",
        "lock_text": "🔒 Application locked\nEnter PIN to unlock",
        "btn_unlock": "Unlock",
        "btn_minimize": "Minimize",
        "err_bad_pin": "Wrong PIN!",
        "pin_title": "PIN",
        "pin_new": "Enter PIN (4+ digits):",
        "pin_set_ok": "PIN set and protection enabled!",
        "pin_bad": "PIN must be 4+ digits.",
        "pin_ask": "Enter PIN:",
        "lock_retry": "Application will stay locked. Try again?",
        "lock_title2": "Lock",
        "pin_not_set": "PIN is not set. Open Settings.",
        "hk_new_title": "New host key",
        "hk_changed_title": "Host key changed!",
        "hk_new_text": "Unknown server:\n\n{host}:{port} [{keytype}]\n{fp256}\nMD5: {fpmd5}\n\nDo you trust this server?",
        "hk_changed_text": "⚠️ SERVER KEY CHANGED (possible MITM)!\n\n{host}:{port} [{keytype}]\nWas: {old}\nNow: {fp256}\nMD5: {fpmd5}\n\nContinue only if you reinstalled the server yourself.",
        "hk_once": "Trust once", "hk_save": "Trust & save",
        "hk_connect_once": "Connect once", "hk_update": "Update & save",
        "msg_hk_reject": "Connection rejected: unknown host key",
        "msg_no_route": "Cannot reach {host}:{port}: {e}",
        "sftp_go": "Go", "sftp_up": "⬆ Up",
        "sftp_refresh": "🔄 Refresh", "sftp_upload": "⬆ Upload…",
        "sftp_download": "⬇ Download", "sftp_mkdir": "📁 New folder",
        "sftp_delete": "🗑 Delete", "sftp_no_conn": "No SFTP connection",
        "sftp_no_session": "No active SSH connection in the current tab.",
        "sftp_pick_file": "Select a file in the list.",
        "sftp_dir_no_dl": "Downloading folders is not supported — open it.",
        "sftp_name": "Name:", "sftp_new_folder": "New folder",
        "sftp_del_q": "Delete", "sftp_del_text": "Delete {name}?",
        "sftp_save_as": "Save as", "sftp_open": "Choose file to upload",
        "sftp_ready": "Ready",
        "col_name": "Name", "col_size": "Size", "col_type": "Type",
        "col_mtime": "Modified",
        "type_dir": "folder", "type_file": "file",
        "st_connected": "Connected to {host}",
        "st_connecting": "Connecting to {host}...",
        "st_off": "Not connected — press Reconnect",
        "st_gone": "Disconnected from {host}",
        "st_gone_err": "Disconnected from {host}: {error}",
        "msg_conn_closed": "\n[Connection closed]\n",
        "msg_conn_closed_err": "\n[Connection closed: {error}]\n",
        "msg_idle": "\n[Auto-disconnect: idle {n} min]\n",
        "msg_send_err": "Send error",
        "search_title": "Search", "search_label": "Enter text to search:",
        "search_notfound": "Text not found.",
        "msg_no_tab": "No active tab.",
        "key_title": "Choose private key",
        "log_title": "Save log", "msg_log_saved": "Log saved!",
        "msg_log_fail": "Could not save:\n{e}",
        "about_title": "About NeuraTTY",
        "ctx_copy": "Copy", "ctx_paste": "Paste",
        "tip_conn": "Connected: {host}", "tip_ing": "Connecting: {host}",
        "tip_off": "Disconnected: {host}", "anim_connecting": "Connecting",
        "untitled": "Untitled session", "new_session": "New session",
        "old_unknown": "(unknown)", "app_title": "NeuraTTY — SSH client",
        "btn_connect_plain": "Connect",
        "tray_show": "Show", "tray_hide": "Hide to tray",
        "tray_quit": "Quit",
        "tray_tip": "NeuraTTY — SSH client",
        "msg_tray_hide": "NeuraTTY minimized to tray. Right-click the icon for menu.",
        "msg_tray_title": "NeuraTTY",
        "tip_edit": "Edit", "tip_del": "Delete",
        "tip_export": "Export active tab log",
        "sftp_no_link": "No connection.",
        "sftp_read_err": "Read error: {e}",
        "sftp_n_objects": "{n} items — {path}",
        "sftp_uploaded": "Uploaded: {path}",
        "sftp_downloaded": "Downloaded: {path}",
        "sftp_fail_up": "Upload failed:\n{e}",
        "sftp_fail_down": "Download failed:\n{e}",
        "sftp_fail_mk": "Could not create:\n{e}",
        "sftp_fail_del": "Could not delete:\n{e}",
        "sftp_no_sftp": "SFTP unavailable: no active connection",
    },
}


def tr(key, lang="ru"):
    table = LANG.get(lang, LANG["ru"])
    return table.get(key, LANG["ru"].get(key, key))


def about_html(lang="ru"):
    if lang == "en":
        return (
            "<h3>NeuraTTY v1.8</h3>"
            "<p>SSH client: terminal, SFTP, known_hosts, PIN protection.</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>SSH connections (password / key / passphrase)</li>"
            "<li>Host key verification (SHA256/MD5)</li>"
            "<li>SFTP browser (upload/download/mkdir/delete)</li>"
            "<li>Password encryption (Fernet + keyring)</li>"
            "<li>Terminal themes, auto-disconnect, PIN, log export</li>"
            "</ul>"
            "<p><i>Author: mrSaT13.</i><br>"
            "© 2025. All rights reserved.</p>"
        )
    return (
        "<h3>NeuraTTY v1.8</h3>"
        "<p>SSH-клиент: терминал, SFTP, known_hosts, PIN-защита.</p>"
        "<p><b>Основные функции:</b></p>"
        "<ul>"
        "<li>Подключение по SSH (пароль / ключ / passphrase)</li>"
        "<li>Проверка host key (SHA256/MD5)</li>"
        "<li>SFTP-браузер (загрузка/скачивание/mkdir/удаление)</li>"
        "<li>Шифрование паролей (Fernet + keyring)</li>"
        "<li>Темы терминала, автоотключение, PIN, экспорт логов</li>"
        "</ul>"
        "<p><i>Автор: mrSaT13.</i><br>"
        "© 2025. Все права защищены.</p>"
    )

# -----------------------------
# Blur Overlay for Lock
# -----------------------------
class BlurOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.setWindowFlags(Qt.Widget)
        self.setGeometry(parent.rect())
        self.panel = None  # центрируемая панель (напр. ввод PIN)
        parent.installEventFilter(self)
        self.show()

    def set_panel(self, panel):
        self.panel = panel
        self.center_panel()

    def center_panel(self):
        if self.panel is not None:
            try:
                x = max(0, (self.width() - self.panel.width()) // 2)
                y = max(0, (self.height() - self.panel.height()) // 2)
                self.panel.move(x, y)
            except Exception:
                pass

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Resize:
            self.setGeometry(obj.rect())
            self.center_panel()
        return super().eventFilter(obj, event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # Полупрозрачный чёрный фон
        painter.fillRect(self.rect(), QColor(0, 0, 0, 180))
        # Опционально: размытие — но в PyQt5 без OpenGL сложно, поэтому просто затемнение

# -----------------------------
# Lock Dialog (Modern)
# -----------------------------
class LockDialog(QDialog):
    def __init__(self, correct_hash, parent=None, lang="ru"):
        super().__init__(parent)
        self.correct_hash = correct_hash
        self.lang = lang
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        # Без WindowStaysOnTopHint: диалог модальный (exec_) — поверх окна
        # программы и так держится, а поверх ВСЕХ программ висеть не должен,
        # плюс с этим флагом Windows не даёт свернуть программу.
        # Без WA_TranslucentBackground: иначе окно полупрозрачное/«светится».
        self.setAutoFillBackground(True)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e2e;
                border: 1px solid #4A6FA5;
                border-radius: 8px;
                padding: 20px;
            }
            QLabel {
                color: white;
                font-size: 14px;
                margin-bottom: 10px;
            }
            QLineEdit {
                background: #2d2d3d;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 10px;
                color: white;
                font-size: 16px;
                text-align: center;
            }
            QPushButton {
                background: #4A6FA5;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
                margin-top: 10px;
            }
            QPushButton:hover {
                background: #3A5A80;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        label = QLabel(tr("lock_text", self.lang))
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setMaxLength(8)
        self.pin_input.setAlignment(Qt.AlignCenter)
        self.pin_input.setFont(QFont("Segoe UI", 14))
        layout.addWidget(self.pin_input)

        btn_unlock = QPushButton(tr("btn_unlock", self.lang))
        btn_unlock.clicked.connect(self.check_pin)
        layout.addWidget(btn_unlock)

        self.pin_input.returnPressed.connect(self.check_pin)

        self.resize(320, 180)
        if parent:
            self.move(parent.geometry().center() - self.rect().center())

    def check_pin(self):
        pin = self.pin_input.text()
        if hashlib.sha256(pin.encode()).hexdigest() == self.correct_hash:
            self.accept()
        else:
            self.pin_input.clear()
            QMessageBox.critical(self, tr("pin_title", self.lang), tr("err_bad_pin", self.lang))


# -----------------------------
# Маленькие переводимые диалоги (вместо англоязычных OK/Cancel Qt)
# -----------------------------
def ask_text(parent, title, label, password=False, lang="ru"):
    """Свой ввод текста с переведёнными кнопками. Возвращает (text, ok)."""
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(360, 140)
    dlg.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")
    layout = QVBoxLayout(dlg)
    layout.addWidget(QLabel(label))
    edit = QLineEdit()
    if password:
        edit.setEchoMode(QLineEdit.Password)
    layout.addWidget(edit)
    btns = QHBoxLayout()
    b_ok = QPushButton(tr("btn_ok", lang))
    b_cancel = QPushButton(tr("btn_cancel_plain", lang))
    b_ok.clicked.connect(dlg.accept)
    b_cancel.clicked.connect(dlg.reject)
    edit.returnPressed.connect(dlg.accept)
    btns.addWidget(b_ok)
    btns.addWidget(b_cancel)
    layout.addLayout(btns)
    ok = dlg.exec_() == QDialog.Accepted
    return edit.text(), ok


def ask_yes_no(parent, title, text, lang="ru"):
    """Свой Да/Нет с переведёнными кнопками. Возвращает True/False."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Question)
    b_yes = box.addButton(tr("yes", lang), QMessageBox.YesRole)
    b_no = box.addButton(tr("no", lang), QMessageBox.NoRole)
    box.exec_()
    return box.clickedButton() == b_yes

# -----------------------------
# Terminal Emulator & Widgets (same as before, but cleaned)
# -----------------------------
# ... (оставим без изменений — они работают)

class TerminalEmulator:
    def __init__(self, width=80, height=24):
        self.width = width
        self.height = height
        self.screen = pyte.Screen(width, height)
        self.stream = pyte.Stream(self.screen)

    def feed(self, data):
        try:
            text = data.decode('utf-8', errors='replace')
            self.stream.feed(text)
        except Exception:
            pass

    def render(self):
        lines = []
        for y in range(self.screen.lines):
            line = []
            for x in range(self.screen.columns):
                char = self.screen.buffer[y].get(x, Char(' ', 'white', 'black'))
                line.append(char)
            lines.append(line)
        return lines

    def resize(self, width, height):
        if width <= 0 or height <= 0:
            return
        self.width = width
        self.height = height
        self.screen.resize(height, width)

    def get_text(self):
        text = ""
        for y in range(self.screen.lines):
            line = ""
            for x in range(self.screen.columns):
                char = self.screen.buffer[y].get(x, Char(' ', 'white', 'black'))
                line += char.data or ' '
            text += line.rstrip() + "\n"
        return text


def _qluminance(color):
    r, g, b = color.redF(), color.greenF(), color.blueF()

    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast_ratio(a, b):
    l1, l2 = _qluminance(a), _qluminance(b)
    hi, lo = (l1, l2) if l1 >= l2 else (l2, l1)
    return (hi + 0.05) / (lo + 0.05)


def _ensure_contrast(fg, bg, theme_fg, theme_bg):
    """Если fg сливается с bg — вернуть тот из (theme_fg, theme_bg),
    что читается лучше. Чёрный текст на чёрном фоне исчезает."""
    if _contrast_ratio(fg, bg) >= 2.2:
        return fg
    if _contrast_ratio(theme_fg, bg) >= _contrast_ratio(theme_bg, bg):
        return theme_fg
    return theme_bg

class TerminalWidget(QPlainTextEdit):
    def __init__(self, parent=None, theme="Dracula", font_family="Consolas", font_size=11, lang="ru"):
        super().__init__(parent)
        self.lang = lang
        self.setFont(QFont(font_family, font_size))
        self.setReadOnly(False)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setUndoRedoEnabled(False)
        self.apply_theme(theme, font_family, font_size)
        self.document().setMaximumBlockCount(2000)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self._updating_selection = False

    def apply_theme(self, theme_name, font_family="Consolas", font_size=11):
        theme_name = (theme_name or "Dracula").strip()
        theme = THEMES.get(theme_name, THEMES["Dracula"])
        bg = theme["bg"]
        fg = theme["fg"]
        font_family = font_family or "Consolas"
        try:
            font_size = int(font_size)
        except Exception:
            font_size = 11
        self.setFont(QFont(font_family, font_size))
        self.setStyleSheet(
            "QPlainTextEdit {"
            f"background-color: {bg}; color: {fg};"
            "border: none; padding: 5px;"
            f"font-family: '{font_family}', monospace;"
            "}"
        )
        self._theme_bg = QColor(bg)
        self._theme_fg = QColor(fg)
        self.default_format = QTextCharFormat()
        self.default_format.setForeground(self._theme_fg)
        self.default_format.setBackground(self._theme_bg)
        self.color_formats = {}
        ansi = theme["ansi"]
        for i in range(16):
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(ansi.get(i, fg)))
            fmt.setBackground(self._theme_bg)
            self.color_formats[i] = fmt

    def _format_for_char(self, char):
        fg_color = getattr(char, "fg", 7) or 7
        bg_color = getattr(char, "bg", 0) or 0
        bold = bool(getattr(char, "bold", False))
        reverse = bool(getattr(char, "reverse", False))
        try:
            fg_idx = int(fg_color) if str(fg_color).isdigit() else 7
        except Exception:
            return self.default_format
        try:
            bg_idx = int(bg_color) if str(bg_color).isdigit() else 0
        except Exception:
            bg_idx = 0
        fg_idx = max(0, min(15, fg_idx))
        bg_idx = max(0, min(15, bg_idx))
        # Кэшируем комбинации (fg, bg, bold, reverse)
        key = (fg_idx, bg_idx, bold, reverse)
        fmt = self.color_formats.get(key)
        if fmt is None:
            fmt = QTextCharFormat(self.default_format)
            base = self.color_formats.get(fg_idx)
            fg_q = base.foreground().color() if base is not None else QColor(self._theme_fg)
            bg_q = QColor(self._theme_bg)
            if reverse:
                fg_q, bg_q = bg_q, fg_q
            elif bg_idx != 0:
                bg_fmt = self.color_formats.get(bg_idx)
                if bg_fmt is not None:
                    bg_q = bg_fmt.foreground().color()
            # Невидимый текст (чёрное на чёрном и т.п.) — подбираем читаемый цвет
            fg_q = _ensure_contrast(fg_q, bg_q, QColor(self._theme_fg), QColor(self._theme_bg))
            fmt.setForeground(fg_q)
            fmt.setBackground(bg_q)
            if bold:
                fmt.setFontWeight(QFont.Bold)
            self.color_formats[key] = fmt
        return fmt

    def on_selection_changed(self):
        pass  # автокопирование убрано: ломало выделение + скролл

    def show_context_menu(self, pos):
        menu = QMenu(self)
        copy_action = menu.addAction(tr("ctx_copy", self.lang))
        paste_action = menu.addAction(tr("ctx_paste", self.lang))
        action = menu.exec_(self.mapToGlobal(pos))
        if action == copy_action:
            self.copy()
        elif action == paste_action:
            clipboard = QApplication.clipboard().text()
            if clipboard and hasattr(self.parent(), "send_key"):
                self.parent().send_key(clipboard)

    def append_text(self, text, fmt=None):
        if fmt is None:
            fmt = self.default_format
        # Не трогаем скролл пользователя: прокручиваем только если уже внизу
        sb = self.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text, fmt)
        if at_bottom:
            self.setTextCursor(cursor)
            self.ensureCursorVisible()

    def render_screen(self, rendered_lines):
        # Батчим последовательные символы с одинаковым форматом — вместо
        # insertText на каждый символ (тормоза/мерцание).
        sb = self.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        self.setUpdatesEnabled(False)
        cursor = self.textCursor()
        cursor.select(QTextCursor.Document)
        cursor.removeSelectedText()
        cursor.beginEditBlock()
        try:
            for line in rendered_lines:
                run_text = []
                run_fmt = None
                run_key = None
                for char in line:
                    fmt = self._format_for_char(char)
                    # быстрый ключ: id формата
                    key = id(fmt)
                    if run_fmt is None:
                        run_fmt = fmt
                        run_key = key
                    if key != run_key:
                        cursor.insertText("".join(run_text), run_fmt)
                        run_text = []
                        run_fmt = fmt
                        run_key = key
                    run_text.append(char.data or " ")
                if run_text:
                    cursor.insertText("".join(run_text), run_fmt)
                cursor.insertText("\n")
        finally:
            cursor.endEditBlock()
            self.setTextCursor(cursor)
            if at_bottom:
                self.ensureCursorVisible()
            self.setUpdatesEnabled(True)

    def keyPressEvent(self, event):
        if hasattr(self.parent(), 'on_key'):
            self.parent().on_key(event)
        else:
            super().keyPressEvent(event)

# -----------------------------
# SSH Tab
# -----------------------------
class SSHTab(QWidget):
    disconnected = pyqtSignal(str)
    new_data = pyqtSignal()
    data_received = pyqtSignal(bytes)
    resize_requested = pyqtSignal()
    host_key_prompt = pyqtSignal(object)
    connected_ok = pyqtSignal()

    def __init__(self, tab_widget, name, config, app, theme="Dracula"):
        super().__init__()
        self.tab_widget = tab_widget
        self.name = name
        self.config = config
        self.app = app
        self.theme = theme
        self.ssh_client = None
        self.ssh_shell = None
        self.connected = False
        self.connecting = False
        self.thread = None
        self.terminal_emu = TerminalEmulator()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        settings = getattr(app, "settings", {}) or {}
        self.terminal = TerminalWidget(
            self,
            theme=theme,
            font_family=settings.get("font_family", "Consolas"),
            font_size=int(settings.get("font_size", 11)),
            lang=settings.get("language", "ru"),
        )
        self.layout.addWidget(self.terminal)

        self.data_received.connect(self._render_received_data)
        self.disconnected.connect(self._handle_disconnect)
        self.resize_requested.connect(self.do_resize)

        self.render_pending = False
        self.render_timer = QTimer()
        self.render_timer.setSingleShot(True)
        self.render_timer.timeout.connect(self._do_render)

        self.resize_timer = QTimer()
        self.resize_timer.setSingleShot(True)
        self.resize_timer.timeout.connect(self.do_resize)
        self.installEventFilter(self)

        self.last_activity = time.monotonic()
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self._check_inactivity)
        self.restart_inactivity_timer()

    def restart_inactivity_timer(self):
        timeout_minutes = 0
        try:
            timeout_minutes = int(self.app.settings.get("inactivity_timeout", 0))
        except Exception:
            timeout_minutes = 0
        self.inactivity_timer.stop()
        if timeout_minutes > 0:
            self.inactivity_timer.start(timeout_minutes * 60 * 1000)

    def touch_activity(self):
        self.last_activity = time.monotonic()

    def t(self, key, **fmt):
        lang = "ru"
        try:
            lang = self.app.settings.get("language", "ru")
        except Exception:
            pass
        s = tr(key, lang)
        return s.format(**fmt) if fmt else s

    def eventFilter(self, obj, event):
        if obj == self and event.type() == QEvent.Resize:
            self.schedule_resize()
        return super().eventFilter(obj, event)

    def schedule_resize(self):
        self.resize_timer.start(200)

    def do_resize(self):
        if not self.connected:
            return
        try:
            font = self.terminal.font()
            fm = QtGui.QFontMetrics(font)
            char_width = fm.horizontalAdvance('W') or 1
            char_height = fm.height() or 1
            w = self.width()
            h = self.height()
            if w <= 1 or h <= 1:
                return
            cols = max(10, w // char_width)
            rows = max(5, h // char_height)
            self.terminal_emu.resize(cols, rows)
            if self.ssh_shell:
                try:
                    self.ssh_shell.resize_pty(width=cols, height=rows)
                except Exception:
                    pass
        except Exception:
            pass

    def connect(self):
        if self.connected or self.connecting:
            return
        host = self.config.get("host", "").strip()
        port = self.config.get("port", 22)
        username = self.config.get("username", "").strip()
        password = self.config.get("password", "")
        key_path = self.config.get("key_path", "").strip()
        use_key = bool(self.config.get("use_key", False))
        if not host or not username:
            QMessageBox.critical(self, self.t("title_error"), self.t("err_host_user"))
            return
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = 22
        self.connecting = True
        self.touch_activity()
        self.app.start_connecting_animation(self.name)
        if hasattr(self.app, "update_tab_status"):
            self.app.update_tab_status(self)
        self.thread = threading.Thread(
            target=self._connect_thread,
            args=(host, port, username, password, key_path, use_key),
            daemon=True
        )
        self.thread.start()

    def reconnect(self):
        self.close_connection(silent=True)
        self.connect()

    def close_connection(self, silent=False):
        self.connected = False
        self.connecting = False
        if self.ssh_shell:
            try:
                self.ssh_shell.close()
            except Exception:
                pass
            self.ssh_shell = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
        if not silent and hasattr(self.app, "update_tab_status"):
            self.app.update_tab_status(self)

    def _connect_thread(self, host, port, username, password, key_path, use_key=False):
        try:
            # 1) known_hosts: получаем ключ сервера ДО авторизации
            try:
                remote_key = self._fetch_remote_key(host, port)
            except Exception as e:
                self.connecting = False
                self.disconnected.emit(self.t("msg_no_route", host=host, port=port, e=e))
                return
            verdict, save = self._verify_host_key_blocking(host, port, remote_key)
            if verdict == "abort":
                self.connecting = False
                self.disconnected.emit(self.t("msg_hk_reject"))
                return
            # 2) само подключение — строгая политика
            self.ssh_client = paramiko.SSHClient()
            try:
                if KNOWN_HOSTS_FILE.exists():
                    self.ssh_client.get_host_keys().load(str(KNOWN_HOSTS_FILE))
            except Exception:
                pass
            self.ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            hid = host_id_for(host, port)
            if verdict in ("once", "save", "update"):
                try:
                    self.ssh_client.get_host_keys().add(hid, remote_key.get_name(), remote_key)
                except Exception:
                    pass
            connect_kwargs = build_connect_kwargs(host, port, username, password, key_path, use_key)
            self.ssh_client.connect(**connect_kwargs)
            if save:
                try:
                    hk = load_host_keys()
                    hk.add(hid, remote_key.get_name(), remote_key)
                    save_host_keys(hk)
                except Exception:
                    pass
            self.ssh_shell = self.ssh_client.invoke_shell(term='xterm-256color')
            self.connected = True
            self.connecting = False
            self.touch_activity()
            # Потокобезопасно: просим GUI-поток сделать resize
            self.resize_requested.emit()
            # Потокобезопасно: сигнал в GUI-поток (без хрупкого
            # QMetaObject.invokeMethod по имени — он падает RuntimeError,
            # если метод не pyqtSlot, и роняет КАЖДОЕ успешное подключение)
            self.connected_ok.emit()
            self._read_loop()
        except Exception as e:
            self.connecting = False
            self.disconnected.emit(str(e))
            return

    @staticmethod
    def _fetch_remote_key(host, port, timeout=10):
        """Возвращает paramiko.PKey сервера без авторизации."""
        from paramiko.transport import Transport
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        t = Transport(sock)
        try:
            t.start_client(timeout=timeout)
            return t.get_remote_server_key()
        finally:
            try:
                t.close()
            except Exception:
                pass

    def _verify_host_key_blocking(self, host, port, remote_key):
        """Проверяет known_hosts. Возвращает (verdict, save_to_disk).
        verdict: ok/once/save/update/abort. Вопросы юзеру — через GUI-поток."""
        hid = host_id_for(host, port)
        hk = load_host_keys()
        stored = hk.get(hid, {})
        keytype = remote_key.get_name()
        if stored.get(keytype) is not None and stored[keytype].asbytes() == remote_key.asbytes():
            return "ok", False
        changed = hid in hk
        old_fp = ""
        if changed:
            try:
                old_key = next(iter(stored.values()))
                old_fp = fingerprint_sha256(old_key)
            except Exception:
                old_fp = self.t("old_unknown")
        payload = {
            "kind": "changed" if changed else "new",
            "host": host,
            "port": int(port),
            "host_id": hid,
            "keytype": keytype,
            "fp256": fingerprint_sha256(remote_key),
            "fpmd5": fingerprint_md5(remote_key),
            "old_fp256": old_fp,
            "event": threading.Event(),
            "answer": "abort",
        }
        self.host_key_prompt.emit(payload)
        # ждем ответа GUI (2 мин), иначе abort
        payload["event"].wait(timeout=120)
        ans = payload.get("answer", "abort")
        if ans == "save":
            return "save", True
        if ans == "update":
            return "update", True
        if ans == "once":
            return "once", False
        return "abort", False

    def _read_loop(self):
        error = ""
        try:
            while self.connected and self.ssh_shell:
                try:
                    if self.ssh_shell.recv_ready():
                        data = self.ssh_shell.recv(32768)
                        if not data:
                            break
                        self.touch_activity()
                        self.data_received.emit(data)
                        self.new_data.emit()
                    else:
                        time.sleep(0.01)
                except Exception as e:
                    error = str(e)
                    break
        finally:
            # Один emit вместо двух
            self.disconnected.emit(error)

    def _render_received_data(self, data):
        self.terminal_emu.feed(data)
        self.touch_activity()
        if not self.render_pending:
            self.render_pending = True
            self.render_timer.start(16)

    def _do_render(self):
        rendered = self.terminal_emu.render()
        self.terminal.render_screen(rendered)
        self.render_pending = False

    def _handle_disconnect(self, error: str):
        was_connected = self.connected or self.connecting
        self.connected = False
        self.connecting = False
        if self.ssh_shell:
            try:
                self.ssh_shell.close()
            except Exception:
                pass
            self.ssh_shell = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
        if hasattr(self.app, "update_tab_status"):
            self.app.update_tab_status(self)
        if error:
            self.terminal.append_text(self.t("msg_conn_closed_err", error=error))
        elif was_connected:
            self.terminal.append_text(self.t("msg_conn_closed"))

    def _check_inactivity(self):
        try:
            timeout = int(self.app.settings.get("inactivity_timeout", 0))
        except Exception:
            timeout = 0
        if timeout <= 0 or not self.connected:
            return
        idle_sec = time.monotonic() - self.last_activity
        if idle_sec >= timeout * 60:
            self.terminal.append_text(self.t("msg_idle", n=timeout))
            self.close_connection()
            if hasattr(self.app, "update_tab_status"):
                self.app.update_tab_status(self)

    def send_key(self, char):
        if self.connected and self.ssh_shell:
            try:
                if isinstance(char, str):
                    self.ssh_shell.send(char.encode('utf-8'))
                else:
                    self.ssh_shell.send(char)
                self.touch_activity()
            except Exception:
                self.disconnected.emit(self.t("msg_send_err"))

    def on_key(self, event):
        if not self.connected:
            event.ignore()
            return
        key = event.key()
        mods = event.modifiers()
        text = event.text()
        ctrl = bool(mods & Qt.ControlModifier)
        # Ctrl-комбинации для shell: Ctrl+C/D/Z/L/A/E/K/U
        if ctrl and text:
            code = ord(text)
            # Qt дает text уже с учетом Ctrl (1..26). Отправляем как есть.
            if 1 <= code <= 26:
                self.send_key(chr(code))
                event.accept()
                return
        if key == Qt.Key_Escape:
            self.send_key("\x1b")
        elif key == Qt.Key_Up:
            self.send_key("\x1b[A")
        elif key == Qt.Key_Down:
            self.send_key("\x1b[B")
        elif key == Qt.Key_Right:
            self.send_key("\x1b[C")
        elif key == Qt.Key_Left:
            self.send_key("\x1b[D")
        elif key == Qt.Key_Home:
            self.send_key("\x1b[H")
        elif key == Qt.Key_End:
            self.send_key("\x1b[F")
        elif key == Qt.Key_PageUp:
            self.send_key("\x1b[5~")
        elif key == Qt.Key_PageDown:
            self.send_key("\x1b[6~")
        elif key == Qt.Key_Delete:
            self.send_key("\x1b[3~")
        elif key == Qt.Key_Insert:
            if mods & Qt.ShiftModifier:
                clipboard = QApplication.clipboard().text()
                if clipboard:
                    self.send_key(clipboard)
                    event.accept()
                    return
            self.send_key("\x1b[2~")
        elif key in (Qt.Key_F1, Qt.Key_F2, Qt.Key_F3, Qt.Key_F4, Qt.Key_F5,
                     Qt.Key_F6, Qt.Key_F7, Qt.Key_F8, Qt.Key_F9, Qt.Key_F10,
                     Qt.Key_F11, Qt.Key_F12):
            fmap = {
                Qt.Key_F1: "\x1bOP", Qt.Key_F2: "\x1bOQ", Qt.Key_F3: "\x1bOR",
                Qt.Key_F4: "\x1bOS", Qt.Key_F5: "\x1b[15~", Qt.Key_F6: "\x1b[17~",
                Qt.Key_F7: "\x1b[18~", Qt.Key_F8: "\x1b[19~", Qt.Key_F9: "\x1b[20~",
                Qt.Key_F10: "\x1b[21~", Qt.Key_F11: "\x1b[23~", Qt.Key_F12: "\x1b[24~",
            }
            self.send_key(fmap[key])
        elif key in (Qt.Key_Return, Qt.Key_Enter):
            self.send_key("\n")
        elif key == Qt.Key_Tab:
            self.send_key("\t")
        elif key == Qt.Key_Backspace:
            self.send_key("\x7f")
        elif text and text.isprintable():
            self.send_key(text)
        else:
            event.ignore()
            return
        event.accept()

    def close(self):
        self.close_connection(silent=True)

    def export_log(self):
        try:
            lang = self.app.settings.get("language", "ru")
        except Exception:
            lang = "ru"
        text = self.terminal_emu.get_text()
        path, _ = QFileDialog.getSaveFileName(self, tr("log_title", lang), "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, tr("title_success", lang), tr("msg_log_saved", lang))
            except Exception as e:
                QMessageBox.critical(self, tr("title_error", lang), tr("msg_log_fail", lang, e=e))

# -----------------------------
# SFTP Browser
# -----------------------------
class SFTPBrowerDialog(QDialog):
    def __init__(self, ssh_client, host_label="", parent=None):
        super().__init__(parent)
        self.ssh_client = ssh_client
        try:
            self.lang = parent.lang if parent is not None and hasattr(parent, "lang") else "ru"
        except Exception:
            self.lang = "ru"
        self.setWindowTitle(f"SFTP — {host_label}")
        self.resize(720, 480)
        self.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")
        self._sftp = None
        self._cur = "."

        layout = QVBoxLayout(self)
        nav = QHBoxLayout()
        self.path_edit = QLineEdit(".")
        self.path_edit.returnPressed.connect(self._go_path)
        btn_go = QPushButton(self._t("sftp_go"))
        btn_go.clicked.connect(self._go_path)
        btn_up = QPushButton(self._t("sftp_up"))
        btn_up.clicked.connect(self._go_up)
        btn_refresh = QPushButton(self._t("sftp_refresh"))
        btn_refresh.clicked.connect(self.refresh)
        nav.addWidget(self.path_edit)
        nav.addWidget(btn_go)
        nav.addWidget(btn_up)
        nav.addWidget(btn_refresh)
        layout.addLayout(nav)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([self._t("col_name"), self._t("col_size"),
                                   self._t("col_type"), self._t("col_mtime")])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self.tree)

        btns = QHBoxLayout()
        b_upload = QPushButton(self._t("sftp_upload"))
        b_upload.clicked.connect(self.upload)
        b_download = QPushButton(self._t("sftp_download"))
        b_download.clicked.connect(self.download)
        b_mkdir = QPushButton(self._t("sftp_mkdir"))
        b_mkdir.clicked.connect(self.mkdir)
        b_delete = QPushButton(self._t("sftp_delete"))
        b_delete.clicked.connect(self.delete_selected)
        b_close = QPushButton(self._t("btn_close"))
        b_close.clicked.connect(self.accept)
        for b in (b_upload, b_download, b_mkdir, b_delete, b_close):
            btns.addWidget(b)
        layout.addLayout(btns)

        self.status = QLabel(self._t("sftp_ready"))
        layout.addWidget(self.status)
        self.refresh()

    def _t(self, key, **fmt):
        s = tr(key, getattr(self, "lang", "ru"))
        return s.format(**fmt) if fmt else s

    def _sftp_client(self):
        try:
            transport = self.ssh_client.get_transport()
            if transport is None or not transport.is_active():
                return None
            if self._sftp is None:
                self._sftp = paramiko.SFTPClient.from_transport(transport)
            return self._sftp
        except Exception:
            return None

    def _norm(self, p):
        sftp = self._sftp_client()
        if sftp is None:
            return None, self._t("sftp_no_sftp")
        try:
            return sftp.normalize(p), ""
        except Exception:
            return p, ""

    def refresh(self, path=None):
        sftp = self._sftp_client()
        if sftp is None:
            self.status.setText(self._t("sftp_no_conn"))
            return
        target = path if path is not None else self.path_edit.text().strip() or "."
        norm, _ = self._norm(target)
        self._cur = norm
        self.path_edit.setText(norm)
        self.tree.clear()
        try:
            items = sftp.listdir_attr(norm)
        except Exception as e:
            self.status.setText(self._t("sftp_read_err", e=e))
            return
        import datetime
        for attr in sorted(items, key=lambda a: (not statmod.S_ISDIR(a.st_mode), a.filename.lower())):
            is_dir = statmod.S_ISDIR(attr.st_mode or 0)
            size = "" if is_dir else str(attr.st_size)
            typ = self._t("type_dir") if is_dir else self._t("type_file")
            try:
                mtime = datetime.datetime.fromtimestamp(attr.st_mtime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                mtime = ""
            item = QTreeWidgetItem([attr.filename, size, typ, mtime])
            item.setData(0, Qt.UserRole, is_dir)
            self.tree.addTopLevelItem(item)
        self.status.setText(self._t("sftp_n_objects", n=len(items), path=norm))

    def _go_path(self):
        self.refresh(self.path_edit.text().strip() or ".")

    def _go_up(self):
        cur = self._cur.rstrip("/")
        if cur in ("", ".", "/"):
            self.refresh("/")
            return
        parent = cur.rsplit("/", 1)[0] or "/"
        self.refresh(parent)

    def _on_double_click(self, item, _col):
        if item.data(0, Qt.UserRole):
            name = item.text(0)
            base = self._cur.rstrip("/") or "/"
            nxt = base + "/" + name if base != "/" else "/" + name
            self.refresh(nxt)

    def _selected_name(self):
        item = self.tree.currentItem()
        return item.text(0) if item else ""

    def _remote_join(self, name):
        base = self._cur.rstrip("/") or "/"
        return base + "/" + name if base != "/" else "/" + name

    def upload(self):
        sftp = self._sftp_client()
        if sftp is None:
            QMessageBox.warning(self, "SFTP", self._t("sftp_no_link"))
            return
        local, _ = QFileDialog.getOpenFileName(self, self._t("sftp_open"))
        if not local:
            return
        remote = self._remote_join(Path(local).name)
        try:
            sftp.put(local, remote)
            self.status.setText(self._t("sftp_uploaded", path=remote))
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, self._t("title_error"), self._t("sftp_fail_up", e=e))

    def download(self):
        sftp = self._sftp_client()
        if sftp is None:
            QMessageBox.warning(self, "SFTP", self._t("sftp_no_link"))
            return
        name = self._selected_name()
        if not name:
            QMessageBox.information(self, "SFTP", self._t("sftp_pick_file"))
            return
        item = self.tree.currentItem()
        if item.data(0, Qt.UserRole):
            QMessageBox.information(self, "SFTP", self._t("sftp_dir_no_dl"))
            return
        remote = self._remote_join(name)
        local, _ = QFileDialog.getSaveFileName(self, self._t("sftp_save_as"), name)
        if not local:
            return
        try:
            sftp.get(remote, local)
            self.status.setText(self._t("sftp_downloaded", path=local))
        except Exception as e:
            QMessageBox.critical(self, self._t("title_error"), self._t("sftp_fail_down", e=e))

    def mkdir(self):
        sftp = self._sftp_client()
        if sftp is None:
            return
        name, ok = ask_text(self, self._t("sftp_new_folder"), self._t("sftp_name"), lang=self.lang)
        if not ok or not name.strip():
            return
        try:
            sftp.mkdir(self._remote_join(name.strip()))
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, self._t("title_error"), self._t("sftp_fail_mk", e=e))

    def delete_selected(self):
        sftp = self._sftp_client()
        if sftp is None:
            return
        name = self._selected_name()
        if not name:
            return
        if not ask_yes_no(self, self._t("sftp_del_q"), self._t("sftp_del_text", name=name), self.lang):
            return
        remote = self._remote_join(name)
        try:
            try:
                sftp.remove(remote)
            except IOError:
                sftp.rmdir(remote)
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, self._t("title_error"), self._t("sftp_fail_del", e=e))

    def closeEvent(self, event):
        try:
            if self._sftp is not None:
                self._sftp.close()
        except Exception:
            pass
        super().closeEvent(event)


# -----------------------------
# Main App — with MODERN UI and LOCK
# -----------------------------
class PyTTYApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        # дефолты для старых settings.json
        for k, v in DEFAULT_SETTINGS.items():
            self.settings.setdefault(k, v)
        self.lang = self.settings.get("language", "ru")
        self.setWindowTitle(tr("app_title", self.lang))
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(700, 500)

        if ICON_PATH.exists():
            self.setWindowIcon(QtGui.QIcon(str(ICON_PATH)))

        self.tabs = {}
        self.sessions = self.load_sessions()
        self.anim_running = False
        self.anim_step = 0
        self.anim_chars = ["|", "/", "-", "\\"]

        self.overlay = None  # для блокировки
        self.lock_panel = None  # панель ввода PIN (немодальная — окно сворачивается)
        self._locked = False
        self._allow_quit = False
        self._tray_hint_shown = False
        self.tray = None

        self.create_actions()
        self.create_widgets()
        self.create_menus()
        self.create_toolbar()
        self.create_tray()
        self.retranslate()
        # Стартуем с пустым экраном: вкладки больше не плодятся сами
        self.apply_theme(self.settings["theme"])

        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self.new_session_dialog)
        QShortcut(QKeySequence("Ctrl+W"), self).activated.connect(self.close_current_tab)
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.search_in_current_tab)

        self.setStyleSheet(MODERN_STYLE)

    def t(self, key, **fmt):
        s = tr(key, self.lang)
        return s.format(**fmt) if fmt else s

    def _guard_locked(self):
        """True — приложение заблокировано, действие запрещено."""
        if self._locked:
            try:
                if self.lock_panel is not None:
                    pin = self.lock_panel.findChild(QLineEdit)
                    if pin is not None:
                        pin.setFocus()
            except Exception:
                pass
            return True
        return False

    def lock_app(self):
        if not self.settings.get("pin_enabled") or not self.settings.get("pin_hash"):
            QMessageBox.information(self, self.t("title_info"), self.t("pin_not_set"))
            return
        if self._locked:
            self._guard_locked()
            return

        # Немодальная блокировка: никаких exec_() — поэтому кнопка
        # «Свернуть» в заголовке окна продолжает работать.
        self._locked = True
        try:
            self.menuBar().setEnabled(False)
        except Exception:
            pass
        try:
            self.toolbar.setEnabled(False)
        except Exception:
            pass
        try:
            self.notebook.setEnabled(False)
        except Exception:
            pass
        try:
            for sc in self.findChildren(QShortcut):
                sc.setEnabled(False)
        except Exception:
            pass

        # Затемнение (настоящий blur в PyQt5 без OpenGL дорог, честно называем dim)
        self.overlay = BlurOverlay(self)

        panel = QWidget(self.overlay)
        panel.setFixedSize(340, 260)
        panel.setObjectName("LockPanel")
        panel.setStyleSheet("""
            QWidget#LockPanel {
                background-color: #1e1e2e;
                border: 1px solid #4A6FA5;
                border-radius: 8px;
            }
            QLabel {
                color: white;
                font-size: 14px;
            }
            QLabel#LockError {
                color: #ff6e6e;
                font-size: 11px;
            }
            QLineEdit {
                background: #2d2d3d;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 10px;
                color: white;
                font-size: 16px;
            }
            QPushButton {
                background: #4A6FA5;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #3A5A80;
            }
        """)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        label = QLabel(self.t("lock_text"))
        label.setAlignment(Qt.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)

        pin_input = QLineEdit()
        pin_input.setEchoMode(QLineEdit.Password)
        pin_input.setMaxLength(8)
        pin_input.setAlignment(Qt.AlignCenter)
        pin_input.setFont(QFont("Segoe UI", 14))
        layout.addWidget(pin_input)

        err = QLabel("")
        err.setObjectName("LockError")
        err.setAlignment(Qt.AlignCenter)
        layout.addWidget(err)

        btn_row = QHBoxLayout()
        btn_unlock = QPushButton(self.t("btn_unlock"))
        btn_min = QPushButton(self.t("btn_minimize"))
        btn_min.clicked.connect(self._minimize_from_lock)
        btn_row.addWidget(btn_unlock)
        btn_row.addWidget(btn_min)
        layout.addLayout(btn_row)

        btn_unlock.clicked.connect(self.unlock_app)
        pin_input.returnPressed.connect(self.unlock_app)

        self.lock_panel = panel
        self.overlay.set_panel(panel)
        panel.show()
        self.overlay.raise_()
        panel.raise_()
        pin_input.setFocus()

    def _minimize_from_lock(self):
        # Явная кнопка + штатная кнопка заголовка (модалок больше нет)
        try:
            self.showMinimized()
        except Exception:
            pass

    def unlock_app(self):
        if not self._locked:
            return
        pin_text = ""
        try:
            pin_box = self.lock_panel.findChild(QLineEdit) if self.lock_panel else None
            pin_text = pin_box.text() if pin_box is not None else ""
        except Exception:
            pin_text = ""
        if hashlib.sha256(pin_text.encode()).hexdigest() != self.settings.get("pin_hash"):
            try:
                err = self.lock_panel.findChild(QLabel, "LockError") if self.lock_panel else None
                if err is not None:
                    err.setText(self.t("err_bad_pin"))
                pin_box.clear()
                pin_box.setFocus()
            except Exception:
                pass
            return
        # PIN верный — снимаем блокировку
        self._locked = False
        try:
            if self.lock_panel is not None:
                self.lock_panel.setParent(None)
                self.lock_panel.deleteLater()
        except Exception:
            pass
        self.lock_panel = None
        try:
            if self.overlay is not None:
                try:
                    self.overlay.parent().removeEventFilter(self.overlay)
                except Exception:
                    pass
                self.overlay.setParent(None)
                self.overlay.deleteLater()
        except Exception:
            pass
        self.overlay = None
        try:
            self.menuBar().setEnabled(True)
        except Exception:
            pass
        try:
            self.toolbar.setEnabled(True)
        except Exception:
            pass
        try:
            self.notebook.setEnabled(True)
        except Exception:
            pass
        try:
            for sc in self.findChildren(QShortcut):
                sc.setEnabled(True)
        except Exception:
            pass
        try:
            self.on_tab_selected(self.notebook.currentIndex())
        except Exception:
            pass

    def close_current_tab(self):
        if self._guard_locked():
            return
        index = self.notebook.currentIndex()
        if index >= 0:
            self.close_tab(index)

    def search_in_current_tab(self):
        if self._guard_locked():
            return
        current = self.notebook.currentWidget()
        if current and hasattr(current, 'terminal'):
            text, ok = ask_text(self, self.t("search_title"), self.t("search_label"), lang=self.lang)
            if ok and text:
                if not current.terminal.find(text):
                    QMessageBox.information(self, self.t("search_title"), self.t("search_notfound"))

    def _icon(self, std):
        try:
            return self.style().standardIcon(std)
        except Exception:
            return QtGui.QIcon()

    def create_actions(self):
        """Единые действия: одни и те же QAction живут и в меню, и в тулбаре."""
        st = QStyle
        self.act_new = QAction(self._icon(st.SP_FileDialogNewFolder), "", self)
        self.act_new.setShortcut("Ctrl+T")
        self.act_new.triggered.connect(self.new_session_dialog)
        self.act_saved = QAction(self._icon(st.SP_DirOpenIcon), "", self)
        self.act_saved.triggered.connect(self.show_saved_sessions)
        self.act_sftp = QAction(self._icon(st.SP_DriveNetIcon), "", self)
        self.act_sftp.triggered.connect(self.open_sftp_browser)
        self.act_close_tab = QAction(self._icon(st.SP_DialogCloseButton), "", self)
        self.act_close_tab.setShortcut("Ctrl+W")
        self.act_close_tab.triggered.connect(self.close_current_tab)
        self.act_quit = QAction(self._icon(st.SP_DialogCancelButton), "", self)
        self.act_quit.triggered.connect(self.quit_app)
        self.act_reconnect = QAction(self._icon(st.SP_BrowserReload), "", self)
        self.act_reconnect.triggered.connect(self.reconnect_current_tab)
        self.act_toolbar = QAction("", self)
        self.act_toolbar.setCheckable(True)
        self.act_toolbar.triggered.connect(self._on_toolbar_toggled)
        self.act_prefs = QAction(self._icon(st.SP_FileDialogDetailedView), "", self)
        self.act_prefs.triggered.connect(self.open_settings)
        self.act_lock = QAction(self._icon(st.SP_VistaShield), "", self)
        self.act_lock.triggered.connect(self.lock_app)
        self.act_about = QAction(self._icon(st.SP_DialogHelpButton), "", self)
        self.act_about.triggered.connect(self.show_about)

    def create_widgets(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        self.notebook = QTabWidget()
        self.notebook.setTabsClosable(True)
        self.notebook.setDocumentMode(False)
        self.notebook.setUsesScrollButtons(True)
        self.notebook.setElideMode(Qt.ElideRight)
        try:
            # Убираем нативную базовую линию таб-бара — иначе белая полоса
            self.notebook.tabBar().setDrawBase(False)
            self.notebook.tabBar().setExpanding(False)
        except Exception:
            pass
        self.notebook.tabCloseRequested.connect(self.close_tab)
        self.notebook.currentChanged.connect(self.on_tab_selected)
        layout.addWidget(self.notebook)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("")
        self.status_bar.addWidget(self.status_label)

    def create_menus(self):
        menubar = self.menuBar()
        self.menu_file = menubar.addMenu("")
        self.menu_file.addAction(self.act_new)
        self.menu_file.addAction(self.act_saved)
        self.menu_file.addAction(self.act_sftp)
        self.menu_file.addSeparator()
        self.menu_file.addAction(self.act_close_tab)
        self.menu_file.addAction(self.act_quit)

        self.menu_view = menubar.addMenu("")
        self.menu_view.addAction(self.act_reconnect)
        self.menu_view.addAction(self.act_toolbar)

        self.menu_prefs = menubar.addMenu("")
        self.menu_prefs.addAction(self.act_prefs)
        self.menu_prefs.addAction(self.act_lock)

        self.menu_help = menubar.addMenu("")
        self.menu_help.addAction(self.act_about)

    def create_toolbar(self):
        # Опциональный тулбар (по умолчанию скрыт — всё уже есть в меню)
        self.toolbar = QToolBar(self.t("toolbar_title"))
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)
        for act in (self.act_new, self.act_saved, self.act_reconnect,
                    self.act_sftp, self.act_prefs, self.act_about, self.act_lock):
            self.toolbar.addAction(act)
        self.toolbar.setVisible(bool(self.settings.get("show_toolbar", False)))

    def _on_toolbar_toggled(self):
        self.set_toolbar_visible(self.act_toolbar.isChecked())

    def set_toolbar_visible(self, visible):
        self.settings["show_toolbar"] = bool(visible)
        save_settings(self.settings)
        self.toolbar.setVisible(bool(visible))
        self.act_toolbar.setChecked(bool(visible))

    # -----------------------------
    # System tray (иконка + меню)
    # -----------------------------
    def _tray_icon(self):
        try:
            if ICON_PATH.exists():
                return QtGui.QIcon(str(ICON_PATH))
        except Exception:
            pass
        try:
            return self.style().standardIcon(QStyle.SP_ComputerIcon)
        except Exception:
            return QtGui.QIcon()

    def create_tray(self):
        """Иконка в трее с меню. Если трей недоступен — работаем как раньше."""
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
        except Exception:
            return
        self.tray = QSystemTrayIcon(self._tray_icon(), self)
        self.tray.setToolTip(self.t("tray_tip"))
        menu = QMenu()
        # Показать/скрыть
        self.tray_act_toggle = QAction("", self)
        self.tray_act_toggle.triggered.connect(self._toggle_from_tray)
        menu.addAction(self.tray_act_toggle)
        menu.addSeparator()
        # Быстрые действия — переиспользуем общие QAction
        menu.addAction(self.act_new)
        menu.addAction(self.act_saved)
        menu.addAction(self.act_sftp)
        menu.addSeparator()
        menu.addAction(self.act_lock)
        menu.addSeparator()
        self.tray_act_quit = QAction("", self)
        self.tray_act_quit.triggered.connect(self.quit_app)
        menu.addAction(self.tray_act_quit)
        self.tray.setContextMenu(menu)
        try:
            self.tray.activated.connect(self._on_tray_activated)
        except Exception:
            pass
        self.tray.show()
        # Пока окно живо в трее — не выходим при закрытии окна
        try:
            QApplication.instance().setQuitOnLastWindowClosed(False)
        except Exception:
            pass
        self.retranslate_tray()

    def retranslate_tray(self):
        if self.tray is None:
            return
        try:
            self.tray.setToolTip(self.t("tray_tip"))
            if self.isVisible():
                self.tray_act_toggle.setText(self.t("tray_hide"))
            else:
                self.tray_act_toggle.setText(self.t("tray_show"))
            self.tray_act_quit.setText(self.t("tray_quit"))
        except Exception:
            pass

    def _toggle_from_tray(self):
        try:
            if self.isVisible():
                self.hide()
            else:
                self.showNormal()
                self.raise_()
                self.activateWindow()
            self.retranslate_tray()
        except Exception:
            pass

    def _on_tray_activated(self, reason):
        # Одинарный/двойной клик — показать/скрыть
        try:
            if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
                self._toggle_from_tray()
        except Exception:
            pass

    def quit_app(self):
        """Настоящий выход (мимо сворачивания в трей)."""
        self._allow_quit = True
        self.close()

    def retranslate(self):
        """Перевести меню/тулбар/статус на текущий язык (живём, без рестарта)."""
        self.setWindowTitle(tr("app_title", self.lang))
        self.menu_file.setTitle(self.t("menu_file"))
        self.menu_view.setTitle(self.t("menu_view"))
        self.menu_prefs.setTitle(self.t("menu_prefs"))
        self.menu_help.setTitle(self.t("menu_help"))
        self.act_new.setText(self.t("act_new"))
        self.act_saved.setText(self.t("act_saved"))
        self.act_sftp.setText(self.t("act_sftp"))
        self.act_close_tab.setText(self.t("act_close_tab"))
        self.act_quit.setText(self.t("act_quit"))
        self.act_reconnect.setText(self.t("act_reconnect"))
        self.act_toolbar.setText(self.t("act_toolbar"))
        self.act_toolbar.setChecked(bool(self.settings.get("show_toolbar", False)))
        self.act_prefs.setText(self.t("act_prefs"))
        self.act_lock.setText(self.t("act_lock"))
        self.act_about.setText(self.t("act_about"))
        self.toolbar.setWindowTitle(self.t("toolbar_title"))
        if not self.anim_running:
            self.on_tab_selected(self.notebook.currentIndex() if hasattr(self, "notebook") else -1)
        # язык контекстных меню терминалов
        for tab in self.tabs.values():
            if hasattr(tab, "terminal"):
                tab.terminal.lang = self.lang
        self.retranslate_tray()

    def apply_theme(self, theme_name):
        """Применить тему терминала ко всем открытым вкладкам.

        Нормализует имя (strip), фолбэк — Dracula. Возвращает итоговое имя.
        Новые вкладки подхватывают тему из settings при создании."""
        theme_name = (theme_name or "Dracula").strip()
        if theme_name not in THEMES:
            theme_name = "Dracula"
        try:
            font_family = self.settings.get("font_family", "Consolas") or "Consolas"
        except Exception:
            font_family = "Consolas"
        try:
            font_size = int(self.settings.get("font_size", 11))
        except Exception:
            font_size = 11
        for tab in self.tabs.values():
            try:
                if hasattr(tab, "terminal"):
                    tab.terminal.apply_theme(theme_name, font_family, font_size)
                    self._rerender_tab(tab)
            except Exception:
                pass
        return theme_name

    def animate_status(self, base_text=None):
        if not self.anim_running:
            return
        if base_text is None:
            base_text = self.t("anim_connecting")
        text = f"{base_text} {self.anim_chars[self.anim_step]}"
        self.status_label.setText(text)
        self.anim_step = (self.anim_step + 1) % len(self.anim_chars)
        QTimer.singleShot(150, lambda: self.animate_status(base_text))

    def start_connecting_animation(self, session_name):
        self.anim_running = True
        self.anim_step = 0
        self.animate_status(self.t("st_connecting", host=session_name))

    def stop_connecting_animation(self, message=None):
        self.anim_running = False
        if message is not None:
            self.status_label.setText(message)

    # 👇 Скопируйте ВСЕ остальные методы из вашего файла (new_session_dialog до closeEvent)
    # Они не изменились и работают корректно.

    def _build_session_form(self, name_default="", config=None):
        """Общий конструктор формы сессии: возвращает виджеты + eye для пароля."""
        config = config or {}
        name_input = QLineEdit(name_default)
        host_input = QLineEdit(config.get("host", ""))
        hosts = list(set(cfg.get("host") for cfg in self.sessions.values() if cfg.get("host")))
        host_input.setCompleter(QCompleter(hosts))
        port_input = QSpinBox()
        port_input.setRange(1, 65535)
        try:
            port_input.setValue(int(config.get("port", 22)))
        except Exception:
            port_input.setValue(22)
        username_input = QLineEdit(config.get("username", ""))
        password_input = QLineEdit(config.get("password", ""))
        password_input.setEchoMode(QLineEdit.Password)
        try:
            password_input.setPlaceholderText(self.t("pass_ph"))
        except Exception:
            pass
        # «глаз» показать/скрыть
        eye = QAction("👁", password_input)
        eye.setCheckable(True)
        eye.toggled.connect(
            lambda checked: password_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        password_input.addAction(eye, QLineEdit.TrailingPosition)
        # Тумблер «использовать SSH-ключ»: выкл = обычный логин/пароль
        use_key_check = QtWidgets.QCheckBox(self.t("fld_use_key"))
        use_key_check.setChecked(bool(config.get("use_key", False)))
        key_path_input = QLineEdit(config.get("key_path", ""))
        try:
            browse_btn = QPushButton(self.t("btn_browse"))
        except Exception:
            browse_btn = QPushButton("Обзор…")
        browse_btn.clicked.connect(lambda: self.browse_key(key_path_input))
        # Путь и обзор активны только при включённом тумблере
        key_path_input.setEnabled(use_key_check.isChecked())
        browse_btn.setEnabled(use_key_check.isChecked())
        use_key_check.toggled.connect(key_path_input.setEnabled)
        use_key_check.toggled.connect(browse_btn.setEnabled)
        # Подсказка поля пароля зависит от режима: passphrase vs обычный пароль
        def _refresh_pass_placeholder(checked):
            try:
                password_input.setPlaceholderText(
                    self.t("pass_ph") if checked else self.t("pass_ph_plain"))
            except Exception:
                pass
        use_key_check.toggled.connect(_refresh_pass_placeholder)
        _refresh_pass_placeholder(use_key_check.isChecked())
        return (name_input, host_input, port_input, username_input,
                password_input, key_path_input, browse_btn, use_key_check)

    def new_session_dialog(self):
        if self._guard_locked():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t("dlg_new_title"))
        dialog.resize(520, 420)
        dialog.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")

        main_layout = QVBoxLayout(dialog)
        main_layout.setContentsMargins(20, 20, 20, 20)

        form_layout = QFormLayout()
        (name_input, host_input, port_input, username_input,
         password_input, key_path_input, browse_btn,
         use_key_check) = self._build_session_form(self.t("new_session"))

        form_layout.addRow(self.t("fld_name"), name_input)
        form_layout.addRow(self.t("fld_host"), host_input)
        form_layout.addRow(self.t("fld_port"), port_input)
        form_layout.addRow(self.t("fld_user"), username_input)
        form_layout.addRow(self.t("fld_pass"), password_input)
        form_layout.addRow("", use_key_check)
        key_layout = QHBoxLayout()
        key_layout.addWidget(key_path_input)
        key_layout.addWidget(browse_btn)
        form_layout.addRow(self.t("fld_key"), key_layout)

        main_layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        save_btn = QPushButton(self.t("btn_save_connect"))
        save_btn.clicked.connect(lambda: self.save_and_connect_session(
            name_input.text(), host_input.text(), port_input.value(),
            username_input.text(), password_input.text(), key_path_input.text(),
            use_key_check.isChecked(), dialog
        ))
        connect_btn = QPushButton(self.t("btn_connect"))
        connect_btn.clicked.connect(lambda: self.connect_session(
            name_input.text(), host_input.text(), port_input.value(),
            username_input.text(), password_input.text(), key_path_input.text(),
            use_key_check.isChecked(), dialog
        ))
        cancel_btn = QPushButton(self.t("btn_cancel"))
        cancel_btn.clicked.connect(dialog.reject)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(connect_btn)
        button_layout.addWidget(cancel_btn)
        main_layout.addLayout(button_layout)

        dialog.exec_()

    def browse_key(self, entry):
        path, _ = QFileDialog.getOpenFileName(
            self, self.t("key_title"), "",
            "SSH Keys (*.pem *.key);;All Files (*)"
        )
        if path:
            entry.setText(path)

    def save_and_connect_session(self, name, host, port, username, password, key_path, use_key, dialog):
        name = name.strip() or self.t("untitled")
        host = host.strip()
        username = username.strip()
        if not host or not username:
            QMessageBox.critical(self, self.t("title_error"), self.t("err_host_user"))
            return

        config = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "key_path": key_path.strip(),
            "use_key": bool(use_key),
        }

        self.sessions[name] = config
        self.save_sessions()
        self.create_new_tab(name, config)
        dialog.accept()

    def connect_session(self, name, host, port, username, password, key_path, use_key, dialog):
        name = name.strip() or self.t("untitled")
        host = host.strip()
        username = username.strip()
        if not host or not username:
            QMessageBox.critical(self, self.t("title_error"), self.t("err_host_user"))
            return

        config = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "key_path": key_path.strip(),
            "use_key": bool(use_key),
        }

        self.create_new_tab(name, config)
        dialog.accept()

    def create_new_tab(self, name, config):
        name = str(name).strip() or self.t("untitled")
        tab_id = name
        counter = 1
        while tab_id in self.tabs:
            tab_id = f"{name}_{counter}"
            counter += 1

        ssh_tab = SSHTab(self.notebook, tab_id, config, self, theme=self.settings.get("theme", "Dracula"))
        ssh_tab.disconnected.connect(self.on_tab_disconnect)
        ssh_tab.new_data.connect(self.on_new_data)
        ssh_tab.host_key_prompt.connect(self.prompt_host_key)
        ssh_tab.connected_ok.connect(self.on_tab_connected)
        self.tabs[tab_id] = ssh_tab
        index = self.notebook.addTab(ssh_tab, f"◌ {tab_id}")
        self.notebook.setCurrentIndex(index)
        self.update_tab_status(ssh_tab)
        ssh_tab.connect()

    def prompt_host_key(self, payload: dict):
        """GUI-поток: спрашиваем доверие к host key. Отвечаем через payload."""
        try:
            kind = payload.get("kind", "new")
            host = payload.get("host", "")
            port = payload.get("port", 22)
            keytype = payload.get("keytype", "")
            fp256 = payload.get("fp256", "")
            fpmd5 = payload.get("fpmd5", "")
            if kind == "changed":
                old = payload.get("old_fp256", "")
                text = self.t("hk_changed_text", host=host, port=port,
                               keytype=keytype, old=old, fp256=fp256, fpmd5=fpmd5)
                box = QMessageBox(self)
                box.setWindowTitle(self.t("hk_changed_title"))
                box.setIcon(QMessageBox.Warning)
                box.setText(text)
                b_once = box.addButton(self.t("hk_connect_once"), QMessageBox.AcceptRole)
                b_update = box.addButton(self.t("hk_update"), QMessageBox.ActionRole)
                b_abort = box.addButton(self.t("btn_cancel_plain"), QMessageBox.RejectRole)
                box.exec_()
                clicked = box.clickedButton()
                if clicked == b_once:
                    payload["answer"] = "once"
                elif clicked == b_update:
                    payload["answer"] = "update"
                else:
                    payload["answer"] = "abort"
            else:
                text = self.t("hk_new_text", host=host, port=port,
                               keytype=keytype, fp256=fp256, fpmd5=fpmd5)
                box = QMessageBox(self)
                box.setWindowTitle(self.t("hk_new_title"))
                box.setIcon(QMessageBox.Question)
                box.setText(text)
                b_once = box.addButton(self.t("hk_once"), QMessageBox.AcceptRole)
                b_save = box.addButton(self.t("hk_save"), QMessageBox.ActionRole)
                b_abort = box.addButton(self.t("btn_cancel_plain"), QMessageBox.RejectRole)
                box.exec_()
                clicked = box.clickedButton()
                if clicked == b_once:
                    payload["answer"] = "once"
                elif clicked == b_save:
                    payload["answer"] = "save"
                else:
                    payload["answer"] = "abort"
        except Exception:
            payload["answer"] = "abort"
        finally:
            try:
                payload["event"].set()
            except Exception:
                pass

    def open_sftp_browser(self):
        if self._guard_locked():
            return
        current = self.notebook.currentWidget()
        if current is None or not getattr(current, "connected", False) or getattr(current, "ssh_client", None) is None:
            QMessageBox.information(self, "SFTP", self.t("sftp_no_session"))
            return
        host = current.config.get("host", "")
        dlg = SFTPBrowerDialog(current.ssh_client, f"{current.name} ({host})", self)
        dlg.exec_()

    def _tab_label(self, tab):
        if getattr(tab, "connecting", False):
            return f"◌ {tab.name}"
        if getattr(tab, "connected", False):
            return f"● {tab.name}"
        return f"○ {tab.name}"

    def update_tab_status(self, tab):
        idx = self.notebook.indexOf(tab)
        if idx >= 0:
            self.notebook.setTabText(idx, self._tab_label(tab))
            host = tab.config.get('host', '')
            if tab.connected:
                self.notebook.setTabToolTip(idx, self.t("tip_conn", host=host))
            elif tab.connecting:
                self.notebook.setTabToolTip(idx, self.t("tip_ing", host=host))
            else:
                self.notebook.setTabToolTip(idx, self.t("tip_off", host=host))

    def on_tab_connected(self):
        # Вызывается из SSH-потока через QueuedConnection
        self.stop_connecting_animation()
        current = self.notebook.currentWidget()
        if current and hasattr(current, "connected"):
            self.update_tab_status(current)
            if current.connected:
                self.status_label.setText(self.t("st_connected", host=current.config.get('host', '...')))

    def reconnect_current_tab(self):
        if self._guard_locked():
            return
        current = self.notebook.currentWidget()
        if current and hasattr(current, "reconnect"):
            current.reconnect()
        else:
            QMessageBox.information(self, self.t("title_info"), self.t("msg_no_tab"))

    def on_tab_selected(self, index):
        # Только статус. Автоконнект убран — он спамил подключениями.
        if index is None or index < 0:
            self.status_label.setText(self.t("status_ready"))
            return
        widget = self.notebook.widget(index)
        if hasattr(widget, 'name') and widget.name in self.tabs:
            if getattr(widget, "connecting", False):
                self.status_label.setText(self.t("st_connecting", host=widget.config.get('host', '...')))
            elif getattr(widget, "connected", False):
                self.status_label.setText(self.t("st_connected", host=widget.config.get('host', '...')))
            else:
                self.status_label.setText(self.t("st_off"))

    def on_tab_disconnect(self, error):
        # Останавливаем анимацию
        self.stop_connecting_animation()
        sender = self.sender()
        tabs = [sender] if sender in self.tabs.values() else [self.notebook.currentWidget()]
        for tab in tabs:
            if tab is not None and hasattr(tab, "name"):
                self.update_tab_status(tab)
        current = self.notebook.currentWidget()
        if current and hasattr(current, 'connected') and not current.connected and not getattr(current, "connecting", False):
            host = current.config.get('host', '...')
            if error:
                self.status_label.setText(self.t("st_gone_err", host=host, error=error))
            else:
                self.status_label.setText(self.t("st_gone", host=host))

    def on_new_data(self):
        sender = self.sender()
        if sender is not None and hasattr(sender, "name"):
            self.update_tab_status(sender)

    def close_tab(self, index):
        if self._guard_locked():
            return
        widget = self.notebook.widget(index)
        if hasattr(widget, 'name') and widget.name in self.tabs:
            widget.close()
            del self.tabs[widget.name]
        self.notebook.removeTab(index)

    def show_saved_sessions(self):
        if self._guard_locked():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t("dlg_saved_title"))
        dialog.resize(680, 520)
        dialog.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel(self.t("saved_title"))
        title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(title)

        search = QLineEdit()
        search.setPlaceholderText(self.t("saved_filter"))
        layout.addWidget(search)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(8)

        rows = []
        for name, config in list(self.sessions.items()):
            item_widget = QWidget()
            item_layout = QHBoxLayout(item_widget)
            item_layout.setContentsMargins(5, 5, 5, 5)

            label = QLabel(f"{name}\n{config.get('host', '')}:{config.get('port', 22)}")
            label.setMinimumWidth(180)
            item_layout.addWidget(label)

            connect_btn = QPushButton(self.t("btn_connect_plain"))
            connect_btn.clicked.connect(partial(self.connect_from_saved, name, config, dialog))
            item_layout.addWidget(connect_btn)

            edit_btn = QPushButton("✏️")
            edit_btn.setToolTip(self.t("tip_edit"))
            edit_btn.clicked.connect(partial(self.edit_session, name, dialog))
            item_layout.addWidget(edit_btn)

            delete_btn = QPushButton("🗑️")
            delete_btn.setToolTip(self.t("tip_del"))
            delete_btn.setStyleSheet("background-color: #ff4d4d;")
            delete_btn.clicked.connect(partial(self.delete_saved_session, name, scroll_layout, item_widget))
            item_layout.addWidget(delete_btn)

            export_btn = QPushButton("📤")
            export_btn.setToolTip(self.t("tip_export"))
            export_btn.clicked.connect(partial(self.export_log_from_saved, name))
            item_layout.addWidget(export_btn)

            scroll_layout.addWidget(item_widget)
            rows.append((str(name).lower() + " " + str(config.get("host", "")).lower(), item_widget))

        def apply_filter(text):
            q = text.strip().lower()
            for haystack, widget in rows:
                widget.setVisible(not q or q in haystack)

        search.textChanged.connect(apply_filter)

        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area)

        close_btn = QPushButton(self.t("btn_close"))
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.exec_()

    def export_log_from_saved(self, name):
        if name in self.tabs:
            self.tabs[name].export_log()
        else:
            QMessageBox.warning(self, self.t("title_error"), self.t("err_no_log"))

    def connect_from_saved(self, name, config, window):
        self.create_new_tab(name, config)
        window.accept()

    def edit_session(self, old_name, parent_window):
        if old_name not in self.sessions:
            return

        config = self.sessions[old_name]
        dialog = QDialog(parent_window)
        dialog.setWindowTitle(self.t("dlg_edit_title", name=old_name))
        dialog.resize(520, 420)
        dialog.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")

        main_layout = QVBoxLayout(dialog)
        main_layout.setContentsMargins(20, 20, 20, 20)

        form_layout = QFormLayout()
        (name_input, host_input, port_input, username_input,
         password_input, key_path_input, browse_btn,
         use_key_check) = self._build_session_form(str(old_name), config)

        form_layout.addRow(self.t("fld_name"), name_input)
        form_layout.addRow(self.t("fld_host"), host_input)
        form_layout.addRow(self.t("fld_port"), port_input)
        form_layout.addRow(self.t("fld_user"), username_input)
        form_layout.addRow(self.t("fld_pass"), password_input)
        form_layout.addRow("", use_key_check)
        key_layout = QHBoxLayout()
        key_layout.addWidget(key_path_input)
        key_layout.addWidget(browse_btn)
        form_layout.addRow(self.t("fld_key"), key_layout)

        main_layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        save_btn = QPushButton(self.t("btn_save"))
        save_btn.clicked.connect(lambda: self.save_edited_session(old_name, name_input.text(), host_input.text(), port_input.value(), username_input.text(), password_input.text(), key_path_input.text(), use_key_check.isChecked(), dialog))
        cancel_btn = QPushButton(self.t("btn_cancel"))
        cancel_btn.clicked.connect(dialog.reject)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        main_layout.addLayout(button_layout)

        dialog.exec_()

    def save_edited_session(self, old_name, new_name, host, port, username, password, key_path, use_key, dialog):
        new_name = new_name.strip() or self.t("untitled")
        host = host.strip()
        username = username.strip()
        if not host or not username:
            QMessageBox.critical(self, self.t("title_error"), self.t("err_host_user"))
            return

        config = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "key_path": key_path.strip(),
            "use_key": bool(use_key),
        }

        if old_name in self.sessions:
            del self.sessions[old_name]
        self.sessions[new_name] = config
        self.save_sessions()

        if old_name in self.tabs:
            tab = self.tabs[old_name]
            tab.name = new_name
            tab.config = config
            self.tabs[new_name] = tab
            del self.tabs[old_name]
            self.update_tab_status(tab)

        dialog.accept()

    def delete_saved_session(self, name, layout, widget):
        if name in self.sessions:
            del self.sessions[name]
            self.save_sessions()
            layout.removeWidget(widget)
            widget.setParent(None)
            widget.deleteLater()
            QMessageBox.information(self, self.t("title_success"), self.t("msg_deleted", name=name))
    def show_about(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t("about_title"))
        dialog.resize(460, 420)
        dialog.setStyleSheet(
            "QDialog { background-color: #1e1e2e; }"
            "QLabel { color: #e0e0e0; }"
            "QLabel a { color: #8be9fd; }"
            "QPushButton { background-color: #4A6FA5; color: white; border: none;"
            " padding: 8px 16px; border-radius: 6px; font-weight: 600; }"
            "QPushButton:hover { background-color: #3A5A80; }"
        )
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 20, 20, 20)
        label = QLabel(about_html(self.lang))
        label.setWordWrap(True)
        label.setTextFormat(Qt.RichText)
        layout.addWidget(label)
        btn = QPushButton(self.t("btn_close"))
        btn.clicked.connect(dialog.accept)
        layout.addWidget(btn)
        dialog.exec_()

    def open_settings(self):
        if self._guard_locked():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t("dlg_prefs_title"))
        dialog.resize(440, 420)
        dialog.setStyleSheet("background-color: #1e1e2e; color: #f8f8f2;")

        layout = QFormLayout(dialog)

        lang_combo = QtWidgets.QComboBox()
        lang_combo.addItem("Русский", "ru")
        lang_combo.addItem("English", "en")
        lang_combo.setCurrentIndex(0 if self.settings.get("language", "ru") == "ru" else 1)
        layout.addRow(self.t("pref_lang"), lang_combo)

        theme_combo = QtWidgets.QComboBox()
        theme_combo.addItems(THEMES.keys())
        theme_combo.setCurrentText(self.settings.get("theme", "Dracula"))
        layout.addRow(self.t("pref_theme"), theme_combo)

        font_combo = QtWidgets.QFontComboBox()
        font_combo.setCurrentText(self.settings.get("font_family", "Consolas"))
        layout.addRow(self.t("pref_font"), font_combo)

        font_size = QSpinBox()
        font_size.setRange(8, 24)
        try:
            font_size.setValue(int(self.settings.get("font_size", 11)))
        except Exception:
            font_size.setValue(11)
        layout.addRow(self.t("pref_fontsize"), font_size)

        timeout_spin = QSpinBox()
        timeout_spin.setRange(0, 120)
        timeout_spin.setValue(int(self.settings.get("inactivity_timeout", 0)))
        timeout_spin.setSuffix(self.t("pref_timeout_suffix"))
        layout.addRow(self.t("pref_timeout"), timeout_spin)

        toolbar_check = QtWidgets.QCheckBox(self.t("pref_toolbar"))
        toolbar_check.setChecked(bool(self.settings.get("show_toolbar", False)))
        layout.addRow("", toolbar_check)

        pin_enabled = QtWidgets.QCheckBox(self.t("pref_pin"))
        pin_enabled.setChecked(self.settings.get("pin_enabled", False))
        layout.addRow("", pin_enabled)

        pin_button = QPushButton(self.t("pref_pin_btn"))
        pin_button.clicked.connect(lambda: self.set_pin(dialog))
        layout.addRow("", pin_button)

        try:
            crypto_label = QLabel(crypto_status())
        except Exception:
            crypto_label = QLabel("plain")
        layout.addRow(self.t("pref_crypto"), crypto_label)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton(self.t("btn_save_plain"))
        save_btn.clicked.connect(lambda: self.save_settings_from_dialog(
            theme_combo.currentText(),
            timeout_spin.value(),
            pin_enabled.isChecked(),
            dialog,
            font_combo.currentText(),
            font_size.value(),
            lang_combo.currentData(),
            toolbar_check.isChecked(),
        ))
        cancel_btn = QPushButton(self.t("btn_cancel_plain"))
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow("", btn_layout)

        dialog.exec_()

    def set_pin(self, parent):
        pin, ok = ask_text(parent, self.t("pin_title"), self.t("pin_new"),
                            password=True, lang=self.lang)
        if ok and len(pin) >= 4 and pin.isdigit():
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            self.settings["pin_hash"] = pin_hash
            self.settings["pin_enabled"] = True  # ← Автоматически включаем!
            QMessageBox.information(parent, self.t("title_success"), self.t("pin_set_ok"))
        else:
            QMessageBox.warning(parent, self.t("title_error"), self.t("pin_bad"))

    def save_settings_from_dialog(self, theme, timeout, pin_enabled, dialog,
                                    font_family="Consolas", font_size=11,
                                    language="ru", show_toolbar=False):
        theme = (theme or "Dracula").strip()
        if theme not in THEMES:
            theme = "Dracula"
        self.settings["theme"] = theme
        self.settings["inactivity_timeout"] = timeout
        self.settings["pin_enabled"] = pin_enabled
        self.settings["font_family"] = font_family or "Consolas"
        try:
            self.settings["font_size"] = int(font_size)
        except Exception:
            self.settings["font_size"] = 11
        self.settings["language"] = language if language in ("ru", "en") else "ru"
        self.lang = self.settings["language"]
        save_settings(self.settings)
        # Обновить тему/шрифт во всех вкладках + перезапустить таймеры неактивности
        applied = self.apply_theme(theme)
        for tab in self.tabs.values():
            try:
                if hasattr(tab, "terminal"):
                    tab.terminal.lang = self.lang
                if hasattr(tab, "restart_inactivity_timer"):
                    tab.restart_inactivity_timer()
            except Exception:
                pass
        self.set_toolbar_visible(bool(show_toolbar))
        self.retranslate()
        # Видимое подтверждение (важно, когда вкладок нет и менять нечего)
        try:
            if self.lang == "en":
                self.status_label.setText(f"Theme applied: {applied}")
            else:
                self.status_label.setText(f"Тема применена: {applied}")
        except Exception:
            pass
        dialog.accept()

    def _rerender_tab(self, tab):
        """Перерисовать текущее содержимое таба новой темой/шрифтом."""
        try:
            rendered = tab.terminal_emu.render()
            tab.terminal.render_screen(rendered)
        except Exception:
            pass

    def load_sessions(self):
        if SESSIONS_FILE.exists():
            try:
                with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    out = {}
                    for k, v in data.items():
                        v = dict(v or {})
                        # миграция: расшифровываем пароль/passphrase, plain остается как был
                        v["password"] = decrypt_secret(str(v.get("password", "")))
                        # миграция тумблера ключа: у старых сессий с путём ключа
                        # поведение сохраняем (ключ был включён неявно)
                        if "use_key" not in v:
                            v["use_key"] = bool(str(v.get("key_path", "")).strip())
                        out[str(k)] = v
                    # если были plain-пароли — тихо пересохраняем уже шифрованными
                    try:
                        self.sessions = out
                        self.save_sessions()
                    except Exception:
                        pass
                    return out
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить сессии:\n{e}")
        return {}

    def save_sessions(self):
        try:
            to_disk = {}
            for k, v in (self.sessions or {}).items():
                vv = dict(v or {})
                vv["password"] = encrypt_secret(str(vv.get("password", "")))
                to_disk[str(k)] = vv
            with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
                json.dump(to_disk, f, indent=2, ensure_ascii=False)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить сессии:\n{e}")

    def closeEvent(self, event):
        # Крестик при живом трее — сворачиваем в трей, а не выходим
        try:
            tray_alive = self.tray is not None and self.tray.isVisible()
        except Exception:
            tray_alive = False
        if tray_alive and not self._allow_quit:
            event.ignore()
            try:
                self.hide()
                self.retranslate_tray()
                if not self._tray_hint_shown:
                    self._tray_hint_shown = True
                    try:
                        self.tray.showMessage(
                            self.t("msg_tray_title"),
                            self.t("msg_tray_hide"),
                            QSystemTrayIcon.Information,
                            4000,
                        )
                    except Exception:
                        pass
            except Exception:
                pass
            return
        # Настоящий выход: временные вкладки больше не засоряют sessions.json
        self.save_sessions()
        for tab in list(self.tabs.values()):
            try:
                tab.close()
            except Exception:
                pass
        try:
            if self.tray is not None:
                self.tray.hide()
        except Exception:
            pass
        event.accept()


# -----------------------------
# PIN on Startup
# -----------------------------
def verify_pin(settings):
    if not settings.get("pin_enabled"):
        return True
    pin_hash = settings.get("pin_hash")
    if not pin_hash:
        return True
    lang = settings.get("language", "ru")
    # LockDialog сам даёт повторные попытки при неверном PIN
    dlg = LockDialog(pin_hash, None, lang)
    return dlg.exec_() == QDialog.Accepted


# -----------------------------
# Launch
# -----------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(MODERN_STYLE)

    settings = load_settings()
    if not verify_pin(settings):
        sys.exit(0)

    window = PyTTYApp()
    window.show()
    sys.exit(app.exec_())