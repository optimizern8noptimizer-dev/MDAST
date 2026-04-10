<div align="center">

<img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/Frida-16.5.9-FF4500?style=for-the-badge&logo=frida&logoColor=white"/>
<img src="https://img.shields.io/badge/OWASP%20MASVS-v2.0-blue?style=for-the-badge"/>
<img src="https://img.shields.io/badge/PCI%20DSS-v4.0-00205B?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Windows%2011-ready-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>

<br/><br/>

# MASP v2.1

**Mobile Application Security Platform**

Платформа для статического (SAST) и динамического (DAST) анализа безопасности Android APK.  
22 SAST-правила · 13 DAST-проверок через Frida/ADB · Отчёты PDF/DOCX · RBAC · Audit log

`v2.1-cleartext-fix` · Python 3.12 · Flask · SQLite · Windows 11

[🚀 Быстрый старт](#-быстрый-старт) · [🔍 SAST-правила](#-sast---статический-анализ) · [⚡ DAST-проверки](#-dast---динамический-анализ) · [📊 Отчёты](#-отчёты) · [🔐 RBAC](#-rbac)

---

</div>

## Содержание

- [Что делает MASP](#-что-делает-masp)
- [Архитектура](#-архитектура)
- [Быстрый старт](#-быстрый-старт)
- [Конфигурация](#-конфигурация)
- [SAST — статический анализ](#-sast---статический-анализ)
- [DAST — динамический анализ](#-dast---динамический-анализ)
- [Отчёты](#-отчёты)
- [RBAC](#-rbac)
- [API Reference](#-api-reference)
- [Структура проекта](#-структура-проекта)
- [Changelog](#-changelog)

---

## 🎯 Что делает MASP

MASP анализирует Android APK-файлы на наличие уязвимостей безопасности — без ручного реверс-инжиниринга.

```
 Загрузить APK
      │
      ├──► SAST (apktool / jadx)
      │    Декомпиляция → поиск по 22 regex-правилам
      │    Покрытие: hardcoded secrets, слабая крипто,
      │    небезопасное хранение, сетевые уязвимости,
      │    небезопасные компоненты Android
      │
      └──► DAST (ADB + Frida 16.5.9)
           Установка на устройство → инжект скриптов →
           перехват runtime-вызовов
           Покрытие: SSL bypass, слабая крипто в памяти,
           утечки в Logcat, root detection, сетевые соединения
                    │
                    ▼
            Findings с CVSS / CWE / MASVS / PCI DSS
                    │
                    ▼
              Отчёт PDF / DOCX
```

**Каждый найденный дефект содержит:**
- CVSS 3.1 Score и Vector
- CWE ID
- OWASP Mobile Top 10 2024
- MASVS v2.0 Control ID
- PCI DSS v4.0 требование
- Конкретную рекомендацию по устранению

---

## 🏗 Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                        MASP v2.1                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Flask Web UI                        │   │
│  │  Login → Upload APK → Start Scan → View → Download   │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                          │ REST API                         │
│  ┌───────────────────────▼────────────────────────────┐     │
│  │               Scan Manager (Queue)                 │     │
│  │                                                    │     │
│  │  ┌─────────────────┐    ┌──────────────────────┐   │     │
│  │  │   SAST Engine   │    │    DAST Engine       │   │     │
│  │  │                 │    │                      │   │     │
│  │  │ apktool / jadx  │    │  ADB: install APK    │   │     │
│  │  │ 22 regex rules  │    │  Frida: inject JS    │   │     │
│  │  │ smali + xml     │    │  Collect findings    │   │     │
│  │  └────────┬────────┘    │  ADB: cleanup        │   │     │
│  │           │             └──────────┬───────────┘   │     │
│  │           └──────────────────┬─────┘               │     │
│  │                              │                     │     │
│  │                    ┌─────────▼────────┐            │     │
│  │                    │    Findings DB    │           │     │
│  │                    │ CVSS·CWE·MASVS·  │            │     │
│  │                    │ PCI DSS          │            │     │
│  │                    └─────────┬────────┘            │     │
│  └──────────────────────────────┼─────────────────────┘     │
│                                 │                           │
│  ┌──────────────────────────────▼─────────────────────┐     │
│  │           Report Generator (PDF / DOCX)            │     │
│  └────────────────────────────────────────────────────┘     │
│                                                             │
│  SQLite · JWT RBAC · Audit Log · Revoked Tokens Table       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Быстрый старт

### Вариант A — один клик (Windows)

```
1. Распакуйте архив
2. Дважды кликните start_windows.bat
```

Скрипт автоматически: создаёт `.venv` → устанавливает зависимости → копирует `.env` → инициализирует БД → создаёт admin → запускает сервер.

Откройте браузер: **http://127.0.0.1:5000**

### Вариант B — PowerShell (Python 3.12)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env -Force
python init_db.py
python run.py
```

### Первый вход

| Поле | Значение |
|---|---|
| Username | `admin` |
| Password | `AdminPass123!` |

> ⚠️ Сразу после первого входа смените пароль и `SECRET_KEY` в `.env`.

### Установка DAST (опционально)

DAST требует подключённое Android-устройство или эмулятор с включённым отладочным режимом:

```powershell
# Установить Frida в тот же venv
pip install frida==16.5.9 frida-tools==13.6.0

# Проверить
frida --version
adb devices
```

---

## ⚙️ Конфигурация

Все параметры задаются в `.env` (создаётся из `.env.example`):

```env
# Сервер
HOST=127.0.0.1
PORT=5000
DEBUG=false

# База данных
DATABASE_URL=sqlite:///./data/masp.db

# Безопасность — ОБЯЗАТЕЛЬНО СМЕНИТЬ
SECRET_KEY=change_me_to_a_random_string_minimum_32_chars_long
JWT_ALGORITHM=HS256
JWT_EXPIRY_HOURS=8

# Хранилище
MAX_CONTENT_LENGTH=209715200   # 200 MB

# DAST
FRIDA_TIMEOUT_SECONDS=300
QUEUE_POLL_SECONDS=3

# Admin по умолчанию
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_EMAIL=admin@masp.local
DEFAULT_ADMIN_PASSWORD=AdminPass123!
```

| Параметр | По умолчанию | Описание |
|---|---|---|
| `HOST` | `127.0.0.1` | Адрес прослушивания (не менять на 0.0.0.0 без firewall) |
| `SECRET_KEY` | random | JWT-секрет. Если не задан — генерируется случайно при каждом старте |
| `JWT_EXPIRY_HOURS` | `8` | Время жизни сессии |
| `FRIDA_TIMEOUT_SECONDS` | `300` | Таймаут DAST-анализа |
| `MAX_CONTENT_LENGTH` | `200 MB` | Максимальный размер загружаемого APK |

---

## 🔍 SAST — статический анализ

SAST декомпилирует APK через apktool/jadx и проверяет smali-код, XML-манифест и ресурсы по 22 правилам.

### Хардкод и секреты

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-001 | Hardcoded API Key or Secret | **CRITICAL** | 9.1 | CWE-798 | MASVS-STORAGE-2 |
| SAST-002 | Hardcoded Password | **CRITICAL** | 9.8 | CWE-259 | MASVS-STORAGE-2 |
| SAST-003 | Hardcoded Private Key or Certificate | **CRITICAL** | 9.1 | CWE-321 | MASVS-CRYPTO-2 |
| SAST-061 | Hardcoded IP Address | low | 3.7 | CWE-547 | MASVS-CODE-2 |

### Криптография

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-010 | Use of Broken Hash Algorithm (MD5/SHA-1) | **high** | 7.5 | CWE-327 | MASVS-CRYPTO-1 |
| SAST-011 | Use of Weak Cipher (DES/3DES/RC4) | **high** | 7.5 | CWE-327 | MASVS-CRYPTO-1 |
| SAST-012 | ECB Mode Encryption | **high** | 7.5 | CWE-327 | MASVS-CRYPTO-1 |
| SAST-013 | Insecure Random Number Generator | medium | 5.9 | CWE-330 | MASVS-CRYPTO-1 |

### Небезопасное хранение данных

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-020 | Sensitive Data in SharedPreferences | **high** | 7.1 | CWE-312 | MASVS-STORAGE-1 |
| SAST-021 | Sensitive Data Written to External Storage | **high** | 7.1 | CWE-312 | MASVS-STORAGE-1 |
| SAST-022 | Sensitive Data in Application Log | medium | 5.5 | CWE-532 | MASVS-STORAGE-2 |

### Сетевая безопасность

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-030 | Insecure HTTP Connection (Cleartext Traffic) | **high** | 7.5 | CWE-319 | MASVS-NETWORK-1 |
| SAST-031 | SSL/TLS Certificate Validation Disabled | **CRITICAL** | 9.1 | CWE-295 | MASVS-NETWORK-1 |
| SAST-032 | Hostname Verification Disabled | **high** | 7.4 | CWE-297 | MASVS-NETWORK-1 |

### Конфигурация Android

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-040 | Debuggable Application in Release | **high** | 7.8 | CWE-489 | MASVS-RESILIENCE-2 |
| SAST-041 | Backup Enabled — Sensitive Data Exposure Risk | medium | 5.5 | CWE-312 | MASVS-STORAGE-1 |
| SAST-042 | Exported Activity Without Permission | **high** | 7.1 | CWE-926 | MASVS-PLATFORM-1 |
| SAST-043 | Dangerous Permissions Declared | medium | 5.5 | CWE-250 | MASVS-PLATFORM-2 |

### Небезопасный код

| ID | Название | Severity | CVSS | CWE | MASVS |
|---|---|:---:|:---:|---|---|
| SAST-050 | SQL Injection Vulnerability | **CRITICAL** | 9.8 | CWE-89 | MASVS-CODE-1 |
| SAST-051 | JavaScript Enabled in WebView | **high** | 8.8 | CWE-749 | MASVS-PLATFORM-1 |
| SAST-060 | Intent with Implicit Broadcast | medium | 6.5 | CWE-927 | MASVS-PLATFORM-1 |

> **Патч v2.1:** SAST-030 (Cleartext Traffic) исправлен — больше не генерирует ложные срабатывания на `res/layout/*.xml`. Добавлен контекстно-зависимый анализ `AndroidManifest.xml` и `network_security_config`.

---

## ⚡ DAST — динамический анализ

DAST инжектирует Frida-скрипты в запущенный процесс через ADB и перехватывает runtime-вызовы.

**Требования:** ADB в PATH + подключённое Android-устройство/эмулятор + `frida-server` на устройстве.

### Процесс DAST-анализа

```
1. ADB: detect connected device
2. ADB: adb install <apk>
3. Frida: inject scripts → hook Java methods
4. Collect findings via message channel
5. ADB: adb uninstall <package>   ← автоматическая очистка
```

### DAST-проверки по категориям

**SSL/TLS (MASVS-NETWORK-1)**

| ID | Хук | Severity | CVSS | CWE |
|---|---|:---:|:---:|---|
| DAST-001 | `TrustManagerImpl.verifyChain` — обход SSL-валидации | CRITICAL | 9.1 | CWE-295 |
| DAST-001 | `OkHttp CertificatePinner.check` — наличие пиннинга | info | 0.0 | CWE-295 |
| DAST-002 | `HttpsURLConnection.setDefaultHostnameVerifier` — кастомный верификатор | high | 7.4 | CWE-297 |

**Криптография в runtime (MASVS-CRYPTO-1)**

| ID | Хук | Severity | CVSS | CWE |
|---|---|:---:|:---:|---|
| DAST-010 | `Cipher.getInstance(DES/3DES/RC4)` — слабый шифр | high | 7.5 | CWE-327 |
| DAST-011 | `Cipher.getInstance(AES/ECB)` — небезопасный режим | high | 7.5 | CWE-327 |
| DAST-012 | `MessageDigest.getInstance(MD5/SHA-1)` — сломанный хэш | high | 7.5 | CWE-327 |
| DAST-013 | `KeyGenerator` с недостаточной длиной ключа | medium | 5.9 | CWE-326 |
| DAST-014 | `java.util.Random` — не CSPRNG | medium | 5.9 | CWE-330 |

**Утечки данных (MASVS-STORAGE)**

| ID | Хук | Severity | CVSS | CWE |
|---|---|:---:|:---:|---|
| DAST-020 | `SharedPreferences.putString(password/token/secret)` | high | 7.1 | CWE-312 |
| DAST-021 | Запись в внешнее хранилище | high | 7.1 | CWE-312 |
| DAST-022 | `Log.d/e/w` с чувствительными данными | medium | 5.5 | CWE-532 |
| DAST-023 | Чувствительные данные в Clipboard | medium | 5.5 | CWE-312 |

**Сетевые соединения (MASVS-NETWORK-1)**

| ID | Хук | Severity | CVSS | CWE |
|---|---|:---:|:---:|---|
| DAST-030 | HTTP-соединение (не HTTPS) | high | 7.5 | CWE-319 |
| DAST-031 | Отправка данных карты/токена открытым текстом | CRITICAL | 9.1 | CWE-319 |

**Root Detection (MASVS-RESILIENCE)**

| ID | Хук | Severity | Описание |
|---|---|:---:|---|
| DAST-040 | Root check методы | info | Факт проверки root — позитивный признак |
| DAST-050 | `Runtime.exec` — выполнение shell-команд | high | Потенциальное выполнение произвольных команд |

---

## 📊 Отчёты

По результатам сканирования генерируются отчёты в двух форматах.

```
POST /api/reports  →  {"scan_id": 42, "format": "pdf"}
GET  /api/reports/42/download
```

### Структура отчёта

- **Титульный лист** — название APK, package name, дата, аналитик
- **Сводка** — общее количество находок по уровням severity (Critical / High / Medium / Low / Info)
- **Детальные находки** — для каждой: ID правила, описание, severity, CVSS Score+Vector, CWE, OWASP MASVS, PCI DSS, рекомендация, ссылки
- **Таблица покрытия стандартов** — OWASP Mobile Top 10 / MASVS v2.0 / PCI DSS v4.0

### Форматы

| Формат | Описание |
|---|---|
| `pdf` | Готовый отчёт для заказчика, цветовая маркировка severity |
| `docx` | Редактируемый Word-документ |

---

## 🔐 RBAC

Три роли с разграничением доступа:

| Роль | Загрузка APK | Запуск сканов | Просмотр своих результатов | Просмотр всех отчётов | Управление пользователями |
|---|:---:|:---:|:---:|:---:|:---:|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `specialist` | ✓ | ✓ | ✓ | — | — |
| `auditor` | — | — | — | ✓ | — |

**Безопасность сессий:**
- JWT с JTI (JWT ID) в каждом токене
- При logout — JTI записывается в таблицу `revoked_tokens`
- Каждый запрос проверяет токен против таблицы отозванных
- Срок жизни токена — 8 часов (настраивается)

---

## 📡 API Reference

Все защищённые endpoints требуют заголовка:

```
Authorization: Bearer <jwt_token>
```

### Auth

| Метод | Путь | Роли | Описание |
|---|---|---|---|
| `POST` | `/api/auth/login` | — | Аутентификация, получение JWT |
| `POST` | `/api/auth/logout` | all | Отзыв токена |
| `GET` | `/api/auth/me` | all | Текущий пользователь |
| `POST` | `/api/auth/users` | admin | Создание пользователя |
| `GET` | `/api/auth/users` | admin | Список пользователей |
| `PUT` | `/api/auth/users/<id>/activate` | admin | Активация/блокировка |
| `PUT` | `/api/auth/users/<id>/role` | admin | Изменение роли |

### Scans

| Метод | Путь | Роли | Описание |
|---|---|---|---|
| `POST` | `/api/scans/upload` | admin, specialist | Загрузка APK (upload registry) |
| `POST` | `/api/scans/` | admin, specialist | Запуск скана по upload_id |
| `GET` | `/api/scans/` | all | Список сканов |
| `GET` | `/api/scans/<id>` | all | Детали скана + findings |
| `GET` | `/api/scans/queue` | all | Размер очереди |

### Reports

| Метод | Путь | Роли | Описание |
|---|---|---|---|
| `POST` | `/api/reports/` | admin, specialist | Генерация отчёта (pdf/docx) |
| `GET` | `/api/reports/` | all | Список отчётов |
| `GET` | `/api/reports/<id>/download` | all | Скачать отчёт |

### Audit

| Метод | Путь | Роли | Описание |
|---|---|---|---|
| `GET` | `/api/audit/` | admin | Журнал всех действий |
| `GET` | `/api/audit/stats` | admin | Статистика дашборда |
| `GET` | `/api/health` | — | Health check |

### Пример — полный цикл

```bash
# 1. Логин
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminPass123!"}' | python -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Загрузить APK
UPLOAD_ID=$(curl -s -X POST http://127.0.0.1:5000/api/scans/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/app.apk" | python -c "import sys,json; print(json.load(sys.stdin)['upload_id'])")

# 3. Запустить SAST
SCAN_ID=$(curl -s -X POST http://127.0.0.1:5000/api/scans/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"upload_id\": $UPLOAD_ID, \"scan_type\": \"sast\"}" | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 4. Статус скана
curl http://127.0.0.1:5000/api/scans/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN"

# 5. Сгенерировать PDF-отчёт
REPORT_ID=$(curl -s -X POST http://127.0.0.1:5000/api/reports/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"scan_id\": $SCAN_ID, \"format\": \"pdf\"}" | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 6. Скачать отчёт
curl http://127.0.0.1:5000/api/reports/$REPORT_ID/download \
  -H "Authorization: Bearer $TOKEN" \
  -o report.pdf
```

---

## 📁 Структура проекта

```
masp/
│
├── app/
│   ├── __init__.py             # Flask factory, blueprint registration
│   ├── config.py               # Config class, .env loading, directory setup
│   ├── database.py             # SQLAlchemy engine + SessionLocal (lazy init)
│   │
│   ├── models/
│   │   ├── user.py             # User, UserRole (admin/specialist/auditor)
│   │   ├── scan.py             # Scan, ScanType (sast/dast/both), ScanStatus
│   │   ├── finding.py          # Finding: rule_id, severity, CVSS, CWE, MASVS
│   │   ├── report.py           # Report: format (pdf/docx), file_path, size
│   │   ├── uploaded_apk.py     # UploadedApk: upload registry, SHA-256
│   │   ├── revoked_token.py    # RevokedToken: JTI blacklist for logout
│   │   └── audit_log.py        # AuditLog: user, action, IP, user-agent
│   │
│   ├── sast/
│   │   ├── rules.py            # 22 SastRule objects: patterns, CVSS, CWE, MASVS
│   │   └── engine.py           # SAST Engine: APK unpack → regex scan → findings
│   │
│   ├── dast/
│   │   ├── frida_scripts.py    # 13 Frida JS scripts (SSL, crypto, storage, network)
│   │   └── engine.py           # DAST Engine: ADB install → Frida inject → collect
│   │
│   ├── services/
│   │   ├── scan_manager.py     # In-process queue: submit, poll, execute
│   │   ├── report_generator.py # PDF (ReportLab) + DOCX (python-docx) generation
│   │   └── auth_service.py     # JWT encode/decode, password hashing
│   │
│   ├── routes/
│   │   ├── auth.py             # /api/auth/* — login, logout, user management
│   │   ├── scans.py            # /api/scans/* — upload, start, status, findings
│   │   ├── reports.py          # /api/reports/* — generate, list, download
│   │   └── audit.py            # /api/audit/* — log, stats
│   │
│   ├── middleware/
│   │   └── auth.py             # @login_required, @roles_required decorators
│   │
│   └── static/
│       └── index.html          # Single-page Web UI
│
├── data/                       # Создаётся автоматически при первом запуске
│   ├── masp.db                 # SQLite база данных
│   ├── uploads/                # Загруженные APK (имя = sha256[:16]_original.apk)
│   ├── reports/                # Сгенерированные отчёты
│   └── logs/
│       └── masp.log            # Backend логи с ротацией
│
├── init_db.py                  # Инициализация БД + создание admin
├── run.py                      # Точка входа (Waitress WSGI)
├── start_windows.bat           # Автоустановка и запуск для Windows
├── requirements.txt
└── .env.example
```

---

## 🔧 Стек технологий

| Компонент | Технология |
|---|---|
| **Backend** | Python 3.12, Flask 3.0 |
| **WSGI** | Waitress (Windows-совместимый, без компилируемых зависимостей) |
| **ORM** | SQLAlchemy (sync) |
| **База данных** | SQLite |
| **SAST** | apktool, jadx, regex (22 правила) |
| **DAST** | Frida 16.5.9, frida-tools, ADB |
| **Отчёты** | ReportLab (PDF), python-docx (DOCX) |
| **Auth** | PyJWT (HS256, JTI blacklist) |
| **Frontend** | Vanilla JS SPA |

---

## 📋 Changelog

### v2.1 — cleartext-fix
- **SAST-030 fix:** устранены ложные срабатывания на `res/layout/*.xml` для правила Cleartext Traffic
- Добавлен контекстно-зависимый анализ `AndroidManifest.xml` и `network_security_config`
- Улучшена дедупликация находок с идентичными evidence

### v2.0 — security hardening
- JWT logout теперь отзывает сессию через JTI-блэклист в БД
- Удалена возможность передавать произвольный путь к APK с клиента — только через upload registry
- Локальный bind изменён с `0.0.0.0` на `127.0.0.1`
- `SECRET_KEY` генерируется случайно если не задан (вместо статической константы)
- Добавлена таблица `uploaded_apks` (upload registry) и `revoked_tokens`
- Централизована инициализация БД и конфигурации
- Добавлена ротация логов в `data/logs/masp.log`
- Frida вынесена в опциональные зависимости для надёжного первого запуска
- Добавлен `start_windows.bat` для Windows 11

---

## ⚠️ Известные ограничения

- **Очередь сканов** — in-process, без персистентности. При перезапуске незавершённые задания теряются.
- **DAST** — требует физическое устройство или эмулятор с запущенным `frida-server`. На Windows — установить Android Platform Tools.
- **SAST** — требует `apktool` и `jadx` в PATH для полной декомпиляции.

---

<div align="center">

**MASP v2.1** · Flask · SQLAlchemy · Frida 16.5.9 · OWASP MASVS v2.0 · PCI DSS v4.0

*Статический и динамический анализ безопасности Android APK*

</div>
