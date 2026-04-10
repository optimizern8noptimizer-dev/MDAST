# MASP v2.0 — Windows 11 Local Run Guide

## 1. What is included
This archive is prepared for:
- Windows 11 local run
- Python 3.12.5
- SQLite
- local file storage for uploads/reports
- basic in-process scan queue

## 2. What was improved
- configuration moved to `.env`
- secure default bind changed to `127.0.0.1`
- `waitress` added for stable local serving on Windows
- database initialization moved to centralized startup path
- logout now revokes JWT session instead of only writing an audit event
- scan start no longer accepts arbitrary server-side file path from client
- upload registry added: scan starts only from a registered uploaded APK
- runtime health endpoint improved
- log file rotation added: `data/logs/masp.log`
- default bootstrap admin creation automated in `init_db.py`
- UI upload flow updated for upload registry mode
- project cleaned for local reproducible launch

## 3. Folder layout after first start
- `data/masp.db` — SQLite database
- `data/uploads/` — uploaded APK files
- `data/reports/` — generated reports
- `data/logs/masp.log` — backend logs

## 4. Run path
### Option A — easiest path
1. Open Explorer.
2. Open the extracted project folder.
3. Double-click `start_windows.bat`.

What it does:
- creates `.venv`
- installs dependencies
- creates `.env` from `.env.example` if missing
- initializes database
- creates admin account if missing
- starts application

### Option B — manual PowerShell path
Open **PowerShell** in the project root and run exactly:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env -Force
python init_db.py
python run.py
```

## 5. First login
After `python init_db.py`, default credentials are:

- Username: `admin`
- Password: `AdminPass123!`

Change these values in `.env` before first run if needed:

```env
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_EMAIL=admin@masp.local
DEFAULT_ADMIN_PASSWORD=AdminPass123!
SECRET_KEY=change_me_to_a_random_string_minimum_32_chars_long
```

## 6. Where to open in browser
Open exactly:

```text
http://127.0.0.1:5000
```

Health endpoint:

```text
http://127.0.0.1:5000/api/health
```

## 7. DAST note
This archive is made to start reliably on Windows first.
For that reason Frida packages were moved out of mandatory installation.

If you need DAST later, install additionally inside the same venv:

```powershell
pip install frida==16.5.9 frida-tools==13.6.0
```

Then verify:

```powershell
frida --version
```

## 8. Expected result
You should get:
- working login page
- upload of `.apk`
- scan creation through upload registry
- audit log entries
- stable logout with token revocation
- health endpoint returning JSON

## 9. Common errors
### Error: `py` not found
Install Python 3.12.5 for Windows and enable **Add python.exe to PATH**.

### Error: PowerShell blocks activation
Run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then reopen PowerShell and activate venv again.

### Error: port 5000 already in use
Edit `.env`:

```env
PORT=5001
```

Then restart with:

```powershell
python run.py
```

### Error: login fails after DB already existed
Delete old local DB and initialize again:

```powershell
Remove-Item .\data\masp.db -Force
python init_db.py
```

## 10. Verification checklist
Run these checks in order:

1. Open `http://127.0.0.1:5000`
2. Login as `admin`
3. Upload an APK
4. Start SAST scan
5. Open `http://127.0.0.1:5000/api/health`
6. Logout
7. Refresh page and confirm old token no longer works
