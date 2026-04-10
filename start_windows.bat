@echo off
setlocal
cd /d %~dp0
if not exist .venv (
  py -3.12 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist .env (
  copy /Y .env.example .env >nul
)
python init_db.py
python run.py
