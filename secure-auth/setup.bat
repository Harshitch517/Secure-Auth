@echo off
setlocal

echo.
echo  SecureAuth - First-Time Setup
echo  ==============================
echo.

:: ── 1. Check Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo         Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found.

:: ── 2. Create virtual environment ────────────────────────────────────────────
if exist venv\ (
    echo  [OK] venv already exists — skipping creation.
) else (
    echo  [1/3] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] venv created.
)

:: ── 3. Install dependencies ───────────────────────────────────────────────────
echo  [2/3] Installing Python packages (this may take ~30 s)...
call venv\Scripts\pip.exe install -r requirements.txt --quiet
if errorlevel 1 (
    echo  [ERROR] Package installation failed.
    pause
    exit /b 1
)
echo  [OK] Packages installed.

:: ── 4. Generate .env if missing ───────────────────────────────────────────────
echo  [3/3] Checking environment config...
if not exist .env (
    call venv\Scripts\python.exe -c ^
        "import secrets; open('.env','w').write('SECRET_KEY='+secrets.token_hex(32)+'\nADMIN_EMAIL=admin@secureauth.local\nADMIN_PASSWORD=Admin@SecureAuth123!\nDATABASE_URL=sqlite:///auth.db\nPORT=5000\n')"
    echo  [OK] .env created with a fresh secret key.
) else (
    echo  [OK] .env already exists — skipping.
)

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo  ┌─────────────────────────────────────────────┐
echo  │  Setup complete!  Run the app with:          │
echo  │                                             │
echo  │    venv\Scripts\activate                    │
echo  │    python run.py                            │
echo  │                                             │
echo  │  Then open: http://127.0.0.1:5000           │
echo  └─────────────────────────────────────────────┘
echo.
pause
