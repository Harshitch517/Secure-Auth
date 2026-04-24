@echo off
echo Compiling Secure-Auth C Version...

set LIBS=c_src/lib/mongoose.c c_src/lib/sqlite3.c c_src/lib/bcrypt.c c_src/lib/crypt_blowfish/crypt_blowfish.c c_src/lib/crypt_blowfish/crypt_gensalt.c
set SRC=c_src/main.c c_src/database.c c_src/utils.c c_src/render.c

clang -o secure_auth_c.exe %SRC% %LIBS% -lws2_32 -lbcrypt
if %errorlevel% equ 0 (
    echo [OK] Compiled with Clang.
    exit /b 0
)

gcc -o secure_auth_c.exe %SRC% %LIBS% -lws2_32 -lbcrypt
if %errorlevel% equ 0 (
    echo [OK] Compiled with GCC.
    exit /b 0
)

cl /Fe:secure_auth_c.exe %SRC% %LIBS% ws2_32.lib bcrypt.lib /I c_src/lib
if %errorlevel% equ 0 (
    echo [OK] Compiled with MSVC.
    exit /b 0
)

echo [ERROR] No compiler found (gcc or cl). 
echo Please install MinGW (GCC) or Build Tools for Visual Studio.
pause
