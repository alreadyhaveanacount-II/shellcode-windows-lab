@echo off
nasm -f win64 main.asm -o main.obj
clang main.obj -fno-stack-protector -o main.exe -mno-sse -mno-sse2 -mno-mmx -fno-builtin -nostdlib -Wl,-entry:_start -Wl,-subsystem:console -Wl,/ALIGN:16 -Wl,/FILEALIGN:16
main
echo %errorlevel%
REM should be zero
pause
