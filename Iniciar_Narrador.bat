@echo off
chcp 65001 >nul
title Narrador de Acessibilidade - Samurai Shodown V Special

cd /d "%~dp0"

echo ============================================================
echo   Narrador de Acessibilidade - Samurai Shodown V Special
echo ============================================================
echo.
echo Iniciando SsvsNarrator.exe...
echo.

"%~dp0SsvsNarrator.exe" %*

echo.
echo O narrador foi finalizado.
pause
