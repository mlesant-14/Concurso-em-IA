@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Estuda AI - servidor
echo Iniciando o Estuda AI...
echo (Deixe esta janela aberta enquanto usar o sistema. Feche-a para desligar.)
echo.
rem abre o navegador depois de 2 segundos
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3000"
node server.js
echo.
echo O servidor parou. Se apareceu erro acima, verifique se o Node.js esta instalado.
pause
