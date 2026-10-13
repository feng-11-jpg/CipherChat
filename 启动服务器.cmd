@echo off
rem CipherChat server: listens on TCP 5050. Change the port number here if needed.
setlocal
cd /d "%~dp0"
java -cp "dist\cipherchat.jar" cipherchat.server.ChatServer 5050
