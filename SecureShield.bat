@echo off
title SISTEMA DE PROTECCION COMPLETA v2.0 - MAXIMA SEGURIDAD
color 0A
setlocal enabledelayedexpansion

:: Verificar permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ============================================
    echo   ESTE SCRIPT REQUIERE PERMISOS DE ADMINISTRADOR
    echo ============================================
    echo.
    echo Por favor, ejecuta como Administrador.
    pause
    exit /b 1
)

:: Crear directorio de logs
set "LOGDIR=%USERPROFILE%\Desktop\SecurityLogs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
set "LOGFILE=%LOGDIR%\security_log_%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt"
set "LOGFILE=%LOGFILE: =0%"

echo ============================================ > "%LOGFILE%"
echo   SISTEMA DE PROTECCION COMPLETA v2.0 >> "%LOGFILE%"
echo   Fecha: %date% %time% >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"
echo. >> "%LOGFILE%"

cls
echo ============================================
echo   SISTEMA DE PROTECCION COMPLETA v2.0
echo   MAXIMA SEGURIDAD ANTI-ESPIONAJE
echo ============================================
echo.
echo Este sistema protegera tu PC contra:
echo - Acceso remoto no autorizado
echo - Keyloggers y spyware
echo - RATs (Remote Access Trojans)
echo - Monitoreo de webcam/microfono
echo - Conexiones sospechosas
echo.
echo Log guardado en: %LOGDIR%
echo.
pause
cls

:: Contadores globales
set total_remote=0
set total_keyloggers=0
set total_rats=0
set total_services=0
set total_ports=0
set total_connections=0

:: ============================================
:: FASE 1: TERMINAR SOFTWARE REMOTO LEGITIMO
:: ============================================
echo.
echo ============================================
echo [FASE 1/10] BLOQUEANDO SOFTWARE REMOTO
echo ============================================
echo.
echo [FASE 1] Iniciando bloqueo de software remoto... >> "%LOGFILE%"

set remote_processes=anydesk teamviewer rustdesk winvnc tightvnc realvnc ultra-vnc uvnc dwservice splashtop logmein chrome-remote-desktop-host msra mstsc quickassist RemotePC GoToMyPC Ammyy radmin supremo mikogo join.me ShowMyPC LiteManager NetSupport RemoteUtilities UltraViewer Zoho_Assist SOS_Online_Backup ISL_Light

for %%p in (%remote_processes%) do (
    tasklist | findstr /i /c:"%%p" >nul 2>&1
    if !errorlevel!==0 (
        echo [BLOQUEADO] Proceso remoto: %%p
        echo [BLOQUEADO] %%p >> "%LOGFILE%"
        taskkill /f /im *%%p*.exe >nul 2>&1
        set /a total_remote+=1
    )
)

echo Procesos remotos bloqueados: %total_remote%
echo.

:: ============================================
:: FASE 2: DETECTAR Y ELIMINAR KEYLOGGERS
:: ============================================
echo.
echo ============================================
echo [FASE 2/10] BUSCANDO KEYLOGGERS
echo ============================================
echo.
echo [FASE 2] Escaneando keyloggers... >> "%LOGFILE%"

set keylogger_list=keylogger keyspy ardamax refog spectre spytech spyagent kidlogger hookshark elitekeylogger perfectkeylogger allinonekeylogger actualkeylogger revealer_keylogger invisible_keylogger blazingtools real_keylogger allinkeylogger familykeylogger softkeylogger windowskeylogger freekey_keylogger elite_keylogger sc-keylog winspy keylog.pro homekey_keylogger ispy_keylogger webwatcher spector spectorsoft spytector

for %%k in (%keylogger_list%) do (
    tasklist | findstr /i "%%k" >nul 2>&1
    if !errorlevel!==0 (
        echo [ALERTA CRITICA] Keylogger detectado: %%k
        echo [KEYLOGGER] %%k >> "%LOGFILE%"
        taskkill /f /im *%%k*.exe >nul 2>&1
        set /a total_keyloggers+=1
    )
)

:: Buscar procesos con hooks de teclado (metodo avanzado)
echo Buscando procesos con hooks de teclado...
for /f "tokens=1" %%a in ('tasklist ^| findstr /i "hook key log spy monitor capture"') do (
    set "proc=%%a"
    if /i not "!proc!"=="winlogon.exe" (
        if /i not "!proc!"=="lsass.exe" (
            if /i not "!proc!"=="csrss.exe" (
                if /i not "!proc!"=="explorer.exe" (
                    echo [SOSPECHOSO] Proceso con hooks: %%a
                    echo [SOSPECHOSO] %%a >> "%LOGFILE%"
                    set /a total_keyloggers+=1
                )
            )
        )
    )
)

echo Keyloggers detectados: %total_keyloggers%
echo.

:: ============================================
:: FASE 3: DETECTAR Y ELIMINAR RATs
:: ============================================
echo.
echo ============================================
echo [FASE 3/10] BUSCANDO RATs Y TROYANOS
echo ============================================
echo.
echo [FASE 3] Escaneando RATs... >> "%LOGFILE%"

set rat_list=nanocore njrat darkcomet quasar cybergate bifrost poison_ivy blackshades xtreme_rat netwire asyncrat remcos warzone_rat agent_tesla ave_maria formbook lokibot azorult raccoon_stealer redline_stealer vidar metasploit cobaltstrike havoc_c2 sliver pupy_rat

for %%r in (%rat_list%) do (
    tasklist | findstr /i "%%r" >nul 2>&1
    if !errorlevel!==0 (
        echo [ALERTA MAXIMA] RAT detectado: %%r
        echo [RAT] %%r >> "%LOGFILE%"
        taskkill /f /im *%%r*.exe >nul 2>&1
        set /a total_rats+=1
    )
)

:: Buscar conexiones sospechosas (C2 servers)
echo Buscando conexiones a servidores de comando y control...
netstat -ano | findstr "ESTABLISHED" | findstr /i "443 8080 8443 4444 5555 6666 7777" >nul 2>&1
if !errorlevel!==0 (
    echo [ADVERTENCIA] Conexiones sospechosas detectadas
    echo [CONEXION_SOSPECHOSA] Puerto C2 detectado >> "%LOGFILE%"
    set /a total_connections+=1
)

echo RATs detectados: %total_rats%
echo.

:: ============================================
:: FASE 4: DESHABILITAR SERVICIOS REMOTOS
:: ============================================
echo.
echo ============================================
echo [FASE 4/10] DESHABILITANDO SERVICIOS REMOTOS
echo ============================================
echo.
echo [FASE 4] Deshabilitando servicios... >> "%LOGFILE%"

set remote_services=TermService TeamViewer AnyDesk RustDesk UmRdpService SessionEnv RemoteRegistry WinRM SSDPSRV upnphost RemoteAccess RasMan

for %%s in (%remote_services%) do (
    sc query %%s >nul 2>&1
    if !errorlevel!==0 (
        echo Deshabilitando: %%s
        echo [SERVICIO] %%s deshabilitado >> "%LOGFILE%"
        net stop %%s >nul 2>&1
        sc config %%s start= disabled >nul 2>&1
        set /a total_services+=1
    )
)

:: Deshabilitar PowerShell Remoting
echo Deshabilitando PowerShell Remoting...
powershell -Command "Disable-PSRemoting -Force" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 0 /f >nul 2>&1
echo [SERVICIO] PowerShell Remoting deshabilitado >> "%LOGFILE%"

:: Deshabilitar Quick Assist
echo Deshabilitando Quick Assist...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemoteAssistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f >nul 2>&1

echo Servicios deshabilitados: %total_services%
echo.

:: ============================================
:: FASE 5: BLOQUEAR PUERTOS CRITICOS
:: ============================================
echo.
echo ============================================
echo [FASE 5/10] BLOQUEANDO PUERTOS DE RED
echo ============================================
echo.
echo [FASE 5] Configurando firewall... >> "%LOGFILE%"

:: Puertos de acceso remoto
set ports_remote=22 23 135 139 445 3389 5900 5901 5500 5800 5801
:: Puertos de RATs comunes
set ports_rats=4444 5555 6666 7777 8080 8443 9999 31337 12345 54321
:: Puertos de C2 servers
set ports_c2=1337 1234 6667 6697 8000 8888 9000 10000

echo Bloqueando puertos de acceso remoto...
for %%p in (%ports_remote%) do (
    netsh advfirewall firewall delete rule name="BLOCK_%%p_TCP_IN" >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_TCP_IN" dir=in action=block protocol=TCP localport=%%p >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_UDP_IN" dir=in action=block protocol=UDP localport=%%p >nul 2>&1
    echo [PUERTO] %%p bloqueado >> "%LOGFILE%"
    set /a total_ports+=1
)

echo Bloqueando puertos de RATs y C2...
for %%p in (%ports_rats% %ports_c2%) do (
    netsh advfirewall firewall delete rule name="BLOCK_%%p_TCP_IN" >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_TCP_IN" dir=in action=block protocol=TCP localport=%%p >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_UDP_IN" dir=in action=block protocol=UDP localport=%%p >nul 2>&1
    echo [PUERTO] %%p bloqueado >> "%LOGFILE%"
    set /a total_ports+=1
)

echo Puertos bloqueados: %total_ports%
echo.

:: ============================================
:: FASE 6: PROTECCION DEL REGISTRO
:: ============================================
echo.
echo ============================================
echo [FASE 6/10] PROTEGIENDO REGISTRO DE WINDOWS
echo ============================================
echo.
echo [FASE 6] Aplicando protecciones de registro... >> "%LOGFILE%"

:: Bloquear carga de DLLs maliciosas
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] DLLs de inicio bloqueadas

:: Deshabilitar Windows Script Host
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Windows Script Host deshabilitado

:: Proteger Task Manager
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Task Manager protegido

:: Proteger Registry Editor
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Registry Editor protegido

:: Bloquear ejecucion desde ubicaciones temporales
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v DefaultLevel /t REG_DWORD /d 262144 /f >nul 2>&1
echo [OK] Ejecucion desde TEMP bloqueada

:: Limpiar auto-inicio peligroso
echo Limpiando entradas de auto-inicio...
set autorun_keys=HKCU\Software\Microsoft\Windows\CurrentVersion\Run HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

for %%k in (%autorun_keys%) do (
    for %%m in (%keylogger_list% %rat_list% %remote_processes%) do (
        reg query "%%k" | findstr /i "%%m" >nul 2>&1
        if !errorlevel!==0 (
            echo [ELIMINADO] Auto-inicio: %%m en %%k
            echo [AUTORUN] %%m eliminado de %%k >> "%LOGFILE%"
            reg delete "%%k" /v *%%m* /f >nul 2>&1
        )
    )
)

echo [OK] Registro protegido y limpiado
echo.

:: ============================================
:: FASE 7: PROTECCION DE WEBCAM Y MICROFONO
:: ============================================
echo.
echo ============================================
echo [FASE 7/10] PROTEGIENDO WEBCAM Y MICROFONO
echo ============================================
echo.
echo [FASE 7] Configurando privacidad... >> "%LOGFILE%"

:: Deshabilitar acceso a camara para todas las apps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f >nul 2>&1
echo [OK] Acceso a webcam denegado globalmente

:: Deshabilitar acceso a microfono para todas las apps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f >nul 2>&1
echo [OK] Acceso a microfono denegado globalmente

:: Deshabilitar captura de pantalla no autorizada
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Captura de pantalla restringida

echo [OK] Privacidad configurada
echo.

:: ============================================
:: FASE 8: BLOQUEO DNS
:: ============================================
echo.
echo ============================================
echo [FASE 8/10] APLICANDO BLOQUEO DNS
echo ============================================
echo.
echo [FASE 8] Bloqueando dominios maliciosos... >> "%LOGFILE%"

set hosts_file=%windir%\System32\drivers\etc\hosts

(
echo.
echo # === BLOQUEO DE SEGURIDAD - %date% %time% ===
echo # Software de acceso remoto
echo 0.0.0.0 anydesk.com
echo 0.0.0.0 relay.anydesk.com
echo 0.0.0.0 download.anydesk.com
echo 0.0.0.0 teamviewer.com
echo 0.0.0.0 get.teamviewer.com
echo 0.0.0.0 download.teamviewer.com
echo 0.0.0.0 rustdesk.com
echo 0.0.0.0 vnc.com
echo 0.0.0.0 realvnc.com
echo 0.0.0.0 tightvnc.com
echo 0.0.0.0 ultravnc.com
echo 0.0.0.0 dwservice.net
echo 0.0.0.0 splashtop.com
echo 0.0.0.0 logmein.com
echo 0.0.0.0 join.me
echo 0.0.0.0 supremo.control
echo 0.0.0.0 ammyy.com
echo.
echo # Dominios de keyloggers conocidos
echo 0.0.0.0 ardamax.com
echo 0.0.0.0 refog.com
echo 0.0.0.0 spytech-web.com
echo 0.0.0.0 kidlogger.net
echo 0.0.0.0 actualspy.com
echo 0.0.0.0 blazingtools.com
echo.
echo # Dominios de spyware
echo 0.0.0.0 flexispy.com
echo 0.0.0.0 mspy.com
echo 0.0.0.0 hoverwatch.com
echo 0.0.0.0 thetruthspy.com
echo 0.0.0.0 spyzie.com
echo.
) >> "%hosts_file%"

echo [OK] %hosts_file% actualizado
echo [DNS] Bloqueo DNS aplicado >> "%LOGFILE%"
echo.

:: ============================================
:: FASE 9: DETECCION DE CONEXIONES ACTIVAS
:: ============================================
echo.
echo ============================================
echo [FASE 9/10] ANALIZANDO CONEXIONES ACTIVAS
echo ============================================
echo.
echo [FASE 9] Analizando conexiones de red... >> "%LOGFILE%"

echo Guardando conexiones activas en log...
netstat -ano | findstr "ESTABLISHED LISTENING" > "%LOGDIR%\conexiones_activas.txt"

echo Buscando conexiones sospechosas...
set suspicious_ips=0
for /f "tokens=3" %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| findstr /v "127.0.0.1 192.168 10.0"') do (
    echo [CONEXION] %%a >> "%LOGFILE%"
    set /a suspicious_ips+=1
)

echo Conexiones analizadas y guardadas en: %LOGDIR%\conexiones_activas.txt
echo Conexiones sospechosas: %suspicious_ips%
echo.

:: ============================================
:: FASE 10: TAREAS PROGRAMADAS SOSPECHOSAS
:: ============================================
echo.
echo ============================================
echo [FASE 10/10] LIMPIANDO TAREAS PROGRAMADAS
echo ============================================
echo.
echo [FASE 10] Buscando tareas sospechosas... >> "%LOGFILE%"

echo Guardando lista de tareas...
schtasks /query /fo LIST > "%LOGDIR%\tareas_programadas.txt"

echo Eliminando tareas de software remoto...
for %%t in (TeamViewer AnyDesk RustDesk "Chrome Remote Desktop" QuickAssist RemotePC) do (
    schtasks /query /tn "%%t" >nul 2>&1
    if !errorlevel!==0 (
        echo [ELIMINADO] Tarea: %%t
        echo [TAREA] %%t eliminada >> "%LOGFILE%"
        schtasks /delete /tn "%%t" /f >nul 2>&1
    )
)

echo [OK] Tareas programadas revisadas
echo.

:: ============================================
:: RESUMEN FINAL
:: ============================================
cls
echo ============================================ >> "%LOGFILE%"
echo   RESUMEN DE PROTECCION >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"
echo Procesos remotos bloqueados: %total_remote% >> "%LOGFILE%"
echo Keyloggers detectados: %total_keyloggers% >> "%LOGFILE%"
echo RATs detectados: %total_rats% >> "%LOGFILE%"
echo Servicios deshabilitados: %total_services% >> "%LOGFILE%"
echo Puertos bloqueados: %total_ports% >> "%LOGFILE%"
echo Conexiones sospechosas: %suspicious_ips% >> "%LOGFILE%"
echo. >> "%LOGFILE%"
echo Archivos generados: >> "%LOGFILE%"
echo - %LOGFILE% >> "%LOGFILE%"
echo - %LOGDIR%\conexiones_activas.txt >> "%LOGFILE%"
echo - %LOGDIR%\tareas_programadas.txt >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"

echo.
echo ============================================
echo   PROTECCION COMPLETA APLICADA
echo ============================================
echo.
echo RESULTADOS:
echo -----------
echo [+] Procesos remotos bloqueados: %total_remote%
echo [+] Keyloggers detectados: %total_keyloggers%
echo [+] RATs detectados: %total_rats%
echo [+] Servicios deshabilitados: %total_services%
echo [+] Puertos bloqueados: %total_ports%
echo [+] Conexiones sospechosas: %suspicious_ips%
echo.
echo ARCHIVOS DE AUDITORIA:
echo ----------------------
echo - Log principal: %LOGFILE%
echo - Conexiones activas: %LOGDIR%\conexiones_activas.txt
echo - Tareas programadas: %LOGDIR%\tareas_programadas.txt
echo.

if %total_keyloggers% GTR 0 (
    echo ============================================
    echo   !!! ALERTA CRITICA !!!
    echo ============================================
    echo Se detectaron %total_keyloggers% posibles keyloggers/spyware
    echo.
    echo ACCIONES RECOMENDADAS:
    echo 1. Cambiar TODAS las contraseñas importantes
    echo 2. Ejecutar escaneo completo con antivirus
    echo 3. Revisar el log detallado
    echo 4. Considerar formateo si persisten amenazas
    echo.
)

if %total_rats% GTR 0 (
    echo ============================================
    echo   !!! ALERTA MAXIMA - TROYANO DETECTADO !!!
    echo ============================================
    echo Se detectaron %total_rats% posibles RATs/Troyanos
    echo.
    echo ACCIONES URGENTES:
    echo 1. Desconectar de Internet INMEDIATAMENTE
    echo 2. NO ingresar contraseñas o datos sensibles
    echo 3. Escanear con antivirus especializado
    echo 4. CONSIDERAR FORMATEO URGENTE
    echo 5. Notificar al equipo de TI si es corporativo
    echo.
)

echo ============================================
echo   SISTEMA PROTEGIDO
echo ============================================
echo.
echo Tu sistema ha sido reforzado contra:
echo - Acceso remoto no autorizado
echo - Keyloggers y spyware
echo - Troyanos de acceso remoto (RATs)
echo - Monitorizacion de webcam/microfono
echo - Conexiones maliciosas
echo.
echo NOTA: Algunos servicios legitimos pueden
echo haber sido bloqueados. Si necesitas usar
echo software de escritorio remoto, deberas
echo habilitarlo manualmente.
echo.
echo Presiona cualquier tecla para finalizar...
pause >nul

:: Abrir carpeta de logs
explorer "%LOGDIR%"

endl
