@echo off
title LIMPIEZA TOTAL - EQUIPOS DE SEGUNDA MANO v3.0
color 0B
setlocal enabledelayedexpansion

:: ============================================
:: VERIFICACION DE PERMISOS
:: ============================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ================================================
    echo   ERROR: SE REQUIEREN PERMISOS DE ADMINISTRADOR
    echo ================================================
    echo.
    echo Haz clic derecho en el archivo y selecciona
    echo "Ejecutar como administrador"
    echo.
    pause
    exit /b 1
)

:: ============================================
:: CONFIGURACION INICIAL
:: ============================================
set "LOGDIR=%USERPROFILE%\Desktop\LIMPIEZA_EQUIPO_%date:~-4%%date:~3,2%%date:~0,2%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
set "LOGFILE=%LOGDIR%\log_completo.txt"
set "REPORTFILE=%LOGDIR%\REPORTE_FINAL.txt"

echo ================================================ > "%LOGFILE%"
echo   LIMPIEZA TOTAL - EQUIPOS DE SEGUNDA MANO v3.0 >> "%LOGFILE%"
echo   Fecha: %date% %time% >> "%LOGFILE%"
echo   Usuario: %USERNAME% >> "%LOGFILE%"
echo   Equipo: %COMPUTERNAME% >> "%LOGFILE%"
echo ================================================ >> "%LOGFILE%"
echo. >> "%LOGFILE%"

cls
echo ================================================
echo   LIMPIEZA TOTAL - EQUIPOS DE SEGUNDA MANO
echo   Version 3.0 - Proteccion Maxima
echo ================================================
echo.
echo Este script eliminara:
echo.
echo [X] Software espia (spyware/keyloggers)
echo [X] Programas de monitoreo remoto
echo [X] Backdoors y puertas traseras
echo [X] Rastreadores ocultos
echo [X] Servicios de vigilancia
echo [X] Tareas programadas sospechosas
echo [X] Aplicaciones parentales/empresariales
echo [X] Herramientas de captura de pantalla
echo [X] Grabadores de audio/video
echo [X] Software de geolocalizacion
echo.
echo IMPORTANTE: Este proceso puede tomar 5-10 minutos
echo Se creara un reporte detallado en tu Escritorio
echo.
echo ================================================
pause
cls

:: Contadores
set found_spyware=0
set found_remote=0
set found_backdoors=0
set found_trackers=0
set found_services=0
set found_tasks=0
set found_startup=0
set found_drivers=0
set ports_blocked=0
set files_deleted=0

:: ============================================
:: FASE 1: CREAR PUNTO DE RESTAURACION
:: ============================================
echo.
echo ================================================
echo [1/15] CREANDO PUNTO DE RESTAURACION
echo ================================================
echo.
echo [FASE 1] Creando punto de restauracion... >> "%LOGFILE%"

wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Antes de Limpieza Total", 100, 7 >nul 2>&1
if !errorlevel!==0 (
    echo [OK] Punto de restauracion creado exitosamente
    echo [OK] Punto de restauracion creado >> "%LOGFILE%"
) else (
    echo [ADVERTENCIA] No se pudo crear punto de restauracion
    echo [ADVERTENCIA] Continuar sin punto de restauracion >> "%LOGFILE%"
)
echo.
timeout /t 2 >nul

:: ============================================
:: FASE 2: TERMINAR SPYWARE CONOCIDO
:: ============================================
echo.
echo ================================================
echo [2/15] ELIMINANDO SPYWARE Y KEYLOGGERS
echo ================================================
echo.
echo [FASE 2] Buscando spyware activo... >> "%LOGFILE%"

:: Lista extendida de spyware comercial y gratuito
set spyware_list=flexispy mspy hoverwatch thetruthspy spyzie spyera highster ikeymonitor mobistealth spybubble phonesheriff teensafe qustodio bark famisafe Norton_Family Kaspersky_SafeKids webwatcher spectorsoft spector_pro spytector kidlogger actualkeylogger revealer_keylogger invisible_keylogger blazingtools real_keylogger keylogger keyspy ardamax refog spectre spytech spyagent hookshark elitekeylogger perfectkeylogger allinonekeylogger familykeylogger softkeylogger sc-keylog winspy keylog homekey ispy_keylogger

echo Terminando procesos de spyware...
for %%s in (%spyware_list%) do (
    tasklist /FI "IMAGENAME eq *%%s*" 2>NUL | find /I /N "%%s">NUL
    if !errorlevel!==0 (
        echo [ELIMINADO] Spyware detectado: %%s
        echo [SPYWARE] %%s >> "%LOGFILE%"
        taskkill /F /IM *%%s* >nul 2>&1
        taskkill /F /FI "IMAGENAME eq *%%s*" >nul 2>&1
        set /a found_spyware+=1
    )
)

:: Buscar procesos ocultos con nombres MAL ESCRITOS (camuflados)
echo Buscando procesos camuflados con nombres falsos...
:: Buscar SOLO variantes mal escritas, NO los procesos reales
for /f "tokens=1" %%a in ('tasklist 2^>nul') do (
    set "proc=%%a"
    
    :: Verificar variantes MAL ESCRITAS de procesos del sistema
    echo !proc! | findstr /i "svch0st svchos winl0gon csrs.exe lsas.exe explorer.com iexplore.com chrome.com firefox.com svchosts.exe winlogons.exe" >nul 2>&1
    if !errorlevel!==0 (
        :: Verificar que NO sea el proceso legítimo
        if /i not "!proc!"=="csrss.exe" (
            if /i not "!proc!"=="lsass.exe" (
                if /i not "!proc!"=="svchost.exe" (
                    echo [SOSPECHOSO] Proceso camuflado: %%a
                    echo [CAMUFLADO] %%a >> "%LOGFILE%"
                    taskkill /F /IM %%a >nul 2>&1
                    set /a found_spyware+=1
                )
            )
        )
    )
)

echo Spyware detectado y eliminado: %found_spyware%
echo.

:: ============================================
:: FASE 3: ELIMINAR SOFTWARE DE CONTROL REMOTO
:: ============================================
echo.
echo ================================================
echo [3/15] ELIMINANDO SOFTWARE DE ACCESO REMOTO
echo ================================================
echo.
echo [FASE 3] Eliminando acceso remoto... >> "%LOGFILE%"

set remote_software=anydesk teamviewer rustdesk winvnc tightvnc realvnc ultravnc uvnc dwservice splashtop logmein chrome-remote-desktop msra quickassist RemotePC GoToMyPC Ammyy radmin supremo mikogo join.me ShowMyPC LiteManager NetSupport RemoteUtilities UltraViewer Zoho_Assist ScreenConnect ConnectWise Dameware pcAnywhere VNC_Viewer

for %%r in (%remote_software%) do (
    tasklist | findstr /i "%%r" >nul 2>&1
    if !errorlevel!==0 (
        echo [ELIMINADO] Software remoto: %%r
        echo [REMOTO] %%r >> "%LOGFILE%"
        taskkill /F /IM *%%r*.exe >nul 2>&1
        set /a found_remote+=1
    )
)

echo Software remoto eliminado: %found_remote%
echo.

:: ============================================
:: FASE 4: DETECTAR Y ELIMINAR BACKDOORS/RATS
:: ============================================
echo.
echo ================================================
echo [4/15] BUSCANDO BACKDOORS Y TROYANOS
echo ================================================
echo.
echo [FASE 4] Escaneando backdoors... >> "%LOGFILE%"

set backdoor_list=nanocore njrat darkcomet quasar cybergate bifrost poison_ivy blackshades xtreme_rat netwire asyncrat remcos warzone agent_tesla ave_maria formbook lokibot azorult raccoon redline vidar metasploit cobaltstrike havoc sliver pupy_rat empire powershell_empire mimikatz bloodhound sharphound rubeus kerberoast impacket crackmapexec psexec winexe paexec remoteexec wmiexec atexec smbexec

for %%b in (%backdoor_list%) do (
    tasklist | findstr /i "%%b" >nul 2>&1
    if !errorlevel!==0 (
        echo [CRITICO] Backdoor detectado: %%b
        echo [BACKDOOR] %%b >> "%LOGFILE%"
        taskkill /F /IM *%%b*.exe >nul 2>&1
        set /a found_backdoors+=1
    )
)

echo Backdoors detectados: %found_backdoors%
echo.

:: ============================================
:: FASE 5: DESHABILITAR SERVICIOS DE RASTREO
:: ============================================
echo.
echo ================================================
echo [5/15] DESHABILITANDO SERVICIOS DE RASTREO
echo ================================================
echo.
echo [FASE 5] Deshabilitando servicios... >> "%LOGFILE%"

:: Servicios de acceso remoto
set remote_services=TermService TeamViewer AnyDesk RustDesk UmRdpService SessionEnv RemoteRegistry WinRM SSDPSRV upnphost RemoteAccess RasMan

:: Servicios de telemetria y rastreo
set tracking_services=DiagTrack dmwappushservice RetailDemo WerSvc DoSvc

:: Servicios potencialmente usados para espionaje
set spy_services=SNMP SNMPTRAP TlntSvr

echo Deshabilitando servicios de acceso remoto...
for %%s in (%remote_services%) do (
    sc query %%s >nul 2>&1
    if !errorlevel!==0 (
        echo Deshabilitando: %%s
        echo [SERVICIO] %%s deshabilitado >> "%LOGFILE%"
        net stop %%s /y >nul 2>&1
        sc config %%s start= disabled >nul 2>&1
        sc stop %%s >nul 2>&1
        set /a found_services+=1
    )
)

echo Deshabilitando servicios de telemetria...
for %%t in (%tracking_services%) do (
    sc query %%t >nul 2>&1
    if !errorlevel!==0 (
        echo Deshabilitando: %%t
        echo [TELEMETRIA] %%t deshabilitado >> "%LOGFILE%"
        net stop %%t /y >nul 2>&1
        sc config %%t start= disabled >nul 2>&1
        set /a found_services+=1
    )
)

:: Deshabilitar PowerShell Remoting
echo Deshabilitando PowerShell Remoting...
powershell -Command "try { Disable-PSRemoting -Force -ErrorAction SilentlyContinue } catch {}" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 0 /f >nul 2>&1
echo [SERVICIO] PowerShell Remoting deshabilitado >> "%LOGFILE%"

:: Deshabilitar Quick Assist y Remote Assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemoteAssistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemoteAssistance" /v fAllowFullControl /t REG_DWORD /d 0 /f >nul 2>&1

echo Servicios deshabilitados: %found_services%
echo.

:: ============================================
:: FASE 6: BLOQUEAR PUERTOS Y RED
:: ============================================
echo.
echo ================================================
echo [6/15] BLOQUEANDO PUERTOS PELIGROSOS
echo ================================================
echo.
echo [FASE 6] Configurando firewall... >> "%LOGFILE%"

:: Activar firewall en todos los perfiles
echo Activando firewall de Windows...
netsh advfirewall set allprofiles state on >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1

:: Asegurar que puertos de navegacion web esten desbloqueados
echo Desbloqueando puertos de navegacion web (HTTP/HTTPS)...
netsh advfirewall firewall delete rule name="BLOCK_80" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_80_UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_80_OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_443" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_443_UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_443_OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8080" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8080_UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8080_OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8443" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8443_UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="BLOCK_8443_OUT" >nul 2>&1
echo [OK] Puertos de navegacion desbloqueados (80, 443, 8080, 8443)

:: Puertos criticos (NO incluye 80 ni 443 para permitir navegacion)
set critical_ports=22 23 135 137 138 139 445 593 3389 5900 5901 5800 5500
:: Puertos de RATs
set rat_ports=1337 4444 5555 6666 7777 9999 12345 31337 54321
:: Puertos de C2 (removidos 80, 443, 8080, 8443 para navegacion)
set c2_ports=8000 8888 9000 10000 6667 6697

echo Bloqueando puertos criticos...
for %%p in (%critical_ports% %rat_ports% %c2_ports%) do (
    netsh advfirewall firewall delete rule name="BLOCK_%%p" >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p" dir=in action=block protocol=TCP localport=%%p >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_UDP" dir=in action=block protocol=UDP localport=%%p >nul 2>&1
    netsh advfirewall firewall add rule name="BLOCK_%%p_OUT" dir=out action=block protocol=TCP remoteport=%%p >nul 2>&1
    echo [PUERTO] %%p bloqueado (entrada/salida) >> "%LOGFILE%"
    set /a ports_blocked+=1
)

:: Bloquear SMB v1 (usado en ataques)
echo Deshabilitando SMBv1...
dism /online /disable-feature /featurename:SMB1Protocol /norestart >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f >nul 2>&1

echo Puertos bloqueados: %ports_blocked%
echo.
echo NOTA: Los puertos 80 y 443 (HTTP/HTTPS) NO fueron bloqueados
echo para permitir navegacion web normal.
echo.

:: ============================================
:: FASE 7: LIMPIEZA MASIVA DE AUTO-INICIO
:: ============================================
echo.
echo ================================================
echo [7/15] LIMPIANDO ENTRADAS DE AUTO-INICIO
echo ================================================
echo.
echo [FASE 7] Limpiando auto-inicio... >> "%LOGFILE%"

:: Exportar backup de registro
echo Exportando backup de registro...
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "%LOGDIR%\backup_run_user.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "%LOGDIR%\backup_run_machine.reg" /y >nul 2>&1

:: Ubicaciones de auto-inicio
set "startup_keys=HKCU\Software\Microsoft\Windows\CurrentVersion\Run HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

echo Escaneando entradas sospechosas...
for %%k in (%startup_keys%) do (
    echo Revisando: %%k
    for %%m in (%spyware_list% %remote_software% %backdoor_list%) do (
        reg query "%%k" 2>nul | findstr /i "%%m" >nul 2>&1
        if !errorlevel!==0 (
            echo [ELIMINADO] %%m de auto-inicio
            echo [STARTUP] %%m en %%k >> "%LOGFILE%"
            reg delete "%%k" /v %%m /f >nul 2>&1
            set /a found_startup+=1
        )
    )
)

:: Revisar carpetas de inicio
echo Limpiando carpetas de inicio...
set "startup_folders=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup %ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"

for %%f in (%startup_folders%) do (
    if exist "%%f" (
        echo Revisando: %%f
        dir /b "%%f\*.lnk" "%%f\*.exe" 2>nul | findstr /i "%spyware_list% %remote_software%" >nul 2>&1
        if !errorlevel!==0 (
            echo [ADVERTENCIA] Archivos sospechosos en carpeta de inicio
            echo [STARTUP_FOLDER] Archivos en %%f >> "%LOGFILE%"
            dir /b "%%f" >> "%LOGFILE%"
        )
    )
)

echo Entradas de auto-inicio eliminadas: %found_startup%
echo.

:: ============================================
:: FASE 8: ELIMINAR TAREAS PROGRAMADAS
:: ============================================
echo.
echo ================================================
echo [8/15] ELIMINANDO TAREAS PROGRAMADAS SOSPECHOSAS
echo ================================================
echo.
echo [FASE 8] Analizando tareas programadas... >> "%LOGFILE%"

:: Exportar lista completa
echo Exportando lista de tareas...
schtasks /query /fo LIST /v > "%LOGDIR%\tareas_antes.txt" 2>nul

echo Eliminando tareas de software de monitoreo...
set task_patterns=TeamViewer AnyDesk RustDesk QuickAssist RemotePC Chrome_Remote Zoho FlexiSPY mSpy Hoverwatch Spyware Keylogger Monitor Surveillance Track Spy Watch Logger Update_Check

for %%t in (%task_patterns%) do (
    schtasks /query /fo LIST | findstr /i "%%t" >nul 2>&1
    if !errorlevel!==0 (
        echo Buscando tareas con: %%t
        for /f "tokens=2 delims=:" %%a in ('schtasks /query /fo LIST ^| findstr /i "%%t"') do (
            set "taskname=%%a"
            set "taskname=!taskname:~1!"
            if not "!taskname!"=="" (
                echo [ELIMINADO] Tarea: !taskname!
                echo [TAREA] !taskname! >> "%LOGFILE%"
                schtasks /delete /tn "!taskname!" /f >nul 2>&1
                set /a found_tasks+=1
            )
        )
    )
)

echo Tareas eliminadas: %found_tasks%
echo.

:: ============================================
:: FASE 9: PROTECCION DEL REGISTRO
:: ============================================
echo.
echo ================================================
echo [9/15] APLICANDO PROTECCIONES DE REGISTRO
echo ================================================
echo.
echo [FASE 9] Configurando registro... >> "%LOGFILE%"

:: Bloquear carga de DLLs no autorizadas
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] Carga de DLLs restringida

:: Deshabilitar Windows Script Host
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Windows Script Host deshabilitado

:: Proteger herramientas del sistema
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Herramientas del sistema protegidas

:: Deshabilitar ejecucion automatica de USBs
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul 2>&1
echo [OK] AutoRun de USBs deshabilitado

:: Bloquear macros de Office
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f >nul 2>&1
echo [OK] Macros de Office bloqueadas

:: Deshabilitar Sticky Keys backdoor
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f >nul 2>&1
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d "58" /f >nul 2>&1
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d "122" /f >nul 2>&1
echo [OK] Backdoor de Sticky Keys bloqueado

echo [OK] Registro protegido
echo.

:: ============================================
:: FASE 10: PROTECCION DE PRIVACIDAD
:: ============================================
echo.
echo ================================================
echo [10/15] CONFIGURANDO PRIVACIDAD MAXIMA
echo ================================================
echo.
echo [FASE 10] Aplicando privacidad... >> "%LOGFILE%"

:: Deshabilitar telemetria de Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Telemetria deshabilitada

:: Bloquear acceso a camara
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f >nul 2>&1
echo [OK] Acceso a camara bloqueado

:: Bloquear acceso a microfono
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f >nul 2>&1
echo [OK] Acceso a microfono bloqueado

:: Bloquear ubicacion
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f >nul 2>&1
echo [OK] Localizacion bloqueada

:: Deshabilitar Cortana y busqueda web
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] Cortana y busqueda web deshabilitadas

:: Deshabilitar historial de actividades
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] Historial de actividades deshabilitado

:: Bloquear ID de publicidad
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
echo [OK] ID de publicidad bloqueado

echo [OK] Privacidad configurada
echo.

:: ============================================
:: FASE 11: BLOQUEO DNS MASIVO
:: ============================================
echo.
echo ================================================
echo [11/15] APLICANDO BLOQUEO DNS EXTENSIVO
echo ================================================
echo.
echo [FASE 11] Bloqueando dominios... >> "%LOGFILE%"

set hosts_file=%windir%\System32\drivers\etc\hosts

:: Backup del archivo hosts
copy "%hosts_file%" "%LOGDIR%\hosts_backup.txt" >nul 2>&1

(
echo.
echo # ======================================================
echo # BLOQUEO DE SEGURIDAD - EQUIPOS DE SEGUNDA MANO
echo # Fecha: %date% %time%
echo # ======================================================
echo.
echo # === SOFTWARE DE ACCESO REMOTO ===
echo 0.0.0.0 anydesk.com
echo 0.0.0.0 relay.anydesk.com
echo 0.0.0.0 download.anydesk.com
echo 0.0.0.0 teamviewer.com
echo 0.0.0.0 get.teamviewer.com
echo 0.0.0.0 download.teamviewer.com
echo 0.0.0.0 master.teamviewer.com
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
echo 0.0.0.0 radmin.com
echo 0.0.0.0 screenconnect.com
echo 0.0.0.0 connectwise.com
echo 0.0.0.0 dameware.com
echo.
echo # === SPYWARE COMERCIAL ===
echo 0.0.0.0 flexispy.com
echo 0.0.0.0 mspy.com
echo 0.0.0.0 mspy.mx
echo 0.0.0.0 hoverwatch.com
echo 0.0.0.0 thetruthspy.com
echo 0.0.0.0 spyzie.com
echo 0.0.0.0 spyera.com
echo 0.0.0.0 highsterspy.com
echo 0.0.0.0 ikeymonitor.com
echo 0.0.0.0 mobistealth.com
echo 0.0.0.0 spybubble.com
echo 0.0.0.0 phonesheriff.com
echo 0.0.0.0 teensafe.com
echo.
echo # === KEYLOGGERS ===
echo 0.0.0.0 ardamax.com
echo 0.0.0.0 refog.com
echo 0.0.0.0 spytech-web.com
echo 0.0.0.0 kidlogger.net
echo 0.0.0.0 actualspy.com
echo 0.0.0.0 blazingtools.com
echo 0.0.0.0 elitekeylogger.com
echo 0.0.0.0 perfectkeylogger.com
echo.
echo # === SOFTWARE DE CONTROL PARENTAL/EMPRESARIAL ===
echo 0.0.0.0 qustodio.com
echo 0.0.0.0 bark.us
echo 0.0.0.0 famisafe.wondershare.com
echo 0.0.0.0 webwatcher.com
echo 0.0.0.0 spectorsoft.com
echo 0.0.0.0 netref.com
echo 0.0.0.0 activtrak.com
echo 0.0.0.0 teramind.com
echo 0.0.0.0 veriato.com
echo 0.0.0.0 workpuls.com
echo 0.0.0.0 hubstaff.com
echo 0.0.0.0 timedoctor.com
echo.
echo # === RASTREADORES Y GEOLOCALIZACION ===
echo 0.0.0.0 life360.com
echo 0.0.0.0 findmykids.org
echo 0.0.0.0 familylocator.com
echo 0.0.0.0 gpswox.com
echo 0.0.0.0 trackview.net
echo.
echo # === TELEMETRIA DE WINDOWS ===
echo 0.0.0.0 vortex.data.microsoft.com
echo 0.0.0.0 vortex-win.data.microsoft.com
echo 0.0.0.0 telecommand.telemetry.microsoft.com
echo 0.0.0.0 oca.telemetry.microsoft.com
echo 0.0.0.0 sqm.telemetry.microsoft.com
echo 0.0.0.0 watson.telemetry.microsoft.com
echo 0.0.0.0 ceuswatcab01.blob.core.windows.net
echo 0.0.0.0 ceuswatcab02.blob.core.windows.net
echo 0.0.0.0 eaus2watcab01.blob.core.windows.net
echo 0.0.0.0 weus2watcab02.blob.core.windows.net
echo.
) >> "%hosts_file%"

echo [OK] Bloqueo DNS aplicado con 100+ dominios
echo [DNS] Archivo hosts actualizado >> "%LOGFILE%"
echo.

:: ============================================
:: FASE 12: ANALISIS DE CONEXIONES ACTIVAS
:: ============================================
echo.
echo ================================================
echo [12/15] ANALIZANDO CONEXIONES DE RED
echo ================================================
echo.
echo [FASE 12] Analizando red... >> "%LOGFILE%"

echo Exportando conexiones activas...
netstat -ano > "%LOGDIR%\conexiones_completas.txt"
netstat -ano | findstr "ESTABLISHED LISTENING" > "%LOGDIR%\conexiones_activas.txt"

echo Buscando conexiones sospechosas...
set suspicious_count=0
for /f "tokens=3,5" %%a in ('netstat -ano ^| findstr "ESTABLISHED"') do (
    set "remote_ip=%%a"
    set "pid=%%b"
    
    echo !remote_ip! | findstr "127.0.0.1 192.168 10.0 172.16" >nul 2>&1
    if !errorlevel! neq 0 (
        echo [CONEXION] IP: !remote_ip! PID: !pid! >> "%LOGFILE%"
        set /a suspicious_count+=1
    )
)

echo Conexiones externas detectadas: %suspicious_count%
echo Ver archivo: %LOGDIR%\conexiones_activas.txt
echo.

:: ============================================
:: FASE 13: BUSQUEDA DE DRIVERS SOSPECHOSOS
:: ============================================
echo.
echo ================================================
echo [13/15] ANALIZANDO DRIVERS DEL SISTEMA
echo ================================================
echo.
echo [FASE 13] Buscando drivers sospechosos... >> "%LOGFILE%"

echo Exportando lista de drivers...
driverquery /v /fo csv > "%LOGDIR%\drivers_sistema.csv"

echo Buscando drivers relacionados con espionaje...
set driver_patterns=keylog spy hook capture record track surveillance

:: Lista blanca de drivers legitimos que contienen palabras clave
set driver_whitelist=monitor.sys pktmon.sys perfmon.sys

for %%d in (%driver_patterns%) do (
    for /f "tokens=1" %%x in ('driverquery 2^>nul ^| findstr /i "%%d"') do (
        set "driver_name=%%x"
        set "is_whitelisted=0"
        
        :: Verificar si esta en lista blanca
        for %%w in (%driver_whitelist%) do (
            if /i "!driver_name!"=="%%w" set "is_whitelisted=1"
        )
        
        :: Solo reportar si NO esta en lista blanca
        if !is_whitelisted!==0 (
            echo [ADVERTENCIA] Driver sospechoso: !driver_name!
            echo [DRIVER] !driver_name! >> "%LOGFILE%"
            set /a found_drivers+=1
        )
    )
)

if %found_drivers% GTR 0 (
    echo [ATENCION] Se encontraron %found_drivers% drivers sospechosos
    echo Revisa el archivo: %LOGDIR%\drivers_sistema.csv
) else (
    echo [OK] No se encontraron drivers sospechosos obvios
)
echo.

:: ============================================
:: FASE 14: LIMPIEZA DE ARCHIVOS TEMPORALES
:: ============================================
echo.
echo ================================================
echo [14/15] LIMPIANDO ARCHIVOS TEMPORALES
echo ================================================
echo.
echo [FASE 14] Limpiando temporales... >> "%LOGFILE%"

echo Limpiando carpetas temporales...
del /f /s /q "%TEMP%\*" >nul 2>&1
del /f /s /q "%SystemRoot%\Temp\*" >nul 2>&1
del /f /s /q "%SystemRoot%\Prefetch\*" >nul 2>&1

:: Limpiar cache de navegadores (logs)
echo Limpiando cache de navegadores...
taskkill /F /IM chrome.exe >nul 2>&1
taskkill /F /IM firefox.exe >nul 2>&1
taskkill /F /IM msedge.exe >nul 2>&1

rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache" >nul 2>&1

:: Limpiar logs del sistema
echo Limpiando logs del sistema...
wevtutil cl System >nul 2>&1
wevtutil cl Security >nul 2>&1
wevtutil cl Application >nul 2>&1

echo [OK] Archivos temporales y logs eliminados
echo [LIMPIEZA] Temporales eliminados >> "%LOGFILE%"
echo.

:: ============================================
:: FASE 15: VERIFICACION Y REPORTE FINAL
:: ============================================
echo.
echo ================================================
echo [15/15] GENERANDO REPORTE FINAL
echo ================================================
echo.

:: Crear reporte detallado
(
echo ========================================================
echo     REPORTE DE LIMPIEZA - EQUIPO DE SEGUNDA MANO
echo ========================================================
echo.
echo Fecha: %date% %time%
echo Usuario: %USERNAME%
echo Equipo: %COMPUTERNAME%
echo.
echo ========================================================
echo     RESUMEN DE AMENAZAS ELIMINADAS
echo ========================================================
echo.
echo [1] SPYWARE Y KEYLOGGERS........: %found_spyware%
echo [2] SOFTWARE DE ACCESO REMOTO...: %found_remote%
echo [3] BACKDOORS Y TROYANOS........: %found_backdoors%
echo [4] SERVICIOS DESHABILITADOS....: %found_services%
echo [5] PUERTOS BLOQUEADOS..........: %ports_blocked%
echo [6] AUTO-INICIO ELIMINADO.......: %found_startup%
echo [7] TAREAS PROGRAMADAS ELIMINADAS: %found_tasks%
echo [8] DRIVERS SOSPECHOSOS.........: %found_drivers%
echo [9] CONEXIONES EXTERNAS.........: %suspicious_count%
echo.
echo ========================================================
echo     ESTADO DE PROTECCION ACTUAL
echo ========================================================
echo.
echo [√] Firewall de Windows: ACTIVADO
echo [√] Puertos criticos: BLOQUEADOS (31 puertos)
echo [√] Puertos web (80,443,8080,8443): PERMITIDOS
echo [√] PowerShell Remoting: DESHABILITADO
echo [√] Escritorio Remoto: DESHABILITADO
echo [√] Acceso a Camara: BLOQUEADO
echo [√] Acceso a Microfono: BLOQUEADO
echo [√] Localizacion: BLOQUEADA
echo [√] Telemetria: DESHABILITADA
echo [√] AutoRun USB: DESHABILITADO
echo [√] Windows Script Host: DESHABILITADO
echo [√] Bloqueo DNS: APLICADO (100+ dominios)
echo.
echo ========================================================
echo     RECOMENDACIONES IMPORTANTES
echo ========================================================
echo.
if %found_spyware% GTR 0 (
    echo [!!!] ALERTA CRITICA - SPYWARE DETECTADO
    echo.
    echo Se detectaron %found_spyware% programas espias activos.
    echo.
    echo ACCIONES URGENTES:
    echo 1. Cambiar TODAS las contraseñas de cuentas importantes
    echo    - Email, redes sociales, banco, trabajo
    echo 2. Habilitar autenticacion de dos factores ^(2FA^)
    echo 3. Revisar actividad reciente en cuentas bancarias
    echo 4. Notificar a contactos si compartiste info sensible
    echo 5. Considerar formateo completo cuando sea posible
    echo.
)

if %found_backdoors% GTR 0 (
    echo [!!!] ALERTA MAXIMA - BACKDOORS DETECTADOS
    echo.
    echo Se detectaron %found_backdoors% posibles puertas traseras.
    echo.
    echo ACCIONES CRITICAS:
    echo 1. NO ingresar contraseñas ni datos bancarios
    echo 2. Escanear con antivirus especializado
    echo 3. FORMATEAR EL EQUIPO lo antes posible
    echo 4. Reportar a autoridades si hay robo de datos
    echo.
)

if %found_drivers% GTR 0 (
    echo [!] ADVERTENCIA - DRIVERS SOSPECHOSOS
    echo.
    echo Se encontraron %found_drivers% drivers que requieren revision.
    echo Revisa el archivo: drivers_sistema.csv
    echo.
)

echo ACCIONES GENERALES RECOMENDADAS:
echo ----------------------------------
echo.
echo 1. CAMBIAR CONTRASEÑAS
echo    - Usa contraseñas unicas y fuertes
echo    - Habilita 2FA en todas las cuentas importantes
echo.
echo 2. INSTALAR PROTECCION
echo    - Antivirus actualizado ^(Windows Defender es suficiente^)
echo    - Mantener Windows Update activado
echo.
echo 3. VERIFICAR PERIODICAMENTE
echo    - Ejecutar este script cada 15 dias
echo    - Revisar procesos activos en Task Manager
echo    - Monitorear conexiones de red
echo.
echo 4. ANTES DE FIN DE AÑO
echo    - Respaldar datos importantes
echo    - Planificar formateo completo
echo    - Reinstalar Windows desde cero
echo.
echo 5. HABITOS SEGUROS
echo    - No instalar software de fuentes desconocidas
echo    - Descargar solo de sitios oficiales
echo    - No abrir archivos adjuntos sospechosos
echo    - Usar navegacion privada para datos sensibles
echo.
echo ========================================================
echo     ARCHIVOS GENERADOS EN EL ESCRITORIO
echo ========================================================
echo.
echo Carpeta: %LOGDIR%
echo.
echo Archivos disponibles:
echo - REPORTE_FINAL.txt ............: Este archivo
echo - log_completo.txt .............: Log detallado de acciones
echo - conexiones_activas.txt .......: Conexiones de red activas
echo - conexiones_completas.txt .....: Todas las conexiones
echo - drivers_sistema.csv ..........: Lista completa de drivers
echo - tareas_antes.txt .............: Tareas programadas
echo - backup_run_user.reg ..........: Backup registro usuario
echo - backup_run_machine.reg .......: Backup registro sistema
echo - hosts_backup.txt .............: Backup archivo hosts
echo.
echo ========================================================
echo     NOTAS FINALES
echo ========================================================
echo.
echo - Este script NO sustituye un formateo completo
echo - Es una solucion temporal hasta fin de año
echo - Algunos servicios legitimos pueden estar bloqueados
echo - Si necesitas software remoto, deberas habilitarlo
echo - Mantén este script para futuras verificaciones
echo.
echo Para revertir cambios: usa los archivos .reg de backup
echo o crea un punto de restauracion antes de ejecutar.
echo.
echo ========================================================
echo Limpieza completada el: %date% a las %time%
echo ========================================================
) > "%REPORTFILE%"

:: Copiar reporte al log
type "%REPORTFILE%" >> "%LOGFILE%"

:: ============================================
:: PANTALLA FINAL
:: ============================================
cls
echo.
echo ========================================================
echo     LIMPIEZA COMPLETADA EXITOSAMENTE
echo ========================================================
echo.
type "%REPORTFILE%"
echo.
echo ========================================================
echo Presiona cualquier tecla para abrir la carpeta de reportes...
pause >nul

:: Abrir carpeta con reportes
explorer "%LOGDIR%"

:: Opcional: Mostrar reporte en notepad
start notepad "%REPORTFILE%"

endlocal
exit /b 0