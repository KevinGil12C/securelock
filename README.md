# 🔐 **SecureShield - Sistema de Protección Integral para Windows**

![Windows Security Shield](https://img.shields.io/badge/Windows-Security-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![Batch Script](https://img.shields.io/badge/Batch-File-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge)

**SecureShield** es un sistema de seguridad avanzado en formato Batch que protege equipos Windows contra amenazas de espionaje, acceso remoto no autorizado y software malicioso.

## ⚡ **Características Destacadas**

### 🛡️ **Protección Multicapa**
- ✅ **Anti-Remote Access**: Bloquea AnyDesk, TeamViewer, VNC, RustDesk
- ✅ **Anti-Keylogger**: Detecta y elimina más de 20 keyloggers conocidos
- ✅ **Anti-RAT**: Identifica troyanos de acceso remoto (Nanocore, DarkComet, Quasar)
- ✅ **Anti-Spyware**: Protege webcam, micrófono y pantalla

### 🔍 **Detección Avanzada**
- 🔬 **Análisis de procesos** con patrones de comportamiento
- 🌐 **Monitoreo de red** y conexiones sospechosas
- 📋 **Auditoría de registro** y auto-inicio
- ⏰ **Revisión de tareas programadas** maliciosas

### 📊 **Sistema de Logs**
- 📝 **Registro detallado** con timestamp
- 🔗 **Conexiones activas** guardadas para análisis
- ⚙️ **Configuraciones aplicadas** documentadas
- 🚨 **Alertas priorizadas** por nivel de amenaza

## 🚀 **Instalación y Uso**

### **Requisitos**
- Windows 10/11 (64-bit recomendado)
- Permisos de Administrador
- PowerShell habilitado
- 50MB espacio libre

### **Instalación en un Paso**
```batch
# Copia este código como SecureShield.bat
# Ejecuta como Administrador (clic derecho → "Ejecutar como administrador")
```

### **Verificación de Instalación**
```batch
# Verificar permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 echo [ERROR] Se necesitan permisos de admin
```

## 📋 **Funcionalidades por Fase**

### **Fase 1: Bloqueo de Software Remoto**
```batch
# Software bloqueado incluye:
- AnyDesk, TeamViewer, RustDesk
- VNC (UltraVNC, TightVNC, RealVNC)
- LogMeIn, Splashtop, dwService
- Chrome Remote Desktop
- Quick Assist de Microsoft
- Y 15+ soluciones adicionales
```

### **Fase 2: Detección de Keyloggers**
```batch
# Keyloggers detectados:
- Ardamax Keylogger
- Refog Keylogger
- Spytech Keylogger
- KidLogger
- Elite Keylogger
- Perfect Keylogger
- Y 15+ variantes conocidas
```

### **Fase 3: Detección de RATs**
```batch
# Troyanos detectados:
- Nanocore RAT
- NjRat
- DarkComet
- Quasar RAT
- Bifrost
- Poison Ivy
- BlackShades
- NetWire
- Agent Tesla
- Y 10+ variantes
```

### **Fase 4: Servicios del Sistema**
```batch
# Servicios deshabilitados:
- TermService (RDP)
- TeamViewer Service
- AnyDesk Service
- Remote Registry
- Windows Remote Management
- UPnP Device Host
```

### **Fase 5: Protección de Puertos**
```batch
# Puertos bloqueados:
- 22, 23, 135, 139, 445
- 3389 (RDP), 5900-5901 (VNC)
- 4444, 5555, 6666 (RAT comunes)
- 1337, 31337, 54321 (backdoors)
- 8000, 8080, 8443, 9000
```

### **Fase 6: Protección del Registro**
```batch
# Configuraciones aplicadas:
- DLLs de inicio bloqueadas
- Windows Script Host deshabilitado
- Task Manager protegido
- Registry Editor protegido
- Ejecución desde TEMP bloqueada
```

### **Fase 7: Privacidad Webcam/Mic**
```batch
# Protecciones de privacidad:
- Acceso a webcam denegado globalmente
- Acceso a micrófono denegado
- Captura de pantalla restringida
```

### **Fase 8: Bloqueo DNS**
```batch
# Dominios bloqueados:
- anydesk.com, teamviewer.com
- rustdesk.com, dwservice.net
- Dominios de keyloggers
- Dominios de spyware comercial
```

### **Fase 9: Análisis de Red**
```batch
# Monitoreo de red:
- Conexiones ESTABLISHED capturadas
- IPs sospechosas identificadas
- Logs detallados de actividad
```

### **Fase 10: Tareas Programadas**
```batch
# Limpieza de automatizaciones:
- Tareas de software remoto eliminadas
- Lista completa de tareas guardada
- Tareas sospechosas documentadas
```

## 📁 **Estructura de Archivos Generados**

```
C:\Users\[Usuario]\Desktop\SecurityLogs\
├── security_log_[AAAAMMDD]_[HHMMSS].txt  # Log principal
├── conexiones_activas.txt                 # Conexiones de red
├── tareas_programadas.txt                 # Tareas programadas
└── (archivos adicionales por ejecución)
```

## ⚙️ **Personalización Avanzada**

### **Agregar Nuevos Procesos a Bloquear**
Edita las variables al inicio del script:
```batch
set remote_processes=nuevoproceso1 nuevoproceso2
set keylogger_list=nuevokeylogger1 nuevokeylogger2
set rat_list=nuevorat1 nuevorat2
```

### **Agregar Nuevos Puertos**
Modifica las listas de puertos:
```batch
set ports_remote=puerto1 puerto2
set ports_rats=puerto3 puerto4
set ports_c2=puerto5 puerto6
```

### **Agregar Nuevos Dominios DNS**
Añade al bloque de hosts:
```batch
echo 0.0.0.0 nuevodominio.com
echo 0.0.0.0 subdominio.dominio.com
```

## 🚨 **Alertas y Niveles de Amenaza**

### **Nivel 1: Información**
```batch
echo [OK] Configuración aplicada
```

### **Nivel 2: Advertencia**
```batch
echo [ADVERTENCIA] Posible amenaza detectada
```

### **Nivel 3: Crítico**
```batch
echo [ALERTA CRITICA] Keylogger detectado
```

### **Nivel 4: Máximo**
```batch
echo [ALERTA MAXIMA - TROYANO DETECTADO]
```

## 📈 **Métricas y Estadísticas**

El script genera un resumen completo con:
- ✅ Procesos bloqueados por categoría
- 🔍 Amenazas detectadas y neutralizadas
- ⚙️ Servicios deshabilitados
- 🔗 Puertos bloqueados
- 🌐 Conexiones sospechosas identificadas

## 🔄 **Restauración del Sistema**

### **Script de Restauración (Recomendado)**
```batch
@echo off
:: Restaurar configuración original
netsh advfirewall reset
:: Habilitar RDP
reg add "HKLM\SYSTEM\...\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
:: Limpiar bloqueo DNS
type hosts | findstr /v "# === BLOQUEO" > hosts.temp
move /y hosts.temp hosts
```

### **Restauración Manual**
1. Eliminar reglas de firewall: `netsh advfirewall reset`
2. Habilitar servicios necesarios
3. Limpiar archivo hosts manualmente

## 🛠️ **Solución de Problemas**

### **Problema: Script no ejecuta**
```batch
# Solución: Verificar permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 echo Ejecutar como Administrador
```

### **Problema: Puertos no se bloquean**
```batch
# Solución: Verificar firewall activo
netsh advfirewall show allprofiles state
```

### **Problema: Procesos persisten**
```batch
# Solución: Forzar cierre con PowerShell
powershell "Get-Process proceso | Stop-Process -Force"
```

## 📊 **Casos de Uso**

### **1. Uso Personal**
- Protección contra spyware doméstico
- Bloqueo de acceso remoto no autorizado
- Privacidad de webcam y micrófono

### **2. Entornos Corporativos**
- Cumplimiento de políticas de seguridad
- Protección de datos sensibles
- Auditoría de conexiones remotas

### **3. Entornos Educativos**
- Prevención de cheating en exámenes
- Protección de laboratorios informáticos
- Control de acceso remoto en aulas

## ⚠️ **Limitaciones y Consideraciones**

### **Limitaciones Técnicas**
- No detecta malware polimórfico
- No protege contra exploits de día cero
- Requiere ejecución manual/periódica
- No reemplaza un antivirus completo

### **Consideraciones Legales**
- Solo para uso en sistemas propios
- Respetar políticas corporativas
- No usar para vigilancia no autorizada
- Cumplir con leyes locales de privacidad

## 🔬 **Tecnologías y Métodos Utilizados**

### **Detección por Firmas**
- Listas de procesos maliciosos conocidos
- Puertos comunes de backdoors
- Dominios de C2 servers

### **Análisis de Comportamiento**
- Hooks de teclado sospechosos
- Conexiones a puertos no estándar
- Tareas programadas automáticas

### **Hardening del Sistema**
- Configuración de políticas de registro
- Restricciones de firewall
- Protección de servicios del sistema

## 📚 **Recursos Adicionales**

### **Documentación Relacionada**
- [Microsoft Security Baseline](https://docs.microsoft.com/security/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Security Guidelines](https://owasp.org/)

### **Herramientas Complementarias**
- [Windows Defender](https://www.microsoft.com/security)
- [Malwarebytes](https://www.malwarebytes.com/)
- [Process Explorer](https://docs.microsoft.com/sysinternals/)

## 🤝 **Contribuir**

### **Reportar Problemas**
1. Revisar logs generados
2. Incluir sistema operativo y versión
3. Describir comportamiento esperado vs real

### **Sugerir Mejoras**
1. Proporcionar ejemplos de amenazas no detectadas
2. Sugerir nuevas técnicas de detección
3. Proponer optimizaciones de rendimiento

## 📄 **Licencia**

Este proyecto está bajo la **Licencia MIT**. Ver archivo [LICENSE](LICENSE) para más detalles.

```
MIT License

Copyright (c) 2024 SecureShield

Se concede permiso, libre de cargos, a cualquier persona que obtenga una copia
de este software y de los archivos de documentación asociados...
```

## 🌟 **Reconocimientos**

- Basado en técnicas de la comunidad de seguridad
- Testeado en entornos Windows 10/11 reales
- Inspirado en necesidades de usuarios reales

---

<div align="center">
  
### **⚠️ IMPORTANTE: SOLO PARA USO LEGÍTIMO ⚠️**

**Este script está diseñado para:**
- Proteger sistemas propios
- Auditoría de seguridad autorizada
- Educación en ciberseguridad

**NO está diseñado para:**
- Vigilancia no autorizada
- Actividades ilegales
- Vulnerar sistemas ajenos

</div>

---

<div align="center">
  <img src="https://img.shields.io/badge/Hecho%20con-❤️-red" alt="Hecho con amor">
  <br>
  <sub>Si este proyecto te ayudó, considera darle una ⭐</sub>
</div>
