# 🛡️ Sistema de Protección Completa v3.1

**Limpieza y protección exhaustiva para equipos de segunda mano**

[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=flat&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Batch](https://img.shields.io/badge/Batch-Script-blue.svg)](https://en.wikipedia.org/wiki/Batch_file)
[![Version](https://img.shields.io/badge/Version-3.1-orange.svg)](https://github.com/KevinGil12C/securelock/releases)

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [¿Qué hace el script?](#-qué-hace-el-script)
- [Archivos generados](#-archivos-generados)
- [Recomendaciones](#-recomendaciones)
- [Limitaciones conocidas](#️-limitaciones-conocidas)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)
- [Disclaimer](#️-disclaimer)

---

## 🎯 Descripción

Script automatizado en Batch para **limpiar y proteger equipos de segunda mano** contra software espía, malware, acceso remoto no autorizado y puertas traseras. Diseñado para s que no pueden formatear inmediatamente su equipo pero necesitan protección mientras tanto.

### ⚠️ **Importante**
Este script es una **solución temporal**. La única forma de garantizar 100% la seguridad en un equipo de segunda mano es realizar un **formateo completo** y reinstalación limpia de Windows.

---

## ✨ Características

### 🔒 Protección Completa

- ✅ **Detección y eliminación de spyware** (50+ variantes comerciales y gratuitas)
- ✅ **Bloqueo de software de acceso remoto** (TeamViewer, AnyDesk, VNC, etc.)
- ✅ **Detección de backdoors y RATs** (30+ troyanos conocidos)
- ✅ **Deshabilitar servicios de rastreo** (telemetría de Windows incluida)
- ✅ **Bloqueo de puertos críticos** (27 puertos peligrosos)
- ✅ **Protección de privacidad** (cámara, micrófono, ubicación)
- ✅ **Limpieza de auto-inicio** (registro y carpetas de inicio)
- ✅ **Eliminación de tareas programadas sospechosas**
- ✅ **Bloqueo DNS** (100+ dominios maliciosos)
- ✅ **Análisis de red** (detección de conexiones sospechosas)
- ✅ **Auditoría de drivers** (identificación de drivers de monitoreo)

### 📊 Características Adicionales

- 🔄 **Punto de restauración automático** (antes de realizar cambios)
- 📝 **Logging detallado** (todas las acciones son registradas)
- 📁 **Backups automáticos** (registro y configuraciones)
- 📈 **Reporte ejecutivo** (resumen claro de amenazas encontradas)
- 🌐 **Navegación web preservada** (puertos 80/443 NO bloqueados)

---

## 💻 Requisitos

### Sistema Operativo
- Windows 10 (todas las versiones)
- Windows 11 (todas las versiones)
- Windows Server 2016+ (compatible pero no recomendado)

### Permisos
- ⚠️ **Permisos de Administrador** (obligatorio)

### Recursos
- 100 MB de espacio libre (para logs y backups)
- Conexión a Internet (opcional, para actualizaciones de firewall)

---

## 📥 Instalación

### Opción 1: Descarga directa

```bash
# Clonar el repositorio
git clone https://github.com/KevinGil12C/securelock
# Navegar al directorio
cd securelock
```

### Opción 2: Descarga manual

1. Descarga el archivo `SecureShield.bat`
2. Guárdalo en una carpeta de tu elección
3. **No ejecutes desde carpetas del sistema** (Documentos, Escritorio está bien)

---

## 🚀 Uso

### Ejecución Básica

1. **Cierra todos los programas** (navegadores, Office, etc.)
2. Guarda tu trabajo
3. **Clic derecho** en el archivo → **"Ejecutar como administrador"**
4. Lee las advertencias y presiona cualquier tecla
5. Espera 5-10 minutos (NO interrumpir)
6. Lee el reporte final

### Captura de pantalla

```
================================================
  LIMPIEZA TOTAL - EQUIPOS DE SEGUNDA MANO
  Version 3.1 - Proteccion Maxima
================================================

Este script eliminara:

[X] Software espia (spyware/keyloggers)
[X] Programas de monitoreo remoto
[X] Backdoors y puertas traseras
...
```

### Ejemplo de uso

```batch
# Ejecutar con privilegios elevados
runas /user:Administrator SecureShield.bat

# O simplemente:
# Clic derecho → Ejecutar como administrador
```

---

## 🔍 ¿Qué hace el script?

### Fase 1: Punto de Restauración
- Crea un punto de restauración del sistema
- Permite revertir cambios si algo sale mal

### Fase 2: Eliminación de Spyware
**Detecta y elimina:**
- FlexiSPY, mSpy, Hoverwatch, TheTruthSpy
- Keyloggers comerciales (Ardamax, Refog, SpyTech)
- Software de control parental malicioso
- Procesos camuflados como servicios del sistema

### Fase 3: Bloqueo de Acceso Remoto
**Termina y bloquea:**
- TeamViewer, AnyDesk, RustDesk
- VNC (TightVNC, RealVNC, UltraVNC)
- Chrome Remote Desktop
- LogMeIn, Splashtop, Ammyy
- 20+ herramientas de acceso remoto

### Fase 4: Detección de Backdoors
**Escanea:**
- RATs: NanoCore, njRAT, DarkComet, QuasarRAT
- Frameworks de pentesting: Metasploit, Cobalt Strike
- Herramientas de post-explotación
- 30+ variantes de troyanos

### Fase 5: Servicios Deshabilitados
**Deshabilita:**
- Escritorio Remoto (TermService)
- PowerShell Remoting
- WinRM (Windows Remote Management)
- Registro Remoto
- Telemetría de Windows (DiagTrack, dmwappushservice)
- Servicios SNMP y Telnet

### Fase 6: Bloqueo de Puertos
**Bloquea 27 puertos críticos:**

| Puerto | Servicio | Peligro |
|--------|----------|---------|
| 22 | SSH | Acceso remoto |
| 23 | Telnet | Acceso sin cifrar |
| 135 | RPC | Ataques de red |
| 139, 445 | SMB | Ransomware |
| 3389 | RDP | Acceso remoto |
| 5900-5901 | VNC | Acceso remoto |
| 4444, 5555 | RATs | Backdoors |

**✅ Mantiene abiertos:**
- Puerto 80 (HTTP)
- Puerto 443 (HTTPS)
- Puerto 8080, 8443 (alternos web)

### Fase 7: Limpieza de Auto-inicio
- Escanea registro de Windows
- Elimina entradas sospechosas
- Limpia carpetas de inicio
- **Crea backups antes de modificar**

### Fase 8: Tareas Programadas
**Elimina tareas relacionadas con:**
- Software de monitoreo
- Servicios de rastreo
- Control parental malicioso
- Actualizaciones de spyware

### Fase 9: Protección del Registro
**Aplica:**
- Bloqueo de carga de DLLs no autorizadas
- Deshabilita Windows Script Host
- Protege Task Manager y Registry Editor
- Deshabilita AutoRun de USBs
- Bloquea macros de Office
- Protege contra backdoor de Sticky Keys

### Fase 10: Privacidad Máxima
**Bloquea acceso a:**
- 📷 Cámara web
- 🎤 Micrófono
- 📍 Ubicación/GPS
- 🔍 Cortana y búsqueda web
- 📊 Historial de actividades
- 🎯 ID de publicidad

### Fase 11: Bloqueo DNS
**Bloquea 100+ dominios:**
- Software de acceso remoto
- Spyware comercial
- Keyloggers
- Control parental
- Rastreadores GPS
- Telemetría de Windows

### Fase 12: Análisis de Red
- Lista todas las conexiones activas
- Identifica conexiones sospechosas
- Detecta conexiones a Facebook/Meta
- Guarda snapshot completo de red

### Fase 13: Drivers Sospechosos
**Analiza drivers del sistema:**
- Busca patrones relacionados con monitoreo
- Lista blanca de drivers legítimos
- Exporta lista completa para auditoría

### Fase 14: Limpieza Profunda
**Elimina:**
- Archivos temporales
- Cache de navegadores
- Logs del sistema
- Prefetch de Windows

### Fase 15: Reporte Final
- Resumen ejecutivo de amenazas
- Estado de protección actual
- Recomendaciones personalizadas
- Archivos de auditoría generados

---

## 📁 Archivos Generados

El script crea una carpeta en el **Escritorio** llamada `LIMPIEZA_EQUIPO_AAAAMMDD/` con:

| Archivo | Descripción |
|---------|-------------|
| `REPORTE_FINAL.txt` | Resumen ejecutivo con recomendaciones |
| `log_completo.txt` | Log detallado de todas las acciones |
| `conexiones_activas.txt` | Conexiones de red al momento del escaneo |
| `conexiones_completas.txt` | Listado completo de puertos y conexiones |
| `drivers_sistema.csv` | Lista de todos los drivers instalados |
| `tareas_antes.txt` | Tareas programadas antes de la limpieza |
| `backup_run_user.reg` | Backup del registro de  |
| `backup_run_machine.reg` | Backup del registro del sistema |
| `hosts_backup.txt` | Backup del archivo hosts original |

---

## 🎯 Recomendaciones

### Después de Ejecutar el Script

#### 🔐 Seguridad Inmediata
1. **Cambiar TODAS las contraseñas**
   - Email personal y corporativo
   - Redes sociales
   - Banca en línea
   - Servicios de streaming
   - Cuentas de trabajo

2. **Habilitar autenticación de dos factores (2FA)**
   - Gmail, Outlook
   - Facebook, Twitter, Instagram
   - Servicios bancarios
   - Cuentas críticas de trabajo

3. **Revisar actividad reciente**
   - Transacciones bancarias
   - Inicios de sesión sospechosos
   - Cambios en configuraciones de cuentas

#### 🖥️ Sistema
1. **Escanear con antivirus**
   - Windows Defender (incluido en Windows)
   - Malwarebytes (recomendado como segundo escaneo)
   - Ejecutar en Modo Seguro para mayor efectividad

2. **Verificar programas instalados**
   ```
   Panel de Control → Programas → Desinstalar un programa
   ```
   - Buscar programas desconocidos
   - Desinstalar software sospechoso

3. **Revisar Task Manager periódicamente**
   - `Ctrl + Shift + Esc`
   - Pestaña "Procesos" y "Detalles"
   - Buscar procesos con alto uso de CPU/Red sin razón

#### 📅 Mantenimiento
1. **Ejecutar este script cada 15 días** (hasta formatear)
2. **Mantener Windows actualizado**
3. **Respaldar datos importantes** regularmente

#### 🎯 Plan a Fin de Año
1. Respaldar documentos importantes
2. Guardar contraseñas en gestor seguro
3. **Formatear completamente el equipo**
4. Reinstalar Windows desde cero
5. NO restaurar backups del sistema anterior

---

## ⚠️ Limitaciones Conocidas

### Servicios Bloqueados Legítimos

El script puede deshabilitar servicios que necesites:

| Servicio | Impacto | Solución |
|----------|---------|----------|
| Escritorio Remoto | No podrás usar RDP | Rehabilitar manualmente |
| PowerShell Remoting | Scripts remotos no funcionarán | Solo habilitar si es necesario |
| Telemetría de Windows | Diagnósticos limitados | Aceptable para privacidad |

### Software Afectado

Estos programas NO funcionarán después del script:
- ❌ TeamViewer
- ❌ AnyDesk
- ❌ VNC
- ❌ Chrome Remote Desktop
- ❌ Quick Assist

**Para rehabilitarlos:** Ejecuta los servicios manualmente desde `services.msc`

### Falsos Positivos Potenciales

El script puede detectar como sospechosos:
- Software de control parental legítimo
- Herramientas de administración corporativa
- Software de monitoreo empresarial autorizado

**Si esto ocurre:** Revisa el log y restaura desde los backups si es necesario

---

## 🔧 Troubleshooting

### Problema: "Se requieren permisos de administrador"

**Solución:**
```
1. Clic derecho en el archivo .bat
2. Seleccionar "Ejecutar como administrador"
3. Aceptar el control de cuentas de  (UAC)
```

### Problema: "No puedo navegar en internet después del script"

**Causa:** Versiones antiguas bloqueaban puerto 443

**Solución:**
```batch
# Ejecutar en CMD como administrador:
netsh advfirewall firewall delete rule name="BLOCK_443"
netsh advfirewall firewall delete rule name="BLOCK_80"
```

O descargar la **versión 3.1** que corrige esto automáticamente.

### Problema: "Mi antivirus detecta el script como malware"

**Causa:** Falso positivo por las acciones del script

**Explicación:** 
- El script modifica registro y servicios
- Algunos antivirus detectan esto como comportamiento malicioso
- Es un **falso positivo**

**Solución:**
1. Agregar excepción en el antivirus
2. Revisar el código fuente (es open source)
3. Ejecutar en entorno controlado primero

### Problema: "Se deshabilitó algo que necesito"

**Solución:**
```
1. Abrir servicios: Win + R → services.msc
2. Buscar el servicio deshabilitado
3. Clic derecho → Propiedades
4. Tipo de inicio: Automático
5. Clic en "Iniciar"
```

O restaurar desde el **punto de restauración** creado.

### Problema: "Spyware detectado: 71"

**Causa:** Bug en versiones antiguas (v3.0 y anteriores)

**Explicación:** Falsos positivos con procesos del sistema

**Solución:** Actualizar a **versión 3.1+**

---

## ❓ FAQ

### ¿Es seguro usar este script?

✅ **Sí.** El script:
- Es código abierto (puedes revisarlo)
- Crea punto de restauración antes de cambios
- Genera backups de todas las modificaciones
- Solo usa comandos nativos de Windows

### ¿Sustituye a un formateo?

❌ **No.** Este script es una solución **temporal**. Para seguridad 100%, siempre formatea equipos de segunda mano.

### ¿Afectará el rendimiento del equipo?

✅ **Puede mejorarlo.** Al deshabilitar telemetría y servicios innecesarios, algunos equipos se vuelven más rápidos.

### ¿Funciona con Windows 7?

⚠️ **Parcialmente.** El script está diseñado para Windows 10/11. Algunas funciones pueden no funcionar en Windows 7.

### ¿Puedo revertir los cambios?

✅ **Sí.** Tienes 3 opciones:
1. Usar el punto de restauración creado
2. Importar los archivos `.reg` de backup
3. Rehabilitar servicios manualmente

### ¿Detecta todos los spyware?

❌ **No al 100%.** Detecta los más comunes (50+ variantes), pero spyware personalizado o muy nuevo puede pasar desapercibido.

### ¿Necesito antivirus adicional?

✅ **Recomendado.** Windows Defender es suficiente para uso básico, pero para equipos de segunda mano considera:
- Malwarebytes (escaneo adicional)
- Kaspersky/Bitdefender (protección avanzada)

### ¿Con qué frecuencia debo ejecutarlo?

📅 **Cada 15 días** hasta que puedas formatear el equipo.

### ¿Funciona en equipos corporativos?

⚠️ **Con precaución.** Puede deshabilitar herramientas de administración legítimas. Consulta con TI antes de ejecutar.

---

## 🤝 Contribuir

Las contribuciones son bienvenidas. Para contribuir:

### Reportar Bugs

1. Abre un [Issue](https://github.com/KevinGil12C/securelock/issues)
2. Describe el problema detalladamente
3. Incluye:
   - Versión de Windows
   - Versión del script
   - Log completo (si es posible)
   - Pasos para reproducir

### Sugerir Mejoras

1. Abre un [Issue](https://github.com/KevinGil12C/securelock/issues) con la etiqueta `enhancement`
2. Describe la funcionalidad deseada
3. Explica el caso de uso

### Enviar Pull Request

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Guía de Estilo

- Usa comentarios claros en español
- Mantén la compatibilidad con Windows 10/11
- Documenta nuevas funciones
- Actualiza el README si es necesario

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

```
MIT License

Copyright (c) 2025 KevinGil12C

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia
de este software y archivos de documentación asociados (el "Software"), para
utilizar el Software sin restricción...
```

---

## ⚖️ Disclaimer

### ⚠️ IMPORTANTE - LEER ANTES DE USAR

Este script se proporciona **"TAL CUAL"**, sin garantías de ningún tipo. El uso de este script es bajo tu propio riesgo.

### Limitaciones

- ❌ **NO garantiza** detectar todo el malware
- ❌ **NO sustituye** un formateo completo
- ❌ **NO reemplaza** software antivirus profesional
- ⚠️ Puede deshabilitar servicios legítimos
- ⚠️ Puede afectar funcionalidad de software corporativo

### Responsabilidad

El autor **NO se hace responsable** de:
- Pérdida de datos
- Daños al sistema operativo
- Problemas de compatibilidad
- Servicios deshabilitados accidentalmente
- Uso indebido del script

### Recomendaciones Legales

- ✅ Solo usa en equipos de tu propiedad
- ✅ Obtén autorización antes de usar en equipos corporativos
- ✅ Respeta las políticas de TI de tu organización
- ✅ Respalda datos importantes antes de ejecutar

### Uso Ético

Este script está diseñado para **protección legítima**. NO debe usarse para:
- ❌ Evadir controles de seguridad corporativos
- ❌ Ocultar actividad maliciosa
- ❌ Interferir con sistemas de terceros
- ❌ Violar términos de servicio

---

## 📞 Soporte

### Comunidad

- 💬 [Discusiones](https://github.com/KevinGil12C/securelock/discussions)
- 🐛 [Reportar Bug](https://github.com/KevinGil12C/securelock/issues)
- 📧 Email: tu-email@ejemplo.com

### Recursos Adicionales

- 📖 [Wiki del Proyecto](https://github.com/KevinGil12C/securelock/wiki)
- 🎥 [Video Tutorial](https://youtube.com/...)
- 📝 [Blog Post](https://tu-blog.com/...)

---

## 🙏 Agradecimientos

- Microsoft por la documentación de Windows
- Comunidad de seguridad informática
- Todos los contribuidores del proyecto

---

## 📊 Estadísticas

![GitHub Stars](https://img.shields.io/github/stars/KevinGil12C/securelock?style=social)
![GitHub Forks](https://img.shields.io/github/forks/KevinGil12C/securelock?style=social)
![GitHub Issues](https://img.shields.io/github/issues/KevinGil12C/securelock)
![GitHub Pull Requests](https://img.shields.io/github/issues-pr/KevinGil12C/securelock)

---

## 🗺️ Roadmap

### v3.2 (Próximamente)
- [ ] Interfaz gráfica (GUI)
- [ ] Modo silencioso
- [ ] Escaneo programado
- [ ] Integración con Windows Defender

### v4.0 (Futuro)
- [ ] Detección con IA
- [ ] Base de datos de malware actualizable
- [ ] Modo de red (múltiples equipos)
- [ ] Reportes HTML

---

<div align="center">

### ⭐ Si este proyecto te fue útil, considera darle una estrella

### 🔒 Mantente seguro - Formatea cuando puedas

**Hecho con ❤️ para la comunidad de seguridad informática**

[⬆ Volver arriba](#-securelock)

</div>
