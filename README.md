# 🛡️ Analizador de Hardening Cisco

> Herramienta web para analizar configuraciones de dispositivos Cisco (routers, switches) y detectar posibles vulnerabilidades o malas prácticas de seguridad. Ideal para auditorías internas, cumplimiento CIS y mejora continua de la postura de seguridad de redes.

---

## 📌 Descripción

Esta herramienta permite subir un archivo de configuración (`show running-config` o `.cfg`) desde un dispositivo Cisco y realiza un análisis automatizado basado en buenas prácticas de seguridad y estándares reconocidos como el **CIS Benchmark para Cisco IOS**.

Una vez cargada la configuración, el sistema muestra:
- Hallazgos organizados por nivel de gravedad (Alta, Media, Baja)
- Recomendaciones claras con comandos sugeridos
- Gráficos visuales del estado de seguridad
- Informe exportable en PDF, JSON y CSV

---

## 🔍 Características actuales

✅ Análisis de:
- Contraseñas débiles o mal cifradas
- Uso de Telnet (recomienda migrar a SSH v2)
- Configuración segura de SSH (clave RSA, versión 2)
- Autenticación centralizada con RADIUS/TACACS+
- Configuración de usuarios locales y privilegios mínimos
- Interfaces físicas no utilizadas
- Configuración de VLANs por defecto
- Timeout de sesiones VTY y consola
- Servicios innecesarios activos
- Configuración de NTP segura
- Cifrado de contraseñas (`service password-encryption`)
- Bloqueo automático tras múltiples intentos fallidos de login
- Y más...

📄 Exportaciones disponibles:
- 📄 PDF con diseño profesional
- 🧾 JSON estructurado
- 📊 CSV para importar en Excel u otras herramientas

📊 Visualizaciones:
- Gráfico de hallazgos por gravedad (con Chart.js)

---

## 🚀 Requisitos previos

No se requiere instalación ni servidor backend. Solo necesitas:

- Un navegador web moderno (Chrome, Firefox, Edge)
- Un archivo de configuración Cisco (.txt o .cfg), típicamente obtenido mediante:
  ```bash
  show running-config
