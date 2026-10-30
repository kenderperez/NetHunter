# 🕸️ NetHunter v4 --- Network Tree Scanner + RTSP Camera Detection

> Escáner de red con descubrimiento L2/L3/ICMP, clasificación automática
> de dispositivos, detección de cámaras IP RTSP y **reproducción de
> video en vivo** directamente desde el navegador.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

------------------------------------------------------------------------

## 📸 Vista general

NetHunter v4 descubre todos los dispositivos de tu red, los clasifica
(PC, móvil, impresora, router, **cámara IP**...), y genera una topología
interactiva en el navegador. Al hacer click sobre cualquier nodo, se
lanza un **SYN scan paralelo** de los 65535 puertos (5-10 segundos) y se
identifican los servicios con sus versiones.

Si el dispositivo es una **cámara RTSP**, aparece un botón **"🎥 Ver en
vivo"** que abre una ventana nueva con el stream en tiempo real (RTSP →
MJPEG vía FFmpeg).

------------------------------------------------------------------------

## 📑 Índice

-   [Características](#-características)
-   [Requisitos](#-requisitos)
-   [Instalación](#-instalación)
-   [Uso del escáner](#-uso-del-escáner)
-   [Uso del emulador de cámara](#-uso-del-emulador-de-cámara)
-   [Ejemplos completos paso a paso](#-ejemplos-completos-paso-a-paso)
-   [Arquitectura](#️-arquitectura)
-   [Seguridad](#-seguridad)
-   [Aviso legal](#️-aviso-legal)
-   [Troubleshooting](#-troubleshooting)
-   [Roadmap](#️-roadmap)
-   [Contribuir](#-contribuir)
-   [Licencia](#-licencia)
-   [Créditos](#-créditos)

------------------------------------------------------------------------

## ✨ Características

### Descubrimiento de red

-   **L2 (ARP)** --- descubrimiento rápido de hosts en la misma subred.
-   **L3 (TCP SYN)** --- detección de hosts en subredes enrutadas.
-   **ICMP (Echo)** --- ping sweep con spoofing L2.
-   **Single-target L3** --- escaneo de IPs públicas, privadas o
    dominios (con resolución DNS).
-   **Resolución de vendor** --- MAC lookup con `mac-vendor-lookup`,
    `scapy` y `api.macvendors.com` como fallback.
-   **Hostname discovery** --- DNS reverso, NetBIOS, mDNS y `<title>`
    HTTP.

### Escaneo de puertos

-   **SYN scan paralelo** --- 12 workers × chunks de 1500, cubre los
    65535 puertos en 5-10s.
-   **Fallback connect_ex** --- si no hay MAC o fallan los raw sockets.
-   **Verificación cruzada** --- segunda pasada sobre puertos críticos
    (554, 8554, 9100, 631...).
-   **Identificación de servicios** --- banners, versiones, TLS, SMB,
    SMTP, MySQL, Redis, VNC, DNS, NTP, RTSP.

### Detección y streaming RTSP

-   **Detección automática** --- escaneo de puertos 554 y 8554.
-   **Detección de paths** --- prueba automática de paths comunes
    (Hikvision, Dahua, ONVIF, genéricos) vía `DESCRIBE`.
-   **Reproducción en vivo** --- RTSP → MJPEG vía FFmpeg, sesiones
    tokenizadas.
-   **Ventana emergente dedicada** --- botón "🎥 Ver en vivo (ventana
    nueva)" para cámaras.
-   **Anti-SSRF** --- validación estricta de URL, host, puerto y
    dispositivo antes de invocar FFmpeg.

### Interfaz web

-   **Topología interactiva** con `vis-network` (jerárquica, auto-fit,
    búsqueda).
-   **Panel de detalles** con puertos abiertos, servicios, versiones y
    banners.
-   **WebSockets** --- resultados en tiempo real conforme avanza el
    escaneo.
-   **Clasificación visual** --- iconos y colores por tipo de
    dispositivo (📷 cámara, 🖨️ impresora, 🌐 router, 🐧 Linux, 🪟
    Windows...).

------------------------------------------------------------------------

## 🧩 Requisitos

### Software

-   **Python 3.8+**
-   **FFmpeg** (para el streaming RTSP y el emulador de test) --- debe
    estar en `PATH`.

### Dependencias Python

\`\`\`bash pip install scapy flask flask-socketio mac-vendor-lookup
Privilegios Linux/macOS: sudo (necesario para raw sockets y ARP).

Windows: Ejecutar como Administrador (para Npcap / raw sockets).

Npcap en Windows Si usás Windows, instalá Npcap (viene con Wireshark)
con la opción "Install Npcap in WinPcap API-compatible Mode".

🚀 Instalación bash \# 1. Clonar el repositorio git clone
https://github.com/tu-usuario/nethunter.git cd nethunter

# 2. Instalar dependencias

pip install scapy flask flask-socketio mac-vendor-lookup

# 3. Verificar FFmpeg

ffmpeg -version 📖 Uso del escáner Sintaxis general bash python
net_hunterv4.py \[target\] \[opciones\] Opción Descripción Default
target IP, CIDR o dominio 10.0.9.1 -l2 / --layer2 Forzar descubrimiento
por ARP auto -l3 / --layer3 Forzar descubrimiento por TCP SYN auto -icmp
/ --icmp Forzar descubrimiento por ICMP auto -s / --single Modo
single-target (IP pública o DNS) off -p / --ports Puertos a probar en L3
(22,80,443) 80,443,22,445,3389,8080 -t / --timeout Timeout de scan
(segundos) 2.0 --no-browser No abrir el navegador off --web-port Puerto
del servidor Flask 5000 --no-dns Omitir resolución de hostname off
--workers Workers paralelos del SYN scan 12 --ffmpeg Ruta a FFmpeg
ffmpeg Ejemplos de uso del escáner 1. Escanear toda la red local (modo
más común) bash \# Linux/macOS sudo python net_hunterv4.py
192.168.1.0/24

# Windows (como Administrador)

python net_hunterv4.py 192.168.1.0/24 Qué hace:

ARP sweep en toda la subred.

TCP SYN a los puertos por defecto en cada host vivo.

Clasificación automática de dispositivos.

Abre automáticamente el navegador en http://127.0.0.1:5000/.

2.  Escanear un solo host (interactivo desde el navegador) bash sudo
    python net_hunterv4.py 192.168.1.50 -s Qué hace:

Abre el navegador con un nodo único representando 192.168.1.50.

El panel se abre solo y lanza el SYN scan 1-65535 en background.

Si detecta RTSP, aparece el banner de cámara + botón "Ver en vivo".

3.  Escanear un dominio remoto (solo consola, sin navegador) bash sudo
    python net_hunterv4.py midominio.com -s --no-browser Salida
    esperada:

# text

NETWORK TREE SCANNER --- SINGLE TARGET (L3 CLI) Target: midominio.com
IP: 203.0.113.42 DNS: midominio.com → 203.0.113.42 Workers: 12
============================================================ \[\*\]
Escaneo completo 1-65535 \[\*\] Fase 1: descubriendo puertos abiertos en
203.0.113.42... connect_ex: 8 abiertos en 12.4s \[\*\] Fase 1
completada: 8 puertos abiertos en 18.2s \[\*\] Fase 2: identificando
servicios y versiones...
============================================================ RESULTADOS
--- 203.0.113.42 (midominio.com)
============================================================ PUERTO
SERVICIO VERSIÓN / BANNER
------------------------------------------------------------ 22 SSH
SSH-2.0-OpenSSH_8.9p1 80 HTTP HTTP/1.1 301 \| nginx/1.18.0 443 HTTPS
TLSv1.3 \| cipher=... 3306 MySQL 8.0.32 ... 4. Escanear con más workers
(red grande, más rápido) bash sudo python net_hunterv4.py 10.0.0.0/16
--workers 30 5. Escanear solo con ARP (rápido, mismo segmento) bash sudo
python net_hunterv4.py 192.168.1.0/24 -l2 6. Escanear puertos
específicos en L3 bash sudo python net_hunterv4.py 192.168.1.50 -l3 -p
22,80,554,8554,8080 7. Sin resolución DNS (más rápido en redes grandes)
bash sudo python net_hunterv4.py 10.0.0.0/16 --no-dns 8. En puerto web
alternativo bash sudo python net_hunterv4.py 192.168.1.0/24 --web-port
8080 9. Sin abrir el navegador automáticamente bash sudo python
net_hunterv4.py 192.168.1.0/24 --no-browser \# Abrí manualmente:
http://127.0.0.1:5000/ 10. FFmpeg en ruta personalizada (Windows)
powershell python net_hunterv4.py 192.168.1.0/24 --ffmpeg
"C:`\ffmpeg`{=tex}`\bin`{=tex}`\ffmpeg`{=tex}.exe" Interfaz web (una vez
abierta) Topología --- todos los dispositivos se muestran como nodos
conectados al gateway.

Búsqueda --- barra superior con filtro por IP/host.

Click en un nodo --- abre el panel de detalles:

Estado del SYN scan en tiempo real.

Lista de puertos abiertos.

Botón "🔍 Descubrir servicios y versiones".

Si es cámara: banner naranja con botón "🎥 Ver en vivo".

🎥 Uso del emulador de cámara El repositorio incluye
rtsp_camera_emulator.py, un emulador de cámara IP que levanta un
servidor RTSP real (Mediamtx) y publica un video de prueba (testsrc2).

Sintaxis general bash python rtsp_camera_emulator.py \[opciones\] Opción
Descripción Default --port Puerto RTSP 8554 --resolution Resolución del
stream 1280x720 --fps Frames por segundo 25 --bitrate Bitrate de video
1500k Ejemplos de uso del emulador 1. Emulador básico (puerto 8554) bash
python rtsp_camera_emulator.py Salida esperada:

# text

# 🎥 RTSP CAMERA EMULATOR

\[\*\] mediamtx ya presente en .rtsp_emulator/mediamtx.exe \[\*\] Config
escrito en .rtsp_emulator/mediamtx.yml \[\*\] Iniciando mediamtx en
:8554... \[\*\] mediamtx LISTO en rtsp://0.0.0.0:8554 \[\*\] Iniciando
FFmpeg (stream de prueba)... \[\*\] Esperando que FFmpeg publique en
rtsp://127.0.0.1:8554/stream1...

============================================================ ✅ EMULADOR
DE CÁMARA RTSP ACTIVO
============================================================ Puerto:
8554 Resolución: 1280x720 @ 25fps IP local: 192.168.1.100

URLs RTSP funcionales: rtsp://127.0.0.1:8554/stream1
rtsp://192.168.1.100:8554/stream1

Ctrl+C para detener. 2. Emular cámara real en puerto 554 (requiere
root/admin) bash \# Linux/macOS sudo python rtsp_camera_emulator.py
--port 554

# Windows (como Administrador)

python rtsp_camera_emulator.py --port 554 3. Stream Full HD a 30fps bash
python rtsp_camera_emulator.py --resolution 1920x1080 --fps 30 --bitrate
3000k 4. Puerto alternativo (si 8554 está ocupado) bash python
rtsp_camera_emulator.py --port 8555 ⚠️ Nota: el scanner solo detecta
RTSP en los puertos 554 y 8554. Si usás otro puerto, tendrás que ajustar
RTSP_PORTS en el código o el scanner no lo reconocerá como cámara.

🧪 Ejemplos completos paso a paso Ejemplo A --- Testear la detección
RTSP de punta a punta (más fácil) Este es el flujo completo para
verificar que todo funciona correctamente.

Paso 1 --- Abrir Terminal 1 e iniciar el emulador:

bash python rtsp_camera_emulator.py Esperá a ver ✅ EMULADOR DE CÁMARA
RTSP ACTIVO.

Paso 2 --- Abrir Terminal 2 y escanear el emulador con el scanner:

bash \# Linux/macOS sudo python net_hunterv4.py 127.0.0.1 -s

# Windows (Administrador)

python net_hunterv4.py 127.0.0.1 -s Paso 3 --- En el navegador que se
abrió automáticamente:

Click en el nodo 127.0.0.1.

Esperá 5-10s a que termine el SYN scan.

Aparece el banner naranja "📷 Cámara CCTV detectada".

Click en "🎥 Ver en vivo (ventana nueva)".

Se abre una ventana con el patrón animado testsrc2 en vivo.

Paso 4 --- Cerrá la ventana emergente para detener el stream (FFmpeg se
mata automáticamente).

Paso 5 --- Ctrl+C en ambas terminales para limpiar.

Ejemplo B --- Testear desde otra PC en la misma red Máquina A (donde
corre el emulador):

bash python rtsp_camera_emulator.py --port 554 Anotá la IP local que
imprime el emulador (por ejemplo 192.168.1.100).

Máquina B (donde corre el scanner):

bash sudo python net_hunterv4.py 192.168.1.0/24 En el navegador:

Buscá el nodo 192.168.1.100 (o usá el buscador).

Debería aparecer con icono 📷 y badge CAMERA desde el inicio.

Click en el nodo → banner de cámara → "Ver en vivo".

Ejemplo C --- Escanear una red corporativa completa bash sudo python
net_hunterv4.py 10.0.0.0/16 --workers 30 --no-dns 10.0.0.0/16 → 65534
direcciones a escanear.

--workers 30 → 30 hilos paralelos por host (más rápido, más carga).

--no-dns → sin resolución reversa (ahorra tiempo).

En el navegador, usá el buscador para filtrar por tipo de dispositivo
(ej. escribir 192.168.5. para filtrar).

Ejemplo D --- Auditar un host público específico bash sudo python
net_hunterv4.py target.example.com -s --no-browser -p
22,80,443,3306,5432,6379 Salida esperada en consola:

text \[\*\] Fase 1: descubriendo puertos abiertos en 203.0.113.42...
connect_ex: 4 abiertos en 2.1s \[\*\] Fase 2: identificando servicios y
versiones (4 puertos)... 22 SSH SSH-2.0-OpenSSH_8.9p1 Ubuntu-3 80 HTTP
HTTP/1.1 301 Moved Permanently \| nginx/1.18.0 443 HTTPS TLSv1.3 \|
cipher=TLS_AES_256_GCM_SHA384 \| CN=... 3306 MySQL
8.0.32-0ubuntu0.22.04.1 Ejemplo E --- Escaneo rápido solo ARP (solo
misma subred) bash sudo python net_hunterv4.py 192.168.1.0/24 -l2
--no-browser Solo hace ARP sweep (muy rápido, \~2s).

No hace SYN L3 ni ICMP.

Ideal para inventarios rápidos de red local.

Ejemplo F --- Combinación personalizada L3 + ICMP bash sudo python
net_hunterv4.py 192.168.1.0/24 -l3 -icmp -p 80,443,554,8554 L3 → solo
TCP SYN sobre puertos 80,443,554,8554.

ICMP → ping sweep adicional.

Sin ARP (útil si estás en otra subred enrutada).

Ejemplo G --- Testear varias cámaras emuladas a la vez Terminal 1:

bash python rtsp_camera_emulator.py --port 8554 Terminal 2:

bash sudo python rtsp_camera_emulator.py --port 554 --resolution 640x480
--fps 15 Terminal 3:

bash sudo python net_hunterv4.py 127.0.0.1 -s El scanner detectará ambos
puertos (554 y 8554) como RTSP y ofrecerá reproducirlos.

🏗️ Arquitectura text
┌──────────────────────────────────────────────────────────────┐ │
Navegador │ │ ┌─────────────────────┐ ┌──────────────────────────┐ │ │ │
Topología vis.js │ │ Panel de detalles │ │ │ │ (nodos + edges) │ │
(puertos, servicios) │ │ │ └─────────────────────┘
└──────────────────────────┘ │ │ ▲ WebSocket ▲ HTTP │
└────────────┼──────────────────┼──────────────────────────────┘ │ │
┌────────────┼──────────────────┼──────────────────────────────┐ │ │
Flask + SocketIO│ │ │ ┌─────────┴──────────┐
┌────┴──────────────────────┐ │ │ │ /api/topology │ │ /api/stream/start
│ │ │ │ /api/debug │ │ /api/stream/`<id>`{=html} │ │ │
└─────────┬──────────┘ │ /stream-popup/`<id>`{=html} │ │ │ │
└─────────┬─────────────────┘ │ │ ┌─────────▼──────────┐
┌─────────▼─────────────────┐ │ │ │ Discovery │ │ FFmpeg subprocess │ │
│ │ - ARP sweep │ │ RTSP → MJPEG │ │ │ │ - TCP SYN L3 │ │ (streams
tokenizados) │ │ │ │ - ICMP sweep │ └───────────────────────────┘ │ │
└─────────┬──────────┘ │ │ ┌─────────▼──────────┐
┌───────────────────────────┐ │ │ │ SYN scan paralelo │ │ Probes │ │ │ │
1-65535 / 5-10s │ │ HTTP, SSH, SMB, RTSP... │ │ │ └────────────────────┘
└───────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘ │ ▼
┌───────────────────┐ │ Red objetivo │ │ 192.168.x.0/24 │
└───────────────────┘ Flujo de descubrimiento de una cámara Discovery
inicial → ARP sweep + TCP SYN L3 + ICMP → lista de IPs + MACs.

Clasificación paralela → 90+ puertos comunes por dispositivo.

Detección RTSP → OPTIONS + DESCRIBE sobre puertos 554/8554 → paths
detectados.

Clasificación → badge CAMERA, icono 📷, borde rojo.

Click en el nodo → panel con banner de cámara + botón "Ver en vivo".

SYN scan completo → puertos adicionales si se necesitan.

Ver en vivo → /api/stream/start → FFmpeg → MJPEG → `<img>`{=html} en la
ventana emergente.

🔒 Seguridad Anti-SSRF --- antes de lanzar FFmpeg, se valida:

URL válida (rtsp://host:port/path).

Host resoluble y perteneciente a un dispositivo ya detectado en el scan.

Puerto abierto en el dispositivo (evita usar el scanner como proxy).

Respuesta RTSP real (OPTIONS) antes de iniciar FFmpeg.

Sesiones tokenizadas --- cada stream tiene un stream_id único
(secrets.token_urlsafe(24)).

Sin comandos shell --- FFmpeg se invoca con subprocess.Popen y lista de
argumentos (no shell=True).

Sanitización de JSON --- validación de tipos y longitudes máximas.

⚠️ Aviso legal Este proyecto es solo para uso educativo y de auditoría
autorizada.

Escanear redes sin autorización explícita del propietario es ilegal en
la mayoría de las jurisdicciones. El autor no se hace responsable del
uso indebido de esta herramienta. Usalo únicamente en:

Redes propias.

Redes de laboratorio / test.

Entornos donde tengas permiso escrito del administrador.

El acceso a cámaras IP ajenas puede violar leyes de privacidad (GDPR,
CFAA, etc.).

🐛 Troubleshooting Permission denied al hacer SYN scan Linux/macOS: sudo
python net_hunterv4.py ...

Windows: abrir PowerShell/CMD como Administrador.

No module named scapy bash pip install scapy mac-vendor-lookup NO
instalado bash pip install mac-vendor-lookup (Opcional --- el scanner
funciona sin él usando OUI manual + API online.)

El navegador no muestra video Verificá que FFmpeg esté en PATH (ffmpeg
-version).

Probá cambiar el path RTSP con los "chips" del panel (algunas cámaras
usan /Streaming/Channels/101, otras
/cam/realmonitor?channel=1&subtype=0).

Si la cámara requiere autenticación, editá la URL:
rtsp://usuario:pass@IP:554/path.

El emulador RTSP no arranca Error: json: unknown field "rtspTransports"

La versión v1.9.3 de MediaMTX no soporta ese campo.

Solución: eliminá la línea rtspTransports: \[tcp, udp\] del archivo
.rtsp_emulator/mediamtx.yml.

Error: must have 'sourceOnDemand' set to true

Solución: añadí sourceOnDemand: yes al bloque all_others en
.rtsp_emulator/mediamtx.yml.

Revisá también:

.rtsp_emulator/mediamtx.log

.rtsp_emulator/ffmpeg.log

El navegador bloquea la ventana emergente Permití popups para
127.0.0.1:5000 (o tu puerto) en la configuración del navegador.

El puerto 5000 ya está en uso (macOS) En macOS, el puerto 5000 lo usa
AirPlay Receiver.

Solución: usá otro puerto, ej. --web-port 8000.

No se detectan cámaras aunque existan Verificá que los puertos 554 y
8554 estén abiertos en la cámara.

Probá con sudo (algunas cámaras requieren raw sockets para OPTIONS).

Aumentá el timeout: -t 5.

🗺️ Roadmap □ Export de topología a PNG / SVG / JSON. □ Detección de
cámaras vía ONVIF (WS-Discovery). □ Grabación de streams RTSP a archivo.
□ Autenticación básica en el panel web. □ Docker compose para levantar
scanner + emulador. □ Soporte para IPv6. 🤝 Contribuir ¡PRs y issues son
bienvenidos!

Forkeá el proyecto.

Creá una rama: git checkout -b feature/nueva-funcionalidad.

Commiteá: git commit -m "Add: nueva funcionalidad".

Pusheá: git push origin feature/nueva-funcionalidad.

Abrí un Pull Request.

📄 Licencia Distribuido bajo la licencia MIT:

text MIT License

Copyright (c) 2025 `<TU NOMBRE>`{=html}

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 🙏 Créditos Scapy
--- crafting de paquetes.

Flask + Flask-SocketIO --- backend web y WebSockets.

vis-network --- topología interactiva.

Mediamtx --- servidor RTSP para testing.

FFmpeg --- transcoding RTSP → MJPEG.

mac-vendor-lookup --- vendor database.

⭐ ¿Te sirvió? Dejá una estrella en el repo --- ayuda mucho a que más
gente lo encuentre.

Hecho con ☕ y 🐍 por \[tu-nombre\]
