<p align="center">
  <img src="https://i.imgur.com/k2k75dS.png" alt="NetHunter Logo" width="450">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/license-GNU%20GPLv3-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/status-stable-brightgreen" alt="Status">
</p>

---

# 🎯 Network Tree Scanner (NetHunter)

Escáner de red interactivo con visualización de topología en el navegador en tiempo real (`vis-network`), descubrimiento de dispositivos en Capa 2 / Capa 3 (`Scapy`), identificación de servicios y reproductor en vivo para cámaras **CCTV / RTSP** integrado vía `FFmpeg`.

<p align="center">
  <img src="https://i.imgur.com/B5FQLHD.png" alt="NetHunter" width="1200">
</p>

## 🚀 Requisitos Previos

* **Python 3.8+**
* **Privilegios de Administrador / Root** (necesarios para enviar paquetes *raw* con Scapy).
* **FFmpeg** *(opcional, solo para ver streaming de cámaras RTSP en el navegador)*.

### Instalar FFmpeg

* **Windows:** Descargar de [ffmpeg.org](https://ffmpeg.org/download.html) y agregar la carpeta `bin` al PATH del sistema.
* **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt update && sudo apt install ffmpeg
  ```
* **macOS:**
  ```bash
  brew install ffmpeg
  ```

## 📦 Instalación

1. Clona este repositorio o descarga los archivos.
2. Instala las dependencias requeridas:

```bash
pip install scapy flask flask-socketio mac-vendor-lookup
```

### Tabla de Dependencias

| Paquete | Uso Principal |
| ----- | ----- |
| **`scapy`** | Barridos ARP, escaneo TCP SYN e ICMP Echo |
| **`flask`** | Servidor web local para la interfaz gráfica |
| **`flask-socketio`** | Comunicación en tiempo real (escaneos de puertos y servicios) |
| **`mac-vendor-lookup`** | Identificación de fabricantes por MAC OUI |

> 🎨 **Logotipo en la interfaz:** Coloca una imagen llamada `logo_nethunter.png` en la misma carpeta del script si deseas que aparezca en la barra superior.

## ⚡ Guía Rápida de Uso

Para ejecutar **NetHunter**, abre una consola con privilegios elevados y utiliza el script `net_hunter.py`:

```bash
python net_hunter.py [target] [opciones]
```

### 🔹 1. Escanear toda la red local (Modo por defecto)

Analiza la subred local completa, descubre dispositivos por ARP + TCP SYN y abre automáticamente el navegador con el mapa interactivo:

* **Linux / macOS:**
  ```bash
  sudo python net_hunter.py 192.168.1.0/24
  ```
* **Windows (Terminal de Administrador):**
  ```cmd
  python net_hunter.py 192.168.1.0/24
  ```

### 🔹 2. Escanear un objetivo único (Single Target)

Escanea una IP (pública/privada) o un nombre de dominio por Capa 3 y abre la interfaz web enfocada en ese dispositivo:

```bash
sudo python net_hunter.py -s 192.168.1.50
```

Para ver los resultados directamente en la consola de comandos sin abrir el navegador:

```bash
sudo python net_hunter.py -s --no-browser 8.8.8.8
```

## 🛠️ Opciones y Flags Disponibles

| Flag | Alias | Descripción | Valor por Defecto |
| ----- | ----- | ----- | ----- |
| `target` | — | Objetivo a escanear (IP, CIDR, rango o DNS). | `10.0.9.1` |
| `-l2` | `--layer2` | Descubrimiento por ARP (Capa 2). | Activo por defecto |
| `-l3` | `--layer3` | Descubrimiento por TCP SYN (Capa 3). | Activo por defecto |
| `-icmp` | `--icmp` | Descubrimiento por pings ICMP Echo. | Inactivo |
| `-s` | `--single` | Modo *Single Target* (IP o DNS individual). | Inactivo |
| `-p` | `--ports` | Lista de puertos para L3 (ej: `22,80,443,554`). | `80,443,22,445,3389,8080` |
| `-t` | `--timeout` | Tiempo de espera (segundos) para respuestas L3/ICMP. | `2.0` |
| `--workers` | — | Hilos paralelos para el escaneo de puertos SYN. | `12` |
| `--no-browser` | — | Deshabilita la apertura automática del navegador. | Inactivo |
| `--no-dns` | — | Deshabilita la resolución de nombres (escaneo más rápido). | Inactivo |
| `--web-port` | — | Puerto donde se inicia la interfaz web. | `5000` |
| `--ffmpeg` | — | Ruta personalizada al ejecutable de FFmpeg. | `ffmpeg` |

## 💡 Ejemplos Prácticos

* **Inventario rápido en Capa 2 (solo ARP):**
  ```bash
  sudo python net_hunter.py 192.168.1.0/24 -l2
  ```

* **Escaneo con puertos personalizados:**
  ```bash
  sudo python net_hunter.py 192.168.1.0/24 -l3 -p 22,80,443,554,8554
  ```

* **Ruta personalizada de FFmpeg (Windows):**
  ```cmd
  python net_hunter.py -s 192.168.1.60 --ffmpeg "C:\ffmpeg\bin\ffmpeg.exe"
  ```

## 📹 Visualización de Cámaras RTSP / CCTV

1. Ejecuta el escaneo sobre la red o una IP de cámara específica (`-s`).
2. Haz clic sobre el nodo de la cámara (**📷**) en el mapa para abrir el panel de detalles.
3. **NetHunter** probará automáticamente rutas RTSP comunes (Hikvision, Dahua, ONVIF, etc.).
4. Presiona el botón **`🎥 Ver en vivo`**.
5. *Nota sobre credenciales:* Si la cámara requiere contraseña, edita la URL en la interfaz añadiendo `usuario:password@` antes de la IP:
   ```text
   rtsp://admin:12345@192.168.1.60:554/Streaming/Channels/101
   ```

## 📜 Licencia

Este proyecto está distribuido bajo la Licencia **GNU General Public License v3.0 (GPL-3.0)**.
