#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Tree Scanner - Scapy + vis-network
Uso: python net_tree.py [target] [-l2] [-l3] [-icmp] [opciones]

Instalación recomendada:
  pip install scapy flask flask-socketio mac-vendor-lookup
  Instala FFmpeg en el sistema y asegúrate de que esté en PATH para ver streams RTSP.

Mejoras incluidas:
  - Detección automática de paths RTSP (Hikvision, Dahua, ONVIF, genéricos).
  - Streaming RTSP → MJPEG vía FFmpeg con sesiones tokenizadas.
  - Validación estricta de URL/host/puerto antes de lanzar FFmpeg (anti-SSRF).
  - NUEVO: Botón "Ver en vivo en ventana nueva" para cámaras CCTV detectadas.
"""

import sys, os, re, random, base64, ipaddress, threading, webbrowser, uuid
import socket, subprocess, urllib.request, logging, ssl, time, struct, warnings
import secrets, shutil
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
from flask import Flask, render_template_string, jsonify, request, Response
from flask_socketio import SocketIO
from scapy.all import ARP, Ether, srp, srp1, IP, TCP, ICMP, sr, sr1, conf

# -------------------------------------------------------------------
# Silenciar warnings
# -------------------------------------------------------------------
warnings.filterwarnings("ignore")

class _SilenceFilters(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        for bad in ('Request timed out', 'Bad request',
                    'Mac address to reach destination',
                    'cannot read manuf', 'more Mac address'):
            if bad in msg: return False
        return True

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").propagate = False
logging.getLogger("scapy.runtime").addFilter(_SilenceFilters())
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)
logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.getLogger("scapy").propagate = False

for name in ('werkzeug', 'engineio', 'socketio', 'flask'):
    lg = logging.getLogger(name)
    lg.setLevel(logging.ERROR)
    lg.addFilter(_SilenceFilters())

# -------------------------------------------------------------------
# Argumentos CLI
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(prog="net_tree.py")
    parser.add_argument("target", nargs="?", default="10.0.9.1")
    parser.add_argument("-l2", "--layer2", action="store_true")
    parser.add_argument("-l3", "--layer3", action="store_true")
    parser.add_argument("-icmp", "--icmp", action="store_true")
    parser.add_argument("-s", "--single", action="store_true",
                        help="Escanear un único target (IP pública/privada o DNS) "
                             "por Layer 3. Abre el navegador y lanza el scan desde ahí.")
    parser.add_argument("-p", "--ports", default=None)
    parser.add_argument("-t", "--timeout", type=float, default=2.0)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--web-port", type=int, default=5000)
    parser.add_argument("--no-dns", action="store_true")
    parser.add_argument("--workers", type=int, default=12,
                        help="Workers paralelos para SYN scan (default 12)")
    parser.add_argument("--ffmpeg", default="ffmpeg",
                        help="Ruta a FFmpeg para convertir streams RTSP (default: ffmpeg)")

    args = parser.parse_args()
    if not args.single and not args.layer2 and not args.layer3 and not args.icmp:
        args.layer2 = True; args.layer3 = True
    if args.ports:
        try:
            args.ports_list = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("[!] Formato inválido. Usa: -p 22,80,443"); sys.exit(1)
    else:
        args.ports_list = [80, 443, 22, 445, 3389, 8080]
    return args

ARGS = parse_args()

# === NUEVO: estado global single-target ===
SINGLE_MODE = ARGS.single
SINGLE_TARGET_IP = None
# === FIN NUEVO ===

# -------------------------------------------------------------------
# RUN_ID
# -------------------------------------------------------------------
RUN_ID = str(uuid.uuid4())[:8] + "-" + str(int(time.time()))
print(f"[*] RUN_ID: {RUN_ID}")

# -------------------------------------------------------------------
# Vendor DB
# -------------------------------------------------------------------
def setup_manuf_db():
    for p in [r"C:\Program Files\Wireshark\manuf",
              r"C:\Program Files (x86)\Wireshark\manuf",
              "/usr/share/wireshark/manuf"]:
        if os.path.exists(p):
            try:
                from scapy.data import MANUFDB
                conf.manufdb = MANUFDB(p)
                print(f"[*] manuf DB cargada: {p}")
                return True
            except Exception: pass
    return False
MANUF_OK = setup_manuf_db()

_MAC_AVAILABLE = False
_MAC_LOOKUP = None
try:
    from mac_vendor_lookup import MacLookup
    _MAC_LOOKUP = MacLookup()
    try:
        _MAC_LOOKUP.update_vendors(); _MAC_AVAILABLE = True
        print("[*] mac-vendor-lookup DB lista")
    except Exception:
        _MAC_AVAILABLE = True
except ImportError:
    print("[!] mac-vendor-lookup NO instalado → pip install mac-vendor-lookup")
except Exception as e:
    print(f"[!] mac-vendor-lookup error: {e}")

OUI_MANUAL = {
    "00:50:56":"VMware","00:0C:29":"VMware","08:00:27":"VirtualBox",
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "00:11:32":"Synology","00:15:5D":"Microsoft Hyper-V",
    "D8:36:5F":"Intelbras","00:1A:79":"Intelbras","F4:8E:38":"Intelbras",
    "F8:8E:85":"Intelbras","74:29:AF":"Intelbras",
    "EC:B1:D7":"Hewlett Packard",
}
MOBILE_VENDORS = ['samsung','xiaomi','huawei','oppo','vivo','oneplus','motorola',
    'lg electronics','sony mobile','zte','tcl','realme','honor','apple',
    'google','htc','nokia','alcatel','tecno']
PC_VENDORS = ['dell','lenovo','hewlett','hp ','asustek','gigabyte','micro-star',
    'msi','intel','toshiba','acer','compal','clevo','framework','raspberry','foxconn',
    'chongqing','fugui','pegatron','quanta','wistron','inventec','intelbras',
    'mercusys','azurewave']

_DNS_CACHE = {}
_HTTP_CACHE = {}
_VENDOR_CACHE = {}
RTSP_PORTS = (554, 8554)

# Paths comunes para auto-detección con DESCRIBE
RTSP_COMMON_PATHS = [
    '/',
    '/stream1', '/stream2',
    '/live', '/live/ch0', '/live/ch1',
    '/Streaming/Channels/101',                    # Hikvision
    '/Streaming/Channels/102',
    '/cam/realmonitor?channel=1&subtype=0',       # Dahua
    '/onvif1', '/onvif2',
    '/h264', '/mpeg4', '/video1',
    '/1', '/11', '/12',
    '/img/video.mjpeg',
]

_STREAM_SESSIONS = {}
_STREAM_SESSIONS_LOCK = threading.Lock()

conf.verb = 0
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                    logger=False, engineio_logger=False,
                    ping_interval=60, ping_timeout=180)
topology_data = {"nodes": [], "edges": [], "devices": [], "run_id": RUN_ID,
                 "target": None, "gateway": None}

# ===================================================================
# NUEVO: Template de ventana emergente para "Ver en vivo"
# ===================================================================
POPUP_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>🎥 Cámara en vivo</title>
<style>
    html, body { margin:0; padding:0; height:100%; background:#000; overflow:hidden; }
    .container { display:flex; align-items:center; justify-content:center; height:100vh; }
    img { max-width:100vw; max-height:100vh; object-fit:contain; display:none; }
    .msg { color:#fff; font-family:'Segoe UI',sans-serif; font-size:1em; text-align:center; padding:20px; }
    .spinner { display:inline-block; width:26px; height:26px; border:3px solid #333;
               border-top-color:#3498db; border-radius:50%;
               animation:spin 0.8s linear infinite; margin-bottom:14px; }
    @keyframes spin { to { transform:rotate(360deg); } }
    .error { color:#f77; }
    #status { position:absolute; top:10px; left:10px; color:#ccc; font-family:Consolas,monospace;
              font-size:0.8em; padding:6px 10px; background:rgba(0,0,0,0.6); border-radius:4px; z-index:5; }
</style>
</head>
<body>
<div id="status">Conectando con la cámara...</div>
<div class="container">
    <div class="msg" id="msg"><span class="spinner"></span><br>Iniciando stream RTSP...</div>
    <img id="cam" alt="Video en vivo">
</div>
<script>
(function(){
    const img = document.getElementById('cam');
    const msg = document.getElementById('msg');
    const status = document.getElementById('status');
    const streamId = {{ stream_id|tojson }};

    img.onload = function() {
        img.style.display = 'block';
        msg.style.display = 'none';
        status.textContent = '🎥 EN VIVO';
        status.style.color = '#4f4';
    };
    img.onerror = function() {
        if (!img.getAttribute('src')) return;
        img.style.display = 'none';
        msg.style.display = 'block';
        msg.className = 'msg error';
        msg.innerHTML = '❌ No se pudo mostrar el video.<br><br>' +
            'Verificá FFmpeg, credenciales RTSP y codec de la cámara.';
        status.textContent = 'ERROR';
        status.style.color = '#f77';
    };
    img.src = '/api/stream/' + streamId;

    // Detener stream al cerrar la ventana
    window.addEventListener('beforeunload', function() {
        try {
            const blob = new Blob([JSON.stringify({stream_id: streamId})],
                                  {type: 'application/json'});
            navigator.sendBeacon('/api/stream/stop', blob);
        } catch(e) {
            try {
                fetch('/api/stream/stop', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({stream_id: streamId}),
                    keepalive: true
                });
            } catch(_) {}
        }
    });
})();
</script>
</body>
</html>
"""

# -------------------------------------------------------------------
# HTML
# -------------------------------------------------------------------
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<title>Network Tree Scanner</title>
<style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: 'Segoe UI', Tahoma, sans-serif; background: #f5f5f5; overflow: hidden; }
    .topbar { position: absolute; top: 0; left: 0; width: 100%; height: 52px; background: #fff;
              border-bottom: 1px solid #e0e0e0; display: flex; align-items: center; padding: 0 20px; z-index: 10; }
    .topbar input { width: 340px; padding: 8px 14px; border: 1px solid #ddd; border-radius: 4px;
                    font-size: 13px; outline: none; background: #fafafa; }
    .topbar input:focus { border-color: #3498db; background: #fff; }
    .topbar button { margin-left: 10px; padding: 8px 14px; background: #3498db; color: #fff;
                     border: none; border-radius: 4px; font-size: 12px; cursor: pointer; font-weight: 600; }
    .topbar button:hover { background: #2980b9; }
    .topbar .run-badge { margin-left: auto; padding: 6px 12px; background: #e8f4ff;
                         border: 1px solid #3498db; border-radius: 4px; font-family: monospace;
                         font-size: 11px; color: #2c3e50; font-weight: 600; }
    #network-container { width: 100vw; height: 100vh; background-color: #f5f5f5;
        background-image: linear-gradient(rgba(0,0,0,0.04) 1px, transparent 1px),
                          linear-gradient(90deg, rgba(0,0,0,0.04) 1px, transparent 1px);
        background-size: 32px 32px; }
    #status { position: absolute; bottom: 20px; left: 20px; padding: 8px 14px; background: #fff;
              border-radius: 6px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); font-size: 0.82em;
              color: #555; z-index: 10; }
    .detail-panel { position: absolute; top: 62px; right: 20px; width: 520px; max-height: 85vh;
                    background: #fff; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);
                    padding: 20px; overflow-y: auto; display: none; z-index: 20; }
    .detail-panel h3 { margin-top: 0; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }
    .detail-panel .close-btn { position: absolute; top: 15px; right: 15px; cursor: pointer;
                               font-size: 1.2em; color: #999; }
    .detail-panel .close-btn:hover { color: #333; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85em; margin-top: 10px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }
    th { background: #f8f9fa; font-weight: 600; color: #444; }
    .banner-box { font-family: Consolas, monospace; font-size: 0.78em; color: #444;
                  background: #f7f7f7; padding: 6px; border-radius: 4px; margin-top: 4px;
                  word-break: break-all; white-space: pre-wrap; max-height: 100px;
                  overflow: auto; border-left: 3px solid #95a5a6; }
    .loading { color: #2980b9; font-style: italic; }
    .progress { display:inline-block; width: 16px; height: 16px; border: 2px solid #ddd;
                border-top-color: #3498db; border-radius: 50%; animation: spin 0.8s linear infinite;
                margin-right: 6px; vertical-align: middle; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .discover-btn { display: inline-block; margin: 10px 0; padding: 10px 18px;
                    background: linear-gradient(180deg, #3498db 0%, #2980b9 100%);
                    color: #fff; border: none; border-radius: 6px; cursor: pointer;
                    font-size: 0.9em; font-weight: 600;
                    box-shadow: 0 2px 6px rgba(52,152,219,0.3); }
    .discover-btn:hover:not(:disabled) { background: linear-gradient(180deg, #2980b9 0%, #1f6c9c 100%); }
    .discover-btn:disabled { opacity: 0.65; cursor: not-allowed; }
    .badge-open { display: inline-block; padding: 2px 8px; background: #d4efdf; color: #1e8449;
                  border-radius: 4px; font-size: 0.78em; font-weight: 600; }
    .badge-pending { display: inline-block; padding: 2px 8px; background: #fcf3cf; color: #7d6608;
                     border-radius: 4px; font-size: 0.78em; font-weight: 600; }
    .badge-wrapped { display: inline-block; padding: 2px 8px; background: #fadbd8; color: #922b21;
                     border-radius: 4px; font-size: 0.78em; font-weight: 600; }
    .badge-version { display: inline-block; padding: 2px 8px; background: #d6eaf8; color: #1b4f72;
                     border-radius: 4px; font-size: 0.78em; font-weight: 600; margin-left: 4px; }
    .badge-rtsp { display: inline-block; padding: 2px 8px; background: #fdebd0; color: #a04000;
                  border-radius: 4px; font-size: 0.78em; font-weight: 600; margin-left: 4px; }
    .camera-stream { margin: 14px 0; padding: 12px; background: #f8f9fa; border: 1px solid #ddd;
                        border-radius: 6px; }
    .camera-stream input { width: 100%; padding: 8px; margin: 6px 0; border: 1px solid #ccc;
                              border-radius: 4px; font-family: Consolas, monospace; font-size: 0.82em; }
    .camera-stream button { margin: 4px 6px 4px 0; padding: 7px 12px; border: 0; border-radius: 4px;
                               background: #3498db; color: white; cursor: pointer; }
    .camera-stream button.stop-stream { background: #c0392b; }
    .camera-stream img { display: block; width: 100%; max-height: 360px; margin-top: 8px;
                            background: #111; object-fit: contain; }
    .camera-hint, .camera-status { color: #666; font-size: 0.82em; }
    .camera-hint code { background: #eef; padding: 1px 5px; border-radius: 3px;
                        font-family: Consolas, monospace; color: #2c3e50; }
    .path-chip { display: inline-block; margin: 2px 4px 2px 0; padding: 2px 8px;
                 background: #e8f4ff; color: #2471a3; border: 1px solid #a9cce3;
                 border-radius: 12px; font-size: 0.75em; cursor: pointer;
                 font-family: Consolas, monospace; }
    .path-chip:hover { background: #d4e6f1; }
</style>
<script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
<script>
    if (typeof vis === 'undefined')
        document.write('<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"><\\/script>');
</script>
<script>
    if (typeof vis === 'undefined')
        document.write('<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/standalone/umd/vis-network.min.js"><\\/script>');
</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
</head>
<body>
<div class="topbar">
    <input type="text" id="search" placeholder="Search IP / LAN / host" />
    <button id="btn-fit">🔍 Ver todo</button>
    <span class="run-badge" id="run-badge">RUN: —</span>
</div>
<div id="network-container"></div>
<div id="status">⏳ Iniciando...</div>

<div class="detail-panel" id="detail-panel">
    <span class="close-btn" onclick="closePanel()">✕</span>
    <h3 id="panel-title">Detalles</h3>
    <div id="panel-content"></div>
</div>

{% raw %}
<script>
(function() {
    'use strict';
    const statusDiv = document.getElementById('status');
    const container = document.getElementById('network-container');
    const runBadge = document.getElementById('run-badge');
    let nodes = null, edges = null, network = null;

    function setStatus(m) { statusDiv.textContent = m; }

    function waitForVis(ms) {
        return new Promise(function(res, rej) {
            const t0 = Date.now();
            (function chk() {
                if (typeof vis !== 'undefined' && vis.DataSet && vis.Network) return res();
                if (Date.now() - t0 > ms) return rej(new Error('vis-network timeout'));
                setTimeout(chk, 100);
            })();
        });
    }

    function fetchTopology(n) {
        return new Promise(function(res, rej) {
            let a = 0;
            (function t() {
                a++;
                setStatus('⏳ Obteniendo topología (' + a + '/' + n + ')...');
                const url = '/api/topology?t=' + Date.now() + '&r=' + Math.random();
                fetch(url, { cache: 'no-store',
                    headers: {'Cache-Control': 'no-cache, no-store, must-revalidate'} })
                .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
                .then(res)
                .catch(function(e) {
                    if (a < n) setTimeout(t, 800);
                    else rej(e);
                });
            })();
        });
    }

    function doFit() {
        if (!network) return;
        try { network.fit({ animation: false }); } catch(e) {}
    }

    document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('btn-fit').addEventListener('click', doFit);

        waitForVis(5000).then(function() { return fetchTopology(3); })
        .then(function(data) {
            console.log('[API] Nodos:', data.nodes ? data.nodes.length : 0);
            console.log('[API] RUN_ID:', data.run_id, '| Target:', data.target);

            runBadge.textContent = 'RUN: ' + (data.run_id || '—') +
                                    (data.target ? '  |  ' + data.target : '');

            // === NUEVO: guardar devices para detectar cámaras ===
            if (data.devices && Array.isArray(data.devices)) {
                data.devices.forEach(function(d) {
                    if (d && d.ip) devicesByIp[d.ip] = d;
                });
            }
            // === FIN NUEVO ===

            if (!data.nodes || data.nodes.length === 0) { setStatus('Sin dispositivos'); return; }

            const seenN = new Set();
            const uniqueNodes = data.nodes.filter(function(n) {
                if (seenN.has(n.id)) return false;
                seenN.add(n.id); return true;
            });
            const seenE = new Set();
            const uniqueEdges = data.edges.filter(function(e) {
                const k = e.from + '->' + e.to;
                if (seenE.has(k)) return false;
                seenE.add(k); return true;
            });

            nodes = new vis.DataSet(uniqueNodes);
            edges = new vis.DataSet(uniqueEdges);

            const options = {
                nodes: { shape: 'image', size: 85, font: { size: 0 },
                         borderWidth: 0, shadow: false, imagePadding: 0,
                         margin: { top: 8, bottom: 8, left: 8, right: 8 } },
                edges: {
                    smooth: { enabled: true, type: 'cubicBezier',
                              forceDirection: 'vertical', roundness: 0.15 },
                    color: { color: '#b0b0b0', highlight: '#3498db' },
                    width: 1.2, arrows: { to: { enabled: false } }
                },
                layout: { hierarchical: {
                    enabled: true, direction: 'UD', sortMethod: 'directed',
                    levelSeparation: 180, nodeSpacing: 220, treeSpacing: 220,
                    blockShifting: true, edgeMinimization: true, parentCentralization: true
                }},
                physics: { enabled: false },
                interaction: { hover: true, tooltipDelay: 200, zoomView: true, dragView: true }
            };

            network = new vis.Network(container, { nodes: nodes, edges: edges }, options);
            setStatus('✅ ' + uniqueNodes.length + ' dispositivos · ' + uniqueEdges.length + ' conexiones');

            [200, 600, 1500, 3000].forEach(function(ms){ setTimeout(doFit, ms); });

            // === NUEVO: auto-abrir panel en modo single-target (?auto=1) ===
            try {
                const qs = new URLSearchParams(window.location.search);
                if (qs.get('auto') === '1' && uniqueNodes.length > 0) {
                    const firstId = uniqueNodes[0].id;
                    setTimeout(function(){ window.openPanel(firstId); }, 900);
                }
            } catch(e) {}
            // === FIN NUEVO ===

            network.on('click', function(p) {
                if (p.nodes.length > 0) window.openPanel(p.nodes[0]);
            });

            document.getElementById('search').addEventListener('input', function(e) {
                const q = e.target.value.toLowerCase().trim();
                if (!q) { network.fit({ animation: true }); return; }
                const m = nodes.get().filter(function(n) { return String(n.id).toLowerCase().indexOf(q) !== -1; });
                if (m.length) network.fit({ nodes: m.map(function(n){return n.id;}), animation: true });
            });
        })
        .catch(function(e) { setStatus('❌ ' + e.message); });
    });

    const socket = (typeof io !== 'undefined') ? io() : null;
    let currentIp = null, currentPorts = [], currentStreamId = null;

    // === NUEVO: estado para "Ver en vivo" popup ===
    const devicesByIp = {};
    const cameraStreamCache = {};
    const pendingLiveOpen = {};
    const scanCompleted = {};
    // === FIN NUEVO ===

    function htmlEscape(value) {
        return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function stopCameraStream() {
        const streamId = currentStreamId;
        currentStreamId = null;
        const image = document.getElementById('camera-image');
        if (image) image.removeAttribute('src');
        if (streamId) {
            fetch('/api/stream/stop', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({stream_id: streamId})
            }).catch(function(error) { console.error('No se pudo detener el stream:', error); });
        }
    }

    // === NUEVO: helpers para "Ver en vivo" en ventana nueva ===
    function buildCameraBanner(ip, statusMsg, statusColor) {
        return '<div style="padding:12px;background:linear-gradient(135deg,#fef5e7,#fdebd0);' +
               'border:1px solid #f0b27a;border-radius:6px;margin-bottom:14px">' +
               '<div style="font-weight:700;color:#a04000;margin-bottom:8px;font-size:0.95em">' +
               '📷 Cámara CCTV detectada</div>' +
               '<button id="btn-live-window" data-cam-ip="' + htmlEscape(ip) + '"' +
               ' style="padding:10px 20px;background:#e67e22;color:#fff;border:none;' +
               'border-radius:4px;cursor:pointer;font-weight:600;font-size:0.95em">' +
               '🎥 Ver en vivo (ventana nueva)</button>' +
               '<div id="live-open-status" style="font-size:0.82em;margin-top:8px;color:' +
               (statusColor || '#a04000') + '">' + (statusMsg || '') + '</div></div>';
    }

    function attachCameraBannerListener(ip) {
        const btn = document.getElementById('btn-live-window');
        if (!btn) return;
        btn.addEventListener('click', function() {
            if (pendingLiveOpen[ip]) return;
            const cached = cameraStreamCache[ip];
            if (cached && cached.url) {
                openLiveWindow(ip, cached.url);
                return;
            }
            if (scanCompleted[ip]) {
                alert('No se detectó RTSP en ' + ip + '. Verificá que sea una cámara RTSP.');
                return;
            }
            // Abrir ventana vacía SÍNCRONA para evitar popup blocker
            const w = window.open('', 'cam_' + ip.replace(/\./g, '_'),
                'width=1000,height=620,resizable=yes,scrollbars=no');
            if (!w) {
                alert('El navegador bloqueó la ventana emergente.\nPermití popups para este sitio.');
                return;
            }
            try {
                w.document.write('<!DOCTYPE html><html><head><title>🎥 ' + htmlEscape(ip) +
                    '</title><style>body{margin:0;background:#000;color:#fff;display:flex;' +
                    'align-items:center;justify-content:center;height:100vh;font-family:sans-serif;' +
                    'text-align:center;padding:20px}.sp{display:inline-block;width:26px;height:26px;' +
                    'border:3px solid #333;border-top-color:#3498db;border-radius:50%;' +
                    'animation:spin 0.8s linear infinite;margin-bottom:14px}' +
                    '@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div>' +
                    '<div class="sp"></div><p>⏳ Esperando detección de RTSP...</p>' +
                    '<p style="color:#999;font-size:0.85em">La ventana se conectará automáticamente.</p>' +
                    '</div></body></html>');
                w.document.close();
            } catch(e) {}
            pendingLiveOpen[ip] = { window: w };
            btn.disabled = true;
            btn.textContent = '⏳ Esperando scan...';
            const status = document.getElementById('live-open-status');
            if (status) status.textContent = '⏳ Esperando detección de puerto RTSP...';
        });
    }

    function openLiveWindow(ip, rtspUrl) {
        const w = window.open('', 'cam_' + ip.replace(/\./g, '_'),
            'width=1000,height=620,resizable=yes,scrollbars=no');
        if (!w) {
            alert('El navegador bloqueó la ventana emergente.');
            return;
        }
        try {
            w.document.write('<!DOCTYPE html><html><head><title>🎥 ' + htmlEscape(ip) +
                '</title><style>body{margin:0;background:#000;color:#fff;display:flex;' +
                'align-items:center;justify-content:center;height:100vh;font-family:sans-serif;' +
                'text-align:center;padding:20px}.sp{display:inline-block;width:26px;height:26px;' +
                'border:3px solid #333;border-top-color:#3498db;border-radius:50%;' +
                'animation:spin 0.8s linear infinite;margin-bottom:14px}' +
                '@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div>' +
                '<div class="sp"></div><p>Iniciando stream RTSP...</p></div></body></html>');
            w.document.close();
        } catch(e) {}
        startStreamInWindow(ip, rtspUrl, w);
    }

    function startStreamInWindow(ip, rtspUrl, w) {
        if (!w || w.closed) return;
        fetch('/api/stream/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: rtspUrl})
        }).then(function(r) {
            return r.json().then(function(b) {
                if (!r.ok || b.error) throw new Error(b.error || ('HTTP ' + r.status));
                return b;
            });
        }).then(function(body) {
            if (!w || w.closed) {
                fetch('/api/stream/stop', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({stream_id: body.stream_id})
                }).catch(function(){});
                return;
            }
            w.location.href = '/stream-popup/' + body.stream_id;
        }).catch(function(e) {
            if (!w || w.closed) return;
            try {
                w.document.body.innerHTML =
                    '<div style="color:#f77;padding:20px;font-family:sans-serif;text-align:center">' +
                    '<p style="font-size:2em;margin:0">❌</p>' +
                    '<p><strong>No se pudo iniciar el stream</strong></p>' +
                    '<p style="font-size:0.9em;color:#ccc">' + htmlEscape(e.message) + '</p>' +
                    '<p style="font-size:0.85em;color:#999;margin-top:20px">Verificá:<br>' +
                    '• Que FFmpeg esté instalado y en PATH<br>' +
                    '• Que las credenciales RTSP sean correctas<br>' +
                    '• Que el codec sea compatible</p></div>';
            } catch(_) { alert('Error: ' + e.message); }
        });
    }
    // === FIN NUEVO ===

    window.openPanel = function(ip) {
        stopCameraStream();
        const p = document.getElementById('detail-panel');
        const t = document.getElementById('panel-title');
        const c = document.getElementById('panel-content');
        p.style.display = 'block';
        t.textContent = '🔍 ' + ip;

        // === NUEVO: mostrar banner si es cámara ===
        const devInfo = devicesByIp[ip] || {};
        const isCameraGuess = (devInfo.badge === 'CAMERA') ||
            ((devInfo.type || '').toLowerCase().indexOf('cámara') !== -1) ||
            ((devInfo.type || '').toLowerCase().indexOf('camara') !== -1);

        let html = '';
        if (isCameraGuess) {
            html += buildCameraBanner(ip, '⏳ Detectando stream RTSP...', '#a04000');
        }
        html += '<p class="loading"><span class="progress"></span>SYN scan 1-65535 PARALELO (5-10s)...</p>';
        c.innerHTML = html;

        if (isCameraGuess) attachCameraBannerListener(ip);
        // === FIN NUEVO ===

        currentIp = ip; currentPorts = [];
        if (socket) socket.emit('request_port_scan', { ip: ip });
    };
    window.closePanel = function() {
        stopCameraStream();
        document.getElementById('detail-panel').style.display = 'none';
    };

    // Construye chips con paths comunes para sugerir al usuario
    const COMMON_RTSP_PATHS = [
        '/', '/stream1', '/stream2', '/live', '/live/ch0',
        '/Streaming/Channels/101', '/Streaming/Channels/102',
        '/cam/realmonitor?channel=1&subtype=0',
        '/onvif1', '/h264', '/mpeg4', '/video1', '/1'
    ];

    function renderServiceCell(r) {
        let h = '<td><span class="badge-open">' + (r.service || 'unknown') + '</span>';
        if (r.tcpwrapped) {
            h += ' <span class="badge-wrapped">tcpwrapped</span>';
        } else if (r.version) {
            h += ' <span class="badge-version">' + r.version.replace(/</g,'&lt;') + '</span>';
        }
        if (r.service === 'RTSP' || r.port === 554 || r.port === 8554) {
            h += ' <span class="badge-rtsp">📷 RTSP</span>';
        }
        if (r.banner) h += '<div class="banner-box">' + r.banner.replace(/</g,'&lt;') + '</div>';
        h += '</td>';
        return h;
    }

    if (socket) {
        socket.on('node_update', function(newNode) {
            if (!nodes) return;
            if (nodes.get(newNode.id)) nodes.update(newNode);
            else nodes.add(newNode);
            setTimeout(doFit, 200);
        });

        socket.on('port_scan_result', function(data) {
            const c = document.getElementById('panel-content');
            if (!data.results || !data.results.length) { c.innerHTML = '<p>Sin puertos abiertos.</p>'; return; }
            currentPorts = data.results.map(function(r){ return r.port; });

            // === NUEVO: detectar cámara por RTSP / clasificación previa y cachear ===
            scanCompleted[data.ip] = true;
            const devInfo = devicesByIp[data.ip] || {};
            const rtspPortsEarly = data.rtsp_ports || [];
            const rtspPathsEarly = data.rtsp_paths || {};
            const hasRtspEarly = rtspPortsEarly.length > 0;
            const isCamera = (devInfo.badge === 'CAMERA') ||
                ((devInfo.type || '').toLowerCase().indexOf('cámara') !== -1) ||
                ((devInfo.type || '').toLowerCase().indexOf('camara') !== -1) ||
                hasRtspEarly;

            if (hasRtspEarly) {
                const rp = rtspPortsEarly[0];
                const dp = rtspPathsEarly[rp] || '/';
                cameraStreamCache[data.ip] = {
                    port: rp, path: dp,
                    url: 'rtsp://' + data.ip + ':' + rp + dp
                };
            }
            // === FIN NUEVO ===

            // === NUEVO: banner de cámara arriba de todo ===
            let h = '';
            if (isCamera) {
                const msg = hasRtspEarly
                    ? '✅ Path RTSP detectado: <code>' + htmlEscape(cameraStreamCache[data.ip].path) + '</code>'
                    : '⚠️ No se detectó RTSP. El dispositivo puede no ser cámara o el puerto no está abierto.';
                h += buildCameraBanner(data.ip, msg, hasRtspEarly ? '#1e8449' : '#a04000');
            }
            // === FIN NUEVO ===
            h += '<p><strong>' + data.results.length + ' puertos abiertos</strong> en ' + data.ip + '</p>';

            const rtspPorts = data.rtsp_ports || [];
            const rtspPaths = data.rtsp_paths || {};
            if (rtspPorts.length) {
                const rtspPort = rtspPorts[0];
                const detectedPath = rtspPaths[rtspPort] || '';
                const initialPath = detectedPath || '/';
                const initialUrl = 'rtsp://' + data.ip + ':' + rtspPort + initialPath;

                let hint;
                if (detectedPath) {
                    hint = '✅ Path detectado automáticamente: <code>' +
                           htmlEscape(detectedPath) + '</code>. ' +
                           'Si requiere autenticación, agregá <code>usuario:pass@</code> antes de la IP.';
                } else {
                    hint = '⚠️ No se pudo detectar el path automáticamente. ' +
                           'Probá con uno de los paths comunes:';
                }

                // Chips de sugerencia
                let chips = '';
                COMMON_RTSP_PATHS.forEach(function(p) {
                    const url = 'rtsp://' + data.ip + ':' + rtspPort + p;
                    chips += '<span class="path-chip" data-url="' +
                             htmlEscape(url) + '">' + htmlEscape(p) + '</span>';
                });

                h += '<section class="camera-stream"><strong>📷 Cámara RTSP detectada</strong>'
                   + '<p class="camera-hint">' + hint + '</p>'
                   + '<div style="margin: 6px 0">' + chips + '</div>'
                   + '<input id="camera-url" type="text" value="' +
                     htmlEscape(initialUrl) + '" aria-label="URL RTSP">'
                   + '<button id="btn-camera-start">▶ Ver en vivo</button>'
                   + '<button id="btn-camera-stop" class="stop-stream" style="display:none">■ Detener</button>'
                   + '<div id="camera-status" class="camera-status">FFmpeg convierte el video a MJPEG para el navegador.</div>'
                   + '<img id="camera-image" alt="Video en vivo de la cámara" style="display:none"></section>';
            }

            h += '<button id="btn-discover" class="discover-btn">🔍 Descubrir servicios y versiones</button>';
            h += '<table id="ports-table"><thead><tr>'
               + '<th style="width:80px">Puerto</th><th>Estado</th></tr></thead><tbody>';
            data.results.forEach(function(r) {
                const isRtsp = rtspPorts.indexOf(r.port) !== -1;
                h += '<tr data-port="' + r.port + '">'
                   + '<td><strong>' + r.port + '</strong></td>'
                   + '<td><span class="badge-open">ABIERTO</span> '
                   + (isRtsp
                       ? '<span class="badge-rtsp">📷 RTSP · cámara</span>'
                       : '<span class="badge-pending">esperando análisis</span>')
                   + '</td></tr>';
            });
            h += '</tbody></table>';
            c.innerHTML = h;

            // Chips: al hacer clic, rellenan el input
            c.querySelectorAll('.path-chip').forEach(function(chip) {
                chip.addEventListener('click', function() {
                    const input = document.getElementById('camera-url');
                    if (input) input.value = chip.getAttribute('data-url');
                });
            });

            const cameraStart = document.getElementById('btn-camera-start');
            if (cameraStart) cameraStart.addEventListener('click', function() {
                stopCameraStream();
                const status = document.getElementById('camera-status');
                const image = document.getElementById('camera-image');
                const stopButton = document.getElementById('btn-camera-stop');
                const streamUrl = document.getElementById('camera-url').value.trim();
                status.textContent = 'Conectando con la cámara...';
                cameraStart.disabled = true;
                fetch('/api/stream/start', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: streamUrl})
                }).then(function(response) {
                    return response.json().then(function(body) {
                        if (!response.ok) throw new Error(body.error || 'No se pudo iniciar el stream');
                        return body;
                    });
                }).then(function(body) {
                    currentStreamId = body.stream_id;
                    image.style.display = 'block';
                    stopButton.style.display = 'inline-block';
                    image.src = body.stream_url;
                    status.textContent = 'Stream activo. Si no aparece video, verifica la ruta y credenciales RTSP.';
                }).catch(function(error) {
                    status.textContent = '❌ ' + error.message;
                }).finally(function() {
                    cameraStart.disabled = false;
                });
            });

            const cameraStop = document.getElementById('btn-camera-stop');
            if (cameraStop) cameraStop.addEventListener('click', function() {
                stopCameraStream();
                cameraStop.style.display = 'none';
                document.getElementById('camera-image').style.display = 'none';
                document.getElementById('camera-status').textContent = 'Stream detenido.';
            });

            const cameraImage = document.getElementById('camera-image');
            if (cameraImage) cameraImage.addEventListener('error', function() {
                document.getElementById('camera-status').textContent =
                    'No se pudo mostrar el video. Verifica FFmpeg, ruta, credenciales y codec de la cámara.';
            });

            document.getElementById('btn-discover').addEventListener('click', function() {
                this.disabled = true;
                this.innerHTML = '<span class="progress"></span>Analizando...';
                socket.emit('request_service_scan', { ip: currentIp, ports: currentPorts });
            });

            // === NUEVO: listener del banner + manejo de pendientes ===
            if (isCamera) {
                attachCameraBannerListener(data.ip);
            }

            if (pendingLiveOpen[data.ip]) {
                const pending = pendingLiveOpen[data.ip];
                delete pendingLiveOpen[data.ip];
                if (hasRtspEarly) {
                    if (pending.window && !pending.window.closed) {
                        startStreamInWindow(data.ip, cameraStreamCache[data.ip].url, pending.window);
                    }
                } else {
                    if (pending.window && !pending.window.closed) {
                        try {
                            pending.window.document.body.innerHTML =
                                '<div style="color:#f77;padding:20px;font-family:sans-serif;text-align:center">' +
                                '<p style="font-size:2em;margin:0">❌</p>' +
                                '<p><strong>No se detectó RTSP en ' + htmlEscape(data.ip) + '</strong></p>' +
                                '<p style="color:#999;font-size:0.9em;margin-top:15px">El dispositivo puede no ser ' +
                                'una cámara o el puerto RTSP está filtrado.</p></div>';
                        } catch(_) {}
                    }
                }
            }
            // === FIN NUEVO ===
        });

        socket.on('service_scan_result', function(data) {
            const table = document.getElementById('ports-table');
            if (!table) return;
            data.results.forEach(function(r) {
                const row = table.querySelector('tr[data-port="' + r.port + '"]');
                if (row) row.innerHTML = '<td><strong>' + r.port + '</strong></td>' + renderServiceCell(r);
            });
            const btn = document.getElementById('btn-discover');
            if (btn) { btn.disabled = false; btn.innerHTML = '✅ Servicios descubiertos'; }
        });
    }
})();
</script>
{% endraw %}
</body>
</html>
"""

# -------------------------------------------------------------------
# Vendor
# -------------------------------------------------------------------
def _to_str(v):
    if v is None: return ""
    if isinstance(v, tuple):
        for i in v:
            if i: return str(i)
        return ""
    return str(v)

_MAC_RE = re.compile(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', re.IGNORECASE)

def is_randomized_mac(mac):
    if not mac or mac.startswith("N/A"): return False
    try: return bool(int(mac.replace(":","").replace("-","")[:2], 16) & 0x02)
    except Exception: return False

def looks_like_mac(s):
    return bool(s and _MAC_RE.match(s.strip()))

def lookup_vendor_online(mac, timeout=4):
    if not mac: return ""
    oui = mac.replace(":","").replace("-","").upper()[:6]
    if len(oui) < 6: return ""
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{oui}",
                                     headers={'User-Agent': 'NetTreeScanner/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 200:
                t = r.read().decode('utf-8').strip()
                if t and not looks_like_mac(t): return t
    except Exception: pass
    return ""

def get_vendor(mac):
    if not mac or mac.startswith("N/A"): return "N/A"
    if mac in _VENDOR_CACHE: return _VENDOR_CACHE[mac]
    if is_randomized_mac(mac):
        _VENDOR_CACHE[mac] = "MAC aleatorizada"
        return "MAC aleatorizada"
    if _MAC_AVAILABLE and _MAC_LOOKUP:
        try:
            v = _to_str(_MAC_LOOKUP.lookup(mac))
            if v and not looks_like_mac(v) and v.lower() != "unknown":
                _VENDOR_CACHE[mac] = v; return v
        except Exception: pass
    if MANUF_OK:
        try:
            v = _to_str(conf.manufdb.lookup(mac))
            if v and not looks_like_mac(v) and v.lower() != "unknown":
                _VENDOR_CACHE[mac] = v; return v
        except Exception: pass
    prefix = mac.upper()[:8]
    if prefix in OUI_MANUAL:
        v = OUI_MANUAL[prefix]; _VENDOR_CACHE[mac] = v; return v
    v = lookup_vendor_online(mac)
    if v:
        _VENDOR_CACHE[mac] = v; return v
    _VENDOR_CACHE[mac] = "Desconocido"
    return "Desconocido"

# -------------------------------------------------------------------
# Hostname
# -------------------------------------------------------------------
def get_hostname_dns(ip, timeout=1.2):
    try:
        socket.setdefaulttimeout(timeout)
        h, _, _ = socket.gethostbyaddr(ip)
        if h and h != ip and not h.startswith(ip + "."): return h
    except Exception: pass
    finally: socket.setdefaulttimeout(None)
    return ""

def get_hostname_netbios(ip, timeout=1.2):
    try:
        header = struct.pack(">HHHHHH", 0xABCD, 0x0000, 1, 0, 0, 0)
        qname_encoded = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        question = bytes([32]) + qname_encoded + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (ip, 137))
        resp, _ = s.recvfrom(2048); s.close()
        if len(resp) < 58: return ""
        num_names = resp[56] if len(resp) > 56 else 0
        for i in range(num_names):
            offset = 57 + i * 18
            if offset + 16 > len(resp): break
            if resp[offset + 15] & 0x80: continue
            name = resp[offset:offset + 15].decode('ascii', errors='ignore').strip('\x00 ')
            if name and len(name) > 1: return name
    except Exception: pass
    return ""

def get_hostname_mdns(ip, timeout=1.2):
    try:
        rev = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        qname = b""
        for label in rev.split('.'):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        header = struct.pack(">HHHHHH", 0, 0x0000, 1, 0, 0, 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + qname + struct.pack(">HH", 12, 1), (ip, 5353))
        try: data, _ = s.recvfrom(2048)
        except socket.timeout:
            s.close(); return ""
        s.close()
        matches = re.findall(rb'([a-zA-Z0-9][a-zA-Z0-9\-]{1,30})\.local', data)
        if matches: return matches[0].decode() + ".local"
    except Exception: pass
    return ""

def get_hostname_http(ip, timeout=1.5):
    for port in (80, 8080, 8000, 5000, 8443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout); s.connect((ip, port))
            s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(2048).decode(errors='ignore'); s.close()
            m = re.search(r'<title>([^<]{2,50})</title>', data, re.IGNORECASE)
            if m:
                title = m.group(1).strip()
                if not any(k in title.lower() for k in
                           ('index', 'apache', 'nginx', 'iis', 'welcome', 'default')):
                    return f"[web] {title}"
        except Exception: continue
    return ""

def get_hostname(ip):
    if ARGS.no_dns: return ""
    if ip in _DNS_CACHE: return _DNS_CACHE[ip]
    hostname = get_hostname_dns(ip)
    if not hostname: hostname = get_hostname_netbios(ip)
    if not hostname: hostname = get_hostname_mdns(ip)
    if not hostname: hostname = get_hostname_http(ip)
    _DNS_CACHE[ip] = hostname
    return hostname

# -------------------------------------------------------------------
# TTL
# -------------------------------------------------------------------
def get_ttl_l3_tcp(ip, ports=(80, 443, 22, 445, 8080, 139, 135, 3389, 5357, 9100, 631)):
    for port in ports:
        try:
            sp = random.randint(40000, 60000)
            ans = sr1(IP(dst=ip) / TCP(sport=sp, dport=port, flags='S'), timeout=1.2, verbose=0)
            if ans and ans.haslayer(IP): return ans[IP].ttl
        except Exception: continue
    return None

def get_ttl_l3_icmp(ip):
    try:
        ans = sr1(IP(dst=ip) / ICMP(), timeout=1.2, verbose=0)
        if ans and ans.haslayer(IP): return ans[IP].ttl
    except Exception: pass
    return None

def detect_ttls(devices):
    results = {}
    if not devices: return results
    print(f"[*] Detectando TTL en {len(devices)} dispositivos...")
    def worker(d):
        ip = d['ip']
        ttl = get_ttl_l3_tcp(ip)
        if ttl is None: ttl = get_ttl_l3_icmp(ip)
        if ttl is not None: results[ip] = ttl
    with ThreadPoolExecutor(max_workers=len(devices) or 1) as ex:
        for _ in as_completed([ex.submit(worker, d) for d in devices]): pass
    print(f"[*] {len(results)} TTLs obtenidos.")
    return results

# -------------------------------------------------------------------
# Detección de tipo
# -------------------------------------------------------------------
def detect_device_kind(ip, open_ports, vendor, ttl):
    p = set(open_ports); vl = (vendor or "").lower()
    if 5555 in p: return ('Android (ADB)', '📱', 'PHONE')
    hl = (get_hostname(ip) or "").lower()
    if hl:
        if any(k in hl for k in ('android','galaxy','redmi','poco','oneplus')): return ('Android', '📱', 'PHONE')
        if 'iphone' in hl: return ('iPhone', '📱', 'PHONE')
        if 'ipad'   in hl: return ('iPad',   '📱', 'TABLET')
        if 'macbook' in hl or 'imac' in hl: return ('macOS', '🍎', 'PC')
        if any(k in hl for k in ('desktop','laptop','pc-','win-')): return ('PC', '💻', 'HOST')
    if 'hewlett' in vl or 'hp ' in vl or vl.startswith('hp'):
        hp_ports = {1688, 7070, 10004, 631, 9100, 515, 9220, 9290, 9500, 3910, 3911, 7680}
        if any(port in p for port in hp_ports):
            return ('Impresora HP', '🖨️', 'PRINTER')
    if 'apple' in vl:
        if 22 in p or 445 in p or 548 in p or 5900 in p: return ('macOS', '🍎', 'PC')
        return ('Apple (iPhone/iPad)', '📱', 'PHONE')
    if any(v in vl for v in MOBILE_VENDORS): return ('Móvil/Tablet', '📱', 'PHONE')
    if any(v in vl for v in PC_VENDORS):
        if ttl and ttl <= 64: return ('Linux PC', '🐧', 'HOST')
        return ('PC', '💻', 'HOST')
    if ttl:
        if ttl <= 64:  return ('Linux/Unix', '🐧', 'HOST')
        if ttl <= 128: return ('Windows PC', '🪟', 'HOST')
        if ttl >= 200: return ('Router/AP', '🌐', 'ROUTER')
    return ('Desconocido', '💻', 'HOST')

# -------------------------------------------------------------------
# ARP helpers
# -------------------------------------------------------------------
def arp_sweep(network_cidr, gateway_ip, timeout=3):
    print(f"[*] ARP sweep: {network_cidr}")
    try:
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr),
                          timeout=timeout, verbose=0)
        mac_map = {}
        for _, received in answered:
            ip = received.psrc
            if ip != gateway_ip: mac_map[ip] = received.hwsrc
        print(f"    -> {len(mac_map)} MACs")
        return mac_map
    except Exception as e:
        print(f"    [!] Error: {e}")
        return {}

def get_mac_for_ip(ip, timeout=2):
    try:
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                   timeout=timeout, verbose=0)
        if ans: return ans.hwsrc
    except Exception: pass
    return None

# -------------------------------------------------------------------
# Discovery L2 / L3 / ICMP
# -------------------------------------------------------------------
def scan_layer2(network_cidr, gateway_ip):
    seen = {}
    for rnd, timeout in enumerate([2, 3, 2], start=1):
        print(f"[*] Capa 2 (ARP) ronda {rnd}/3...")
        try:
            answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr),
                              timeout=timeout, verbose=0)
            new = 0
            for _, received in answered:
                ip = received.psrc
                if ip not in seen and ip != gateway_ip:
                    seen[ip] = {"mac": received.hwsrc, "methods": {"L2"}}
                    new += 1
            print(f"    -> +{new} (total {len(seen)})")
        except Exception as e:
            print(f"    [!] Error: {e}")
    return seen

def scan_layer3(network_cidr, gateway_ip, probe_ports, timeout=2.0, mac_map=None):
    net = ipaddress.ip_network(network_cidr, strict=False)
    all_ips = [str(ip) for ip in net.hosts() if str(ip) != gateway_ip]
    if mac_map is None: mac_map = arp_sweep(network_cidr, gateway_ip, timeout=2)
    targets = [(ip, mac_map[ip]) for ip in all_ips if ip in mac_map]
    if not targets: return set()
    print(f"[*] Capa 3 (TCP SYN L2) — {len(targets)} IPs × {len(probe_ports)} puertos")
    src_port = random.randint(1024, 65535)
    packets = []
    for ip, mac in targets:
        for port in probe_ports:
            packets.append(Ether(dst=mac) / IP(dst=ip) / TCP(sport=src_port, dport=port, flags='S'))
    alive = set()
    for i in range(0, len(packets), 500):
        try:
            answered, _ = srp(packets[i:i+500], timeout=timeout, verbose=0)
            for sent, received in answered:
                if received.haslayer(TCP) and received[TCP].flags in (0x12, 0x14):
                    alive.add(received[IP].src)
        except Exception: pass
    print(f"[*] Capa 3 (TCP SYN): {len(alive)} hosts vivos")
    return alive

def scan_icmp(network_cidr, gateway_ip, timeout=2.0, mac_map=None):
    net = ipaddress.ip_network(network_cidr, strict=False)
    all_ips = [str(ip) for ip in net.hosts() if str(ip) != gateway_ip]
    if not all_ips: return set()
    if mac_map is None: mac_map = arp_sweep(network_cidr, gateway_ip, timeout=2)
    targets = [(ip, mac_map[ip]) for ip in all_ips if ip in mac_map]
    if not targets: return set()
    print(f"[*] Capa 3 (ICMP Echo L2) — {len(targets)} IPs")
    packets = [Ether(dst=mac) / IP(dst=ip) / ICMP(type=8, code=0) for ip, mac in targets]
    alive = set()
    for i in range(0, len(packets), 500):
        try:
            answered, _ = srp(packets[i:i+500], timeout=timeout, verbose=0)
            for sent, received in answered:
                if received.haslayer(ICMP) and received[ICMP].type in (0, 3):
                    alive.add(received[IP].src)
        except Exception: pass
    print(f"[*] Capa 3 (ICMP): {len(alive)} hosts vivos")
    return alive

def discover_hosts(network_cidr, gateway_ip):
    seen = {}; mac_map = None
    if ARGS.layer2:
        l2 = scan_layer2(network_cidr, gateway_ip)
        for ip, info in l2.items():
            seen[ip] = {"mac": info["mac"], "methods": set(info["methods"])}
        mac_map = {ip: info["mac"] for ip, info in l2.items()}
    if (ARGS.layer3 or ARGS.icmp) and mac_map is None:
        mac_map = arp_sweep(network_cidr, gateway_ip, timeout=3)
        for ip, mac in mac_map.items():
            seen[ip] = {"mac": mac, "methods": set()}
    if ARGS.layer3:
        l3 = scan_layer3(network_cidr, gateway_ip, ARGS.ports_list, ARGS.timeout, mac_map)
        for ip in l3:
            if ip in seen: seen[ip]["methods"].add("L3")
            else: seen[ip] = {"mac": mac_map.get(ip, "N/A"), "methods": {"L3"}}
    if ARGS.icmp:
        ic = scan_icmp(network_cidr, gateway_ip, ARGS.timeout, mac_map)
        for ip in ic:
            if ip in seen: seen[ip]["methods"].add("ICMP")
            else: seen[ip] = {"mac": mac_map.get(ip, "N/A"), "methods": {"ICMP"}}
    for ip in seen:
        m = seen[ip]["methods"]
        seen[ip]["source"] = "+".join(sorted(m)) if m else "?"
    return seen

# -------------------------------------------------------------------
# SVG
# -------------------------------------------------------------------
def _esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;")
                    .replace(">","&gt;").replace('"',"&quot;"))

def make_node_svg(icon, ip, badge, lan, extra="", border="#d0d0d0"):
    extra_lines = [l.strip() for l in extra.split("|") if l.strip()][:3]
    W, H = 200, 90
    extra_svg = ""; y = 62
    for line in extra_lines:
        extra_svg += (f'<text x="68" y="{y}" font-family="Consolas,monospace" '
                      f'font-size="8" fill="#666">{_esc(line[:28])}</text>')
        y += 10
    bw = max(56, len(badge)*7 + 14)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
        f'<rect x="1" y="1" width="{W-2}" height="{H-2}" rx="4" fill="white" stroke="{border}" stroke-width="1.2"/>'
        f'<rect x="10" y="-1" width="{bw}" height="15" rx="2" fill="#2c3e50"/>'
        f'<text x="16" y="10" font-family="Arial,sans-serif" font-size="8.5" '
        f'font-weight="700" fill="white">{_esc(badge)}</text>'
        f'<text x="14" y="52" font-size="28">{icon}</text>'
        f'<text x="68" y="28" font-family="Arial,sans-serif" font-size="11" '
        f'font-weight="600" fill="#2c3e50">{_esc(ip)}</text>'
        f'<text x="68" y="42" font-family="Arial,sans-serif" font-size="9" '
        f'fill="#888">LAN {_esc(lan)}</text>'
        f'{extra_svg}'
        f'</svg>'
    )
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode('utf-8')).decode('ascii')

# -------------------------------------------------------------------
# Clasificación
# -------------------------------------------------------------------
_COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,515,548,554,
    587,631,636,993,995,1080,1194,1433,1521,1688,1723,1883,1900,2049,2082,
    2083,2222,2375,3000,3306,3389,4443,4848,5000,5060,5222,5269,5353,5355,
    5357,5432,5555,5672,5900,5984,6379,6443,7001,7002,7070,7443,7547,7680,
    8000,8006,8008,8009,8080,8081,8088,8090,8161,8443,8554,8834,8888,9000,
    9090,9100,9200,9443,10000,10004,11211,15672,27017,27018,50000,50030,50070
]

def _check_port(ip, port, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try: return (ip, port) if s.connect_ex((ip, port)) == 0 else None
    except Exception: return None
    finally:
        try: s.close()
        except Exception: pass

def detect_rtsp_ports(ip, open_ports):
    """
    Detecta puertos RTSP activos y sus paths.
    Retorna (ports_list, paths_dict):
      - ports_list: [554, 8554, ...] los que responden como RTSP
      - paths_dict: {554: '/Streaming/Channels/101', ...} si se pudo detectar
    """
    detected = []
    paths = {}
    for port in RTSP_PORTS:
        if port not in open_ports:
            continue
        try:
            response = probe_rtsp(ip, port, discover_path=True)
        except Exception:
            response = ""
        if response.upper().startswith("RTSP/"):
            detected.append(port)
            m = re.search(r'PATH:\s*(\S+)', response)
            if m:
                paths[port] = m.group(1).replace('(auth', '').strip()
    return detected, paths

def classify_by_ports(open_ports, rtsp_ports=None):
    p = set(open_ports)
    if 9100 in p or 631 in p or 515 in p:
        return ('Impresora', '🖨️', 'PRINTER')
    if (1688 in p and 7070 in p) or (10004 in p and 7070 in p) or (7680 in p and 7070 in p):
        return ('Impresora HP', '🖨️', 'PRINTER')
    if rtsp_ports:
        return ('Cámara CCTV', '📷', 'CAMERA')
    if 53 in p and (80 in p or 443 in p):
        return ('Router/Gateway', '🌐', 'ROUTER')
    if 3389 in p:
        return ('Windows Server', '🪟', 'SERVER')
    if 22 in p and (80 in p or 443 in p or 3306 in p):
        return ('Servidor Linux', '🖥️', 'SERVER')
    if 5555 in p:
        return ('Android (ADB)', '📱', 'PHONE')
    return None, None, None

def classify_all_devices(devices):
    if not devices: return devices
    all_ports = {d['ip']: [] for d in devices}
    with ThreadPoolExecutor(max_workers=120) as ex:
        futures = []
        for d in devices:
            for p in _COMMON_PORTS:
                futures.append(ex.submit(_check_port, d['ip'], p, 0.8))
        for f in as_completed(futures):
            r = f.result()
            if r: all_ports[r[0]].append(r[1])
    for d in devices:
        d['open_ports'] = sorted(all_ports[d['ip']])
        d.setdefault('rtsp_ports', [])
        d.setdefault('rtsp_paths', {})

    rtsp_candidates = [d for d in devices
                       if any(port in d['open_ports'] for port in RTSP_PORTS)]
    if rtsp_candidates:
        with ThreadPoolExecutor(max_workers=min(32, len(rtsp_candidates))) as ex:
            futures = {ex.submit(detect_rtsp_ports, d['ip'], d['open_ports']): d
                       for d in rtsp_candidates}
            for future in as_completed(futures):
                dev = futures[future]
                try:
                    ports, paths = future.result()
                except Exception:
                    ports, paths = [], {}
                dev['rtsp_ports'] = ports
                dev['rtsp_paths'] = paths

    if not ARGS.no_dns:
        with ThreadPoolExecutor(max_workers=len(devices)) as ex:
            for _ in as_completed([ex.submit(get_hostname, d['ip']) for d in devices]): pass
    for d in devices:
        d['hostname'] = _DNS_CACHE.get(d['ip'], "")
        dtype, icon, badge = classify_by_ports(d['open_ports'], d.get('rtsp_ports'))
        if not dtype:
            dtype, icon, badge = detect_device_kind(d['ip'], d['open_ports'],
                                                     d.get('vendor',''), d['ttl'])
        d['type'] = dtype; d['icon'] = icon; d['badge'] = badge
    return devices

# -------------------------------------------------------------------
# Rebuild node
# -------------------------------------------------------------------
def rebuild_node(dev):
    ip = dev['ip']
    dtype, icon, badge = classify_by_ports(dev.get('open_ports', []),
                                             dev.get('rtsp_ports'))
    if not dtype:
        dtype, icon, badge = detect_device_kind(ip, dev.get('open_ports', []),
                                                 dev.get('vendor',''), dev.get('ttl'))
    dev['type'] = dtype; dev['icon'] = icon; dev['badge'] = badge
    border = "#d0d0d0"
    if   'Impresora' in dtype: border = "#3498db"
    elif 'Cámara'    in dtype: border = "#e74c3c"
    elif 'Servidor'  in dtype: border = "#27ae60"
    elif 'Router'    in dtype or 'AP' in dtype: border = "#9b59b6"
    elif 'Windows'   in dtype: border = "#0078d4"
    elif 'Linux'     in dtype: border = "#f1c40f"
    elif 'macOS'     in dtype: border = "#7f8c8d"
    elif any(k in dtype for k in ('Android','iPhone','iPad','Apple','Móvil')):
        border = "#e67e22"
    elif 'IoT' in dtype or 'Web' in dtype: border = "#f39c12"
    vs = dev.get('vendor') or ''
    extra = []
    if dev.get('hostname'): extra.append(f"HOST: {dev['hostname'][:28]}")
    if vs and vs not in ('Desconocido', 'MAC aleatorizada', 'N/A'):
        extra.append(f"VENDOR: {vs[:28]}")
    if dev.get('source'): extra.append(f"SRC: {dev['source']}")
    if dev.get('open_ports'):
        ps = ",".join(str(p) for p in dev['open_ports'][:5])
        if len(dev['open_ports']) > 5: ps += f" (+{len(dev['open_ports'])-5})"
        extra.append(f"PORTS: {ps}")
    if dev.get('ttl'): extra.append(f"TTL: {dev['ttl']}")
    return {
        "id": ip, "shape": "image",
        "image": make_node_svg(icon, ip, badge, ip, "|".join(extra), border),
        "size": 85,
        "title": f"{dtype}\nMAC: {dev.get('mac','N/A')}\n"
                 f"Vendor: {vs or 'N/A'}\nSource: {dev.get('source','?')}\n"
                 f"Host: {dev.get('hostname') or 'N/A'}\n"
                 f"Ports: {','.join(str(p) for p in dev.get('open_ports', [])[:15])}"
    }

# =====================================================================
# SYN SCAN FULL PARALELO — L2
# =====================================================================
def syn_scan_full_l2_parallel(ip, mac, num_workers=12, chunk_size=1500, timeout=0.8):
    """
    SYN scan L2 paralelo con hilos.
    - 12 workers concurrentes, cada uno escanea ~5461 puertos.
    - Chunks de 1500 con timeout 0.8s.
    - Solo UNA pasada paralela + verificación paralela de puertos críticos.
    - Total: 4-8 segundos para 1-65535 puertos.
    """
    all_ports = list(range(1, 65536))
    open_ports = set()
    responded_all = set()
    lock = threading.Lock()
    t0 = time.time()

    groups = [[] for _ in range(num_workers)]
    for i, p in enumerate(all_ports):
        groups[i % num_workers].append(p)

    def worker(ports_list, worker_id):
        local_open = set()
        local_responded = set()
        for i in range(0, len(ports_list), chunk_size):
            chunk = ports_list[i:i+chunk_size]
            src_port = random.randint(1024, 65535)
            packets = [Ether(dst=mac) / IP(dst=ip) / TCP(sport=src_port, dport=p, flags='S')
                       for p in chunk]
            try:
                ans, _ = srp(packets, timeout=timeout, verbose=0)
                for sent, rcv in ans:
                    if rcv.haslayer(TCP):
                        local_responded.add(sent[TCP].dport)
                        if rcv[TCP].flags == 0x12:  # SYN-ACK
                            local_open.add(sent[TCP].dport)
            except Exception:
                pass
        with lock:
            open_ports.update(local_open)
            responded_all.update(local_responded)

    print(f"[*] SYN scan L2 PARALELO: {num_workers} workers × chunks {chunk_size}, timeout {timeout}s")
    threads = [threading.Thread(target=worker, args=(g, i), daemon=True)
               for i, g in enumerate(groups)]
    for t in threads: t.start()
    for t in threads: t.join()

    elapsed1 = time.time() - t0
    print(f"    Pasada 1 ({elapsed1:.1f}s): {len(responded_all)}/{len(all_ports)} respondieron, "
          f"{len(open_ports)} abiertos: {sorted(open_ports)}")

    critical_ports = [9100, 631, 515, 80, 443, 8080, 8443, 8000, 8888, 9000,
                      21, 22, 23, 25, 161, 445, 3389, 1688, 7070, 10004,
                      7680, 5000, 3000, 53, 5355, 5357, 554, 8554, 5001]
    missing_critical = [p for p in critical_ports if p not in responded_all]

    if missing_critical:
        print(f"    Pasada 2: verificando {len(missing_critical)} puertos críticos en paralelo...")
        def check_critical(port):
            src_port = random.randint(1024, 65535)
            pkt = Ether(dst=mac) / IP(dst=ip) / TCP(sport=src_port, dport=port, flags='S')
            try:
                ans = srp1(pkt, timeout=2.5, verbose=0)
                if ans and ans.haslayer(TCP) and ans[TCP].flags == 0x12:
                    with lock:
                        open_ports.add(port)
                    return port
            except Exception: pass
            return None

        with ThreadPoolExecutor(max_workers=len(missing_critical)) as ex:
            for r in ex.map(check_critical, missing_critical):
                if r: print(f"        -> {r} ABIERTO (verificado en P2)")

    elapsed = time.time() - t0
    return sorted(open_ports), elapsed


def connect_scan_full(ip, timeout=0.6, max_workers=300):
    """Fallback connect_ex paralelo."""
    opened = []
    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0: return p
        except Exception: pass
        finally:
            try: s.close()
            except Exception: pass
        return None
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(check, range(1, 65536)):
            if r: opened.append(r)
    return sorted(set(opened)), time.time() - t0


def discover_open_ports(ip):
    # === NUEVO: modo single-target → forzar L3, sin MAC ===
    if SINGLE_MODE:
        print(f"    [*] Single-target L3 scan de {ip} (sin MAC)")
        ports = syn_scan_l3_single(ip, ports=None, timeout=1.0)
        print(f"    -> {len(ports)} puertos abiertos: {ports[:30]}")
        return ports
    # === FIN NUEVO ===

    mac = None
    for d in topology_data.get("devices", []):
        if d['ip'] == ip:
            mac = d.get('mac', ''); break
    if not mac or mac.startswith("N/A") or mac == "N/A (L3)":
        print(f"    [*] Resolviendo MAC de {ip}...")
        mac = get_mac_for_ip(ip)

    if not mac:
        print(f"    [!] Sin MAC → fallback connect_ex()")
        ports, elapsed = connect_scan_full(ip)
        print(f"    -> {len(ports)} puertos en {elapsed:.1f}s: {ports[:30]}")
        return ports

    print(f"[*] SYN scan PARALELO vía L2 en {ip} (mac {mac})")
    ports, elapsed = syn_scan_full_l2_parallel(ip, mac,
                                                num_workers=ARGS.workers,
                                                chunk_size=1500,
                                                timeout=0.8)
    print(f"    -> {len(ports)} puertos abiertos en {elapsed:.1f}s: {ports[:30]}")

    if not ports:
        print(f"    [!] SYN L2 devolvió 0 → connect_ex() paralelo")
        p2, e2 = connect_scan_full(ip)
        ports = sorted(set(ports) | set(p2))
        print(f"    -> connect_ex: {len(p2)} en {e2:.1f}s")
    return ports

# =====================================================================
# *** SYN SCAN L3 PARA SINGLE TARGET (IP pública/privada/DNS) ***
# =====================================================================
def syn_scan_full_l3_parallel(ip, ports=None, num_workers=12, chunk_size=1000, timeout=1.0):
    """
    SYN scan L3 puro (IP/TCP) para un único target — sin necesitar MAC.
    Ideal para IPs remotas/públicas o resueltas por DNS.
    - No usa Ether() → funciona enrutado a través de gateways.
    - Requiere privilegios (root/admin) por el uso de raw sockets.
    """
    if ports is None:
        ports = list(range(1, 65536))
    open_ports = set()
    responded_all = set()
    lock = threading.Lock()
    t0 = time.time()

    groups = [[] for _ in range(num_workers)]
    for i, p in enumerate(ports):
        groups[i % num_workers].append(p)

    def worker(ports_list):
        local_open = set()
        local_responded = set()
        for i in range(0, len(ports_list), chunk_size):
            chunk = ports_list[i:i+chunk_size]
            src_port = random.randint(1024, 65535)
            packets = [IP(dst=ip) / TCP(sport=src_port, dport=p, flags='S')
                       for p in chunk]
            try:
                ans, _ = sr(packets, timeout=timeout, verbose=0)
                for sent, rcv in ans:
                    if rcv.haslayer(TCP):
                        local_responded.add(sent[TCP].dport)
                        if rcv[TCP].flags == 0x12:  # SYN-ACK
                            local_open.add(sent[TCP].dport)
            except Exception:
                pass
        with lock:
            open_ports.update(local_open)
            responded_all.update(local_responded)

    threads = [threading.Thread(target=worker, args=(g,), daemon=True)
               for g in groups]
    for t in threads: t.start()
    for t in threads: t.join()

    elapsed = time.time() - t0
    return sorted(open_ports), sorted(responded_all), elapsed


def syn_scan_l3_single(ip, ports=None, num_workers=None, timeout=1.0):
    """
    Escaneo L3 de un único target. connect_ex primero (rápido y sin privilegios),
    luego SYN raw L3 como verificación cruzada.
    """
    if num_workers is None:
        num_workers = ARGS.workers
    if ports is None:
        ports = list(range(1, 65536))

    open_ports = set()

    # --- Pasada 1: connect_ex paralelo (no requiere root/admin) ---
    print(f"[*] Connect scan paralelo en {ip} ({len(ports)} puertos)...")
    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            if s.connect_ex((ip, p)) == 0: return p
        except Exception: pass
        finally:
            try: s.close()
            except Exception: pass
        return None
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=400) as ex:
        for r in ex.map(check, ports):
            if r: open_ports.add(r)
    print(f"    connect_ex: {len(open_ports)} abiertos en {time.time()-t0:.1f}s")

    # --- Pasada 2: SYN raw L3 (complementa, detecta puertos filtrados) ---
    try:
        print(f"[*] SYN raw L3 (verificación cruzada)...")
        op2, resp, el2 = syn_scan_full_l3_parallel(
            ip, ports=ports, num_workers=num_workers,
            chunk_size=2000, timeout=0.8)
        nuevos = set(op2) - open_ports
        if nuevos:
            print(f"    SYN raw: +{len(nuevos)} nuevos ({sorted(nuevos)[:20]})")
        open_ports.update(op2)
    except PermissionError:
        print(f"    [!] Sin privilegios para SYN raw (OK, connect_ex ya escaneó)")
    except Exception as e:
        print(f"[!] SYN raw falló: {e}")

    return sorted(open_ports)


def run_single_target_scan(target):
    """
    Escaneo Layer 3 de un único target (IP pública/privada o DNS) por CLI.
    NO muestra topología. Solo puertos, servicios y versiones.
    """
    hostname_dns = ""
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            hostname_dns = target
        except Exception as e:
            print(f"[!] No se pudo resolver '{target}': {e}")
            sys.exit(1)

    print("=" * 60)
    print("  NETWORK TREE SCANNER — SINGLE TARGET (L3 CLI)")
    print(f"  Target:  {target}")
    print(f"  IP:      {ip}")
    if hostname_dns:
        print(f"  DNS:     {hostname_dns} → {ip}")
    print(f"  Workers: {ARGS.workers}")
    print("=" * 60)

    if ARGS.ports:
        ports_to_scan = sorted(set(ARGS.ports_list))
        print(f"[*] Puertos personalizados: {len(ports_to_scan)} ({ports_to_scan[:20]}"
              f"{'...' if len(ports_to_scan) > 20 else ''})")
    else:
        ports_to_scan = list(range(1, 65536))
        print(f"[*] Escaneo completo 1-65535")

    print(f"\n[*] Fase 1: descubriendo puertos abiertos en {ip}...")
    t0 = time.time()
    open_ports = syn_scan_l3_single(ip, ports=ports_to_scan, timeout=1.0)
    print(f"[*] Fase 1 completada: {len(open_ports)} puertos abiertos en {time.time()-t0:.1f}s")

    if not open_ports:
        print("[!] No se encontraron puertos abiertos (o el host está detrás de un firewall "
              "que descarta paquetes).")
        return

    print(f"\n[*] Fase 2: identificando servicios y versiones "
          f"({len(open_ports)} puertos, paralelo)...")
    t1 = time.time()
    results = []
    def do_probe(p):
        try:
            return identify_service_full(ip, p)
        except Exception as e:
            return {'port': p, 'service': 'error', 'version': str(e)[:80],
                    'banner': '', 'tcpwrapped': False}
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(open_ports)))) as ex:
        for r in ex.map(do_probe, open_ports):
            results.append(r)
    results.sort(key=lambda x: x['port'])
    print(f"[*] Fase 2 completada en {time.time()-t1:.1f}s")

    print("\n" + "=" * 60)
    print(f"  RESULTADOS — {ip}" + (f" ({hostname_dns})" if hostname_dns else ""))
    print("=" * 60)
    print(f"{'PUERTO':>7}  {'SERVICIO':<24}  {'VERSIÓN / BANNER'}")
    print("-" * 60)
    for r in results:
        ver = r.get('version') or r.get('banner') or ''
        if r.get('tcpwrapped'):
            ver = 'tcpwrapped'
        ver = ver.replace('\n', ' ').replace('\r', ' ').strip()
        print(f"{r['port']:>7}  {r['service']:<24}  {ver[:80]}")
    print("-" * 60)
    print(f"[*] Total: {len(results)} servicios identificados.")
    print(f"[*] RUN_ID: {RUN_ID}")
    print("=" * 60)


# -------------------------------------------------------------------
# Sondas
# -------------------------------------------------------------------
def is_tcpwrapped(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((ip, port))
        s.settimeout(1.0)
        try:
            data = s.recv(64); s.close()
            return len(data) == 0
        except socket.timeout:
            s.close(); return False
    except Exception: return False

def probe_http(ip, port, timeout=2.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((ip, port))
        s.send((f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScanner\r\n"
                f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        chunks = []; total = 0
        while total < 8192:
            try:
                c = s.recv(2048)
                if not c: break
                chunks.append(c); total += len(c)
            except socket.timeout: break
        s.close(); return b''.join(chunks).decode(errors='ignore')
    except Exception: return ""

def probe_https(ip, port=443, timeout=3.0):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        w = ctx.wrap_socket(s, server_hostname=ip)
        w.connect((ip, port))
        cert = w.getpeercert(binary_form=False); version = w.version(); cipher = w.cipher()
        w.close()
        parts = []
        if version: parts.append(version)
        if cipher: parts.append(f"cipher={cipher[0]}")
        if cert:
            subj = dict(x[0] for x in cert.get('subject', [])) if cert else {}
            if subj.get('commonName'): parts.append(f"CN={subj['commonName']}")
        return " | ".join(parts) if parts else "TLS OK"
    except Exception: return ""

def probe_dns(ip, port=53, timeout=3):
    try:
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for label in b'version.bind'.split(b'.'):
            query += bytes([len(label)]) + label
        query += b'\x00' + b'\x00\x10' + b'\x03'
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (ip, port))
        data, _ = s.recvfrom(512); s.close()
        strings = re.findall(rb'[\x20-\x7e]{3,}', data)
        for b in strings:
            st = b.decode('ascii', errors='ignore')
            if st.lower() in ('version', 'bind', 'txt', 'version.bind'): continue
            return st
        return "DNS activo (sin version.bind)"
    except socket.timeout:
        return "DNS (version.bind no responde)"
    except Exception: return ""

def probe_banner(ip, port, timeout=2, send=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((ip, port))
        if send: s.send(send)
        try: data = s.recv(2048).decode(errors='ignore').strip()
        except socket.timeout: data = ""
        s.close(); return data
    except Exception: return ""

def probe_mysql(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((ip, port))
        d = s.recv(256); s.close()
        if len(d) > 5: return d[5:60].split(b'\x00')[0].decode(errors='ignore')
    except Exception: pass
    return ""

def probe_redis(ip, port, timeout=2): return probe_banner(ip, port, timeout, send=b"PING\r\n")

def probe_smtp(ip, port, timeout=2):
    return (probe_banner(ip, port, timeout) + "\n" +
            probe_banner(ip, port, timeout, send=b"EHLO scanner.local\r\n")).strip()

def probe_smb(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((ip, port))
        s.send(bytes.fromhex(
            "00000085ff534d42720000000018012800000000000000000000000000002f4b"
            "0000c15500000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000"))
        d = s.recv(512).decode(errors='ignore'); s.close()
        return "SMB/CIFS presente" if ("SMB" in d or "NT LM" in d) else d.strip()[:200]
    except Exception: return ""

def probe_rtsp(ip, port, timeout=2, uri=None, discover_path=False):
    """
    Sondea un puerto RTSP.
    - discover_path=False: solo OPTIONS (comportamiento clásico).
    - discover_path=True: tras confirmar RTSP, prueba RTSP_COMMON_PATHS con
      DESCRIBE y devuelve 'PATH: <path>' si alguno responde 200 o 401.
    """
    try:
        target = uri or "rtsp://%s:%d/" % (ip, port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(("OPTIONS %s RTSP/1.0\r\nCSeq: 1\r\n\r\n" % target).encode())
            data = bytearray()
            while len(data) < 4096 and b'\r\n' not in data:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data.extend(chunk)
            banner = data.decode(errors='ignore').strip()

            if not discover_path or not banner.upper().startswith("RTSP/"):
                return banner

            # Ya sabemos que es RTSP. Probamos paths comunes con DESCRIBE.
            for path in RTSP_COMMON_PATHS:
                try:
                    s.sendall(("DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
                               "CSeq: 2\r\nAccept: application/sdp\r\n"
                               "User-Agent: NetTreeScanner\r\n\r\n"
                               % (ip, port, path)).encode())
                    resp = s.recv(2048).decode(errors='ignore')
                    status_line = resp.split('\r\n', 1)[0]
                    if 'RTSP/1.0 200' in status_line and (
                            'application/sdp' in resp or 'v=0' in resp):
                        return banner + "\nPATH: " + path
                    if 'RTSP/1.0 401' in status_line:
                        return banner + "\nPATH: " + path + " (auth requerida)"
                except Exception:
                    break
            return banner
    except Exception:
        return ""

def probe_ntp(ip, port=123, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'\x1b' + 47 * b'\0', (ip, port))
        d, _ = s.recvfrom(1024); s.close()
        if len(d) >= 48: return f"NTP stratum {d[1]}"
    except Exception: pass
    return ""

PORT_INFO = {
    21:("FTP",lambda i,p: probe_banner(i,p)), 22:("SSH",lambda i,p: probe_banner(i,p)),
    23:("Telnet",lambda i,p: probe_banner(i,p)), 25:("SMTP",lambda i,p: probe_smtp(i,p)),
    53:("DNS",lambda i,p: probe_dns(i,p)), 80:("HTTP",lambda i,p: probe_http(i,p)),
    110:("POP3",lambda i,p: probe_banner(i,p)), 123:("NTP",lambda i,p: probe_ntp(i,p)),
    135:("MS-RPC",lambda i,p: ""), 139:("NetBIOS",lambda i,p: probe_smb(i,p)),
    143:("IMAP",lambda i,p: probe_banner(i,p)), 443:("HTTPS",lambda i,p: probe_https(i,p)),
    445:("SMB",lambda i,p: probe_smb(i,p)), 554:("RTSP",lambda i,p: probe_rtsp(i,p)),
    8554:("RTSP",lambda i,p: probe_rtsp(i,p)),
    631:("IPP",lambda i,p: probe_http(i,p)), 993:("IMAPS",lambda i,p: probe_banner(i,p)),
    995:("POP3S",lambda i,p: probe_banner(i,p)), 1433:("MSSQL",lambda i,p: ""),
    1688:("MSMQ / HP JetAdmin", lambda i,p: ""),
    3306:("MySQL",lambda i,p: probe_mysql(i,p)), 3389:("RDP",lambda i,p: ""),
    5355:("LLMNR", lambda i,p: ""), 5432:("PostgreSQL",lambda i,p: ""),
    5555:("ADB (Android)",lambda i,p: ""), 5900:("VNC",lambda i,p: probe_banner(i,p)),
    6379:("Redis",lambda i,p: probe_redis(i,p)),
    7070:("HP Web Services", lambda i,p: probe_http(i,p)),
    7547:("TR-069",lambda i,p: ""), 7680:("HP Device Mgmt", lambda i,p: ""),
    8000:("HTTP-Alt",lambda i,p: probe_http(i,p)),
    8080:("HTTP-Alt",lambda i,p: probe_http(i,p)),
    8443:("HTTPS-Alt",lambda i,p: probe_https(i,p)),
    8888:("HTTP-Alt",lambda i,p: probe_http(i,p)),
    9100:("JetDirect",lambda i,p: probe_banner(i,p)),
    10004:("HP Device Mgmt", lambda i,p: ""),
    27017:("MongoDB",lambda i,p: ""), 52869:("TR-069 (CWMP)",lambda i,p: ""),
}

def extract_version(port, banner):
    if not banner: return ""
    txt = banner.replace('\r\n', '\n'); lines = txt.split('\n')
    if port in (80, 8080, 8888, 8000, 631, 443, 8443, 7070):
        parts = []
        if lines and lines[0].startswith('HTTP/'): parts.append(lines[0].strip())
        for line in lines:
            ll = line.lower()
            if ll.startswith('server:'): parts.append(line.split(':', 1)[1].strip())
            elif ll.startswith('x-powered-by:'): parts.append("PHP/" + line.split(':', 1)[1].strip())
        return ' | '.join(parts) if parts else ""
    if port == 53: return banner.strip()
    if port == 22:
        if lines and lines[0].startswith('SSH-'): return lines[0].strip()
    if port == 3306: return banner.strip()[:120]
    if port in (21, 25, 110, 143, 465, 587, 993, 995): return lines[0].strip()[:120]
    if port == 5900: return lines[0].strip()[:60]
    return lines[0].strip()[:120]

def identify_service_full(ip, port):
    entry = PORT_INFO.get(port, (None, None))
    if entry[0]: service, probe = entry
    else: service, probe = "Desconocido", lambda i,p: probe_banner(i,p)
    banner = ""
    if probe:
        try: banner = (probe(ip, port) or "").strip()
        except Exception: banner = ""
    tcpwrapped = False
    if not banner: tcpwrapped = is_tcpwrapped(ip, port)
    version = extract_version(port, banner)
    return {'port': port, 'service': service, 'version': version,
            'banner': banner[:400], 'tcpwrapped': tcpwrapped}

# -------------------------------------------------------------------
# Rutas Flask
# -------------------------------------------------------------------
@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index(): return render_template_string(HTML_TEMPLATE)

@app.route('/api/version')
def api_version(): return jsonify({'run_id': RUN_ID})

@app.route('/api/topology')
def api_topology():
    print(f"[API] /api/topology → {len(topology_data['nodes'])} nodos, "
          f"{len(topology_data['edges'])} edges (run {RUN_ID})")
    return jsonify(topology_data)

@app.route('/api/debug')
def api_debug(): return jsonify(topology_data)

# === NUEVO: ventana emergente para "Ver en vivo" ===
@app.route('/stream-popup/<stream_id>')
def stream_popup(stream_id):
    with _STREAM_SESSIONS_LOCK:
        if stream_id not in _STREAM_SESSIONS:
            return "Stream no encontrado o expirado", 404
    return render_template_string(POPUP_TEMPLATE, stream_id=stream_id)
# === FIN NUEVO ===

def _stop_stream_process(process):
    if not process or process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

@app.route('/api/stream/start', methods=['POST'])
def api_stream_start():
    data = request.get_json(silent=True) or {}
    stream_url = data.get('url', '')
    if (not isinstance(stream_url, str) or not stream_url or len(stream_url) > 2048
            or any(ord(char) < 32 for char in stream_url)):
        return jsonify({'error': 'Indica una URL RTSP válida (máximo 2048 caracteres).'}), 400

    try:
        parsed = urlsplit(stream_url)
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 554
    except ValueError:
        return jsonify({'error': 'La URL RTSP tiene un host o puerto inválido.'}), 400
    if (parsed.scheme.lower() != 'rtsp' or not host or parsed.fragment
            or port < 1 or port > 65535):
        return jsonify({'error': 'Usa una URL RTSP completa, por ejemplo rtsp://IP:554/ruta.'}), 400

    try:
        target_ip = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            target_ip = socket.gethostbyname(host)
        except OSError:
            return jsonify({'error': 'No se pudo resolver el host RTSP.'}), 400
    device = next((item for item in topology_data.get('devices', [])
                   if item.get('ip') == target_ip), None)
    if not device:
        return jsonify({'error': 'El host RTSP no pertenece a un dispositivo detectado.'}), 403
    if port not in device.get('open_ports', []):
        return jsonify({'error': 'El puerto RTSP no figura abierto. Escanea primero el dispositivo.'}), 400

    path = parsed.path or '/'
    probe_uri = "rtsp://%s:%d%s%s" % (
        target_ip, port, path, ("?" + parsed.query) if parsed.query else "")
    response = probe_rtsp(target_ip, port, timeout=2, uri=probe_uri)
    if not response.upper().startswith("RTSP/"):
        return jsonify({'error': 'El puerto abierto no respondió como un servicio RTSP.'}), 400

    ffmpeg = shutil.which(ARGS.ffmpeg)
    if not ffmpeg:
        return jsonify({'error': 'No se encontró FFmpeg. Instálalo o indica su ruta con --ffmpeg.'}), 503

    stream_id = secrets.token_urlsafe(24)
    session = {'url': stream_url, 'ffmpeg': ffmpeg, 'process': None}
    with _STREAM_SESSIONS_LOCK:
        _STREAM_SESSIONS[stream_id] = session
    return jsonify({'stream_id': stream_id,
                    'stream_url': '/api/stream/' + stream_id})

@app.route('/api/stream/<stream_id>')
def api_stream_video(stream_id):
    with _STREAM_SESSIONS_LOCK:
        session = _STREAM_SESSIONS.get(stream_id)
        if not session:
            return jsonify({'error': 'El stream no existe o ya fue detenido.'}), 404
        if not session.get('process'):
            try:
                session['process'] = subprocess.Popen(
                    [session['ffmpeg'], '-nostdin', '-hide_banner', '-loglevel', 'error',
                     '-rtsp_transport', 'tcp', '-i', session['url'], '-an',
                     '-vf', 'fps=10,scale=960:-2', '-q:v', '5', '-f', 'mpjpeg', 'pipe:1'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, bufsize=0,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            except OSError:
                _STREAM_SESSIONS.pop(stream_id, None)
                logging.exception("No se pudo iniciar FFmpeg para el stream RTSP")
                return jsonify({'error': 'No se pudo iniciar FFmpeg. Revisa la ruta configurada.'}), 503
    if not session.get('process'):
        return jsonify({'error': 'El stream no existe o ya fue detenido.'}), 404
    process = session['process']

    def generate():
        try:
            if process.stdout:
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        break
                    yield chunk
        finally:
            _stop_stream_process(process)
            with _STREAM_SESSIONS_LOCK:
                _STREAM_SESSIONS.pop(stream_id, None)

    return Response(generate(), content_type='multipart/x-mixed-replace; boundary=ffmpeg',
                    headers={'X-Accel-Buffering': 'no'})

@app.route('/api/stream/stop', methods=['POST'])
def api_stream_stop():
    data = request.get_json(silent=True) or {}
    stream_id = data.get('stream_id')
    if not isinstance(stream_id, str) or not stream_id:
        return jsonify({'error': 'Falta el identificador del stream.'}), 400
    with _STREAM_SESSIONS_LOCK:
        session = _STREAM_SESSIONS.pop(stream_id, None)
    if session:
        _stop_stream_process(session.get('process'))
    return jsonify({'stopped': bool(session)})

@socketio.on('request_port_scan')
def handle_port_scan(data):
    target_ip = data['ip']
    print(f"\n[*] Fase 1: puertos abiertos en {target_ip}")
    def run_scan():
        try:
            t0 = time.time()
            opened = discover_open_ports(target_ip)
            print(f"    -> {len(opened)} puertos en {time.time()-t0:.1f}s total")
            rtsp_ports, rtsp_paths = detect_rtsp_ports(target_ip, opened)
            if rtsp_ports:
                print(f"    -> RTSP detectado en puertos {rtsp_ports}, paths: {rtsp_paths}")
            dev = next((d for d in topology_data["devices"] if d['ip'] == target_ip), None)
            if dev:
                dev['open_ports'] = opened
                dev['rtsp_ports'] = rtsp_ports
                dev['rtsp_paths'] = rtsp_paths
                new_node = rebuild_node(dev)
                for i, n in enumerate(topology_data["nodes"]):
                    if n['id'] == target_ip:
                        topology_data["nodes"][i] = new_node; break
                else: topology_data["nodes"].append(new_node)
                socketio.emit('node_update', new_node, to=None)
                print(f"    -> Reclasificado: {dev['type']}")
            payload = {'ip': target_ip, 'results': [{'port': p} for p in opened],
                       'rtsp_ports': rtsp_ports,
                       'rtsp_paths': rtsp_paths}
        except Exception as e:
            print(f"[!] Error: {e}")
            payload = {'ip': target_ip, 'results': [], 'error': str(e)}
        socketio.emit('port_scan_result', payload, to=None)
    socketio.start_background_task(run_scan)
    return {'status': 'ok'}

@socketio.on('request_service_scan')
def handle_service_scan(data):
    target_ip = data['ip']
    ports = data.get('ports') or []
    print(f"\n[*] Fase 2: servicios en {target_ip}")
    def run_scan():
        try:
            results = []
            for p in ports:
                r = identify_service_full(target_ip, p)
                results.append(r)
                print(f"    {p:5}  {r['service']:20}  "
                      f"{'tcpwrapped' if r['tcpwrapped'] else r['version'][:50]}")
            dev = next((d for d in topology_data["devices"] if d['ip'] == target_ip), None)
            if dev:
                dev['open_ports'] = sorted(set(dev.get('open_ports', []) +
                                               [r['port'] for r in results]))
                new_node = rebuild_node(dev)
                for i, n in enumerate(topology_data["nodes"]):
                    if n['id'] == target_ip:
                        topology_data["nodes"][i] = new_node; break
                socketio.emit('node_update', new_node, to=None)
            payload = {'ip': target_ip, 'results': results}
        except Exception as e:
            print(f"[!] Error: {e}")
            payload = {'ip': target_ip, 'results': [], 'error': str(e)}
        socketio.emit('service_scan_result', payload, to=None)
    socketio.start_background_task(run_scan)
    return {'status': 'ok'}

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def normalize_target(target):
    try:
        ip = ipaddress.ip_address(target)
        return str(ipaddress.ip_network(f"{target}/24", strict=False)), str(ip)
    except ValueError:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return str(net), str(next(net.hosts()))
        except ValueError:
            print(f"[!] Formato inválido: {target}"); sys.exit(1)

if __name__ == '__main__':
    # ------------------------------------------------------------------
    # Modo single-target:
    #   -s                    → abre navegador con el target (L3 scan desde web)
    #   -s --no-browser       → escaneo CLI directo
    # ------------------------------------------------------------------
    if ARGS.single:
        # --- Modo CLI puro ---
        if ARGS.no_browser:
            run_single_target_scan(ARGS.target)
            sys.exit(0)

        # --- Modo navegador ---
        hostname_dns = ""
        try:
            ipaddress.ip_address(ARGS.target)
            target_ip = ARGS.target
        except ValueError:
            try:
                target_ip = socket.gethostbyname(ARGS.target)
                hostname_dns = ARGS.target
            except Exception as e:
                print(f"[!] No se pudo resolver '{ARGS.target}': {e}")
                sys.exit(1)

        SINGLE_MODE = True
        SINGLE_TARGET_IP = target_ip

        print("=" * 60)
        print("  NETWORK TREE SCANNER — SINGLE TARGET (Browser / L3)")
        print(f"  Input:   {ARGS.target}")
        print(f"  IP:      {target_ip}")
        if hostname_dns:
            print(f"  DNS:     {hostname_dns} → {target_ip}")
        print(f"  RUN_ID:  {RUN_ID}")
        print("=" * 60)
        print("[*] Abriendo navegador. El panel se abrirá solo (?auto=1).")

        extra = "Single target L3"
        if hostname_dns:
            extra += f"|DNS: {hostname_dns[:24]}"

        node = {
            "id": target_ip, "shape": "image",
            "image": make_node_svg('🎯', target_ip, 'TARGET',
                                    hostname_dns or target_ip,
                                    extra, '#e74c3c'),
            "size": 85,
            "title": f"Single Target\n{ARGS.target} → {target_ip}"
        }
        topology_data["nodes"] = [node]
        topology_data["edges"] = []
        topology_data["devices"] = [{
            "ip": target_ip, "mac": "N/A", "vendor": "N/A",
            "source": "L3", "type": "Single Target", "icon": "🎯",
            "badge": "TARGET", "os": "", "ttl": None,
            "hostname": hostname_dns, "open_ports": [],
            "rtsp_ports": [], "rtsp_paths": {}
        }]
        topology_data["target"]  = f"{ARGS.target} ({target_ip})"
        topology_data["gateway"] = None
        topology_data["run_id"]  = RUN_ID

        url = f'http://127.0.0.1:{ARGS.web_port}/?run={RUN_ID}&auto=1'
        print(f"[*] URL: {url}")
        threading.Timer(1.5, lambda: webbrowser.open_new(url)).start()

        socketio.run(app, host='0.0.0.0', port=ARGS.web_port, debug=False,
                     allow_unsafe_werkzeug=True, log_output=False)
        sys.exit(0)

    # ------------------------------------------------------------------
    # Modo red completa
    # ------------------------------------------------------------------
    network_cidr, gateway_ip = normalize_target(ARGS.target)

    print("=" * 60)
    print("  NETWORK TREE SCANNER")
    print(f"  Red objetivo: {network_cidr}")
    print(f"  Gateway:      {gateway_ip}")
    print(f"  RUN_ID:       {RUN_ID}")
    modo = []
    if ARGS.layer2: modo.append("L2 (ARP)")
    if ARGS.layer3: modo.append(f"L3 (TCP SYN: {ARGS.ports_list})")
    if ARGS.icmp:   modo.append("ICMP (Echo)")
    print(f"  Modo:         {' + '.join(modo)}")
    print(f"  Workers SYN:  {ARGS.workers}")
    print("=" * 60)

    seen = discover_hosts(network_cidr, gateway_ip)
    print(f"\n[*] {len(seen)} dispositivos únicos descubiertos.")

    nodes = [{
        "id": gateway_ip, "shape": "image",
        "image": make_node_svg('🌐', gateway_ip, 'ROUTER', gateway_ip, 'Gateway de red', '#3498db'),
        "size": 85, "title": "Gateway de red"
    }]
    edges = []; devices = []
    for ip, info in seen.items():
        mac = info.get("mac", "N/A")
        vendor = get_vendor(mac)
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "source": info.get("source", "?"),
            "type": "Desconocido", "icon": "💻", "badge": "HOST",
            "os": "", "ttl": None, "hostname": "", "open_ports": [],
            "rtsp_ports": [], "rtsp_paths": {}
        })
        edges.append({"from": gateway_ip, "to": ip})

    ttl_map = detect_ttls(devices)
    for d in devices: d['ttl'] = ttl_map.get(d['ip'])

    print("[*] Clasificando dispositivos en paralelo...")
    t0 = time.time()
    classify_all_devices(devices)
    print(f"[*] Clasificación completada en {time.time()-t0:.1f}s")

    for dev in devices:
        node = rebuild_node(dev)
        nodes.append(node)
        ttl_str = str(dev['ttl']) if dev['ttl'] else '?'
        rtsp_info = ""
        if dev.get('rtsp_ports'):
            rtsp_info = f"  RTSP:{dev['rtsp_ports']}"
        print(f"   -> {dev['ip']:15} {dev['icon']}  {dev['type']:22}  "
              f"TTL:{ttl_str:5}  {dev['badge']:8}  [{dev['source']:10}]  "
              f"vendor: {(dev['vendor'] or 'N/A')[:22]:22}  "
              f"ports: {dev['open_ports'][:8]}{rtsp_info}")

    topology_data["nodes"] = nodes
    topology_data["edges"] = edges
    topology_data["devices"] = devices
    topology_data["run_id"] = RUN_ID
    topology_data["target"] = network_cidr
    topology_data["gateway"] = gateway_ip

    print(f"\n[*] Topología lista: {len(nodes)} nodos.")
    print(f"[*] URL: http://127.0.0.1:{ARGS.web_port}/?run={RUN_ID}")

    if not ARGS.no_browser:
        url = f'http://127.0.0.1:{ARGS.web_port}/?run={RUN_ID}'
        threading.Timer(1.5, lambda: webbrowser.open_new(url)).start()

    socketio.run(app, host='0.0.0.0', port=ARGS.web_port, debug=False,
                 allow_unsafe_werkzeug=True, log_output=False)