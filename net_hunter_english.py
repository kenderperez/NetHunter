#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Tree Scanner - Scapy + vis-network
Usage: python net_tree.py [target] [-l2] [-l3] [-icmp] [options]

Recommended installation:
  pip install scapy flask flask-socketio mac-vendor-lookup
  Install FFmpeg on the system and make sure it is in PATH to view RTSP streams.

Included improvements:
  - Automatic RTSP path detection (Hikvision, Dahua, ONVIF, generic).
  - RTSP → MJPEG streaming via FFmpeg with tokenized sessions.
  - Strict URL/host/port validation before launching FFmpeg (anti-SSRF).
  - "View live in new window" button for detected CCTV cameras.
  - Automatic gateway and subnet mask detection (cross-platform).
  - If an IP is passed without a prefix and falls within the local network, the real mask is used.
"""

import sys, os, re, random, base64, ipaddress, threading, webbrowser, uuid, json
import socket, subprocess, urllib.request, logging, ssl, time, struct, warnings
import secrets, shutil
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
from flask import Flask, render_template_string, jsonify, request, Response, send_from_directory
from flask_socketio import SocketIO
from scapy.all import ARP, Ether, srp, srp1, IP, TCP, ICMP, sr, sr1, conf

# -------------------------------------------------------------------
# Silence warnings
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
# CLI arguments
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(prog="net_tree.py")
    parser.add_argument("target", nargs="?", default="10.0.9.1")
    parser.add_argument("-l2", "--layer2", action="store_true")
    parser.add_argument("-l3", "--layer3", action="store_true")
    parser.add_argument("-icmp", "--icmp", action="store_true")
    parser.add_argument("-s", "--single", action="store_true",
                        help="Scan a single target (public/private IP or DNS) "
                             "via Layer 3. Opens the browser and launches the scan from there.")
    parser.add_argument("-p", "--ports", default=None)
    parser.add_argument("-t", "--timeout", type=float, default=2.0)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--web-port", type=int, default=5000)
    parser.add_argument("--no-dns", action="store_true")
    parser.add_argument("--workers", type=int, default=12,
                        help="Parallel workers for SYN scan (default 12)")
    parser.add_argument("--ffmpeg", default="ffmpeg",
                        help="Path to FFmpeg to convert RTSP streams (default: ffmpeg)")

    args = parser.parse_args()
    if not args.single and not args.layer2 and not args.layer3 and not args.icmp:
        args.layer2 = True; args.layer3 = True
    if args.ports:
        try:
            args.ports_list = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("[!] Invalid format. Use: -p 22,80,443"); sys.exit(1)
    else:
        args.ports_list = [80, 443, 22, 445, 3389, 8080]
    return args

ARGS = parse_args()

# === NEW: global single-target state ===
SINGLE_MODE = ARGS.single
SINGLE_TARGET_IP = None
# === END NEW ===

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
                print(f"[*] manuf DB loaded: {p}")
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
        print("[*] mac-vendor-lookup DB ready")
    except Exception:
        _MAC_AVAILABLE = True
except ImportError:
    print("[!] mac-vendor-lookup NOT installed → pip install mac-vendor-lookup")
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

# Common paths for auto-detection with DESCRIBE
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
# NEW: Popup template for "Live view"
# ===================================================================
POPUP_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>🎥 Live camera</title>
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
<div id="status">Connecting to the camera...</div>
<div class="container">
    <div class="msg" id="msg"><span class="spinner"></span><br>Starting RTSP stream...</div>
    <img id="cam" alt="Live video">
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
        status.textContent = '🎥 LIVE';
        status.style.color = '#4f4';
    };
    img.onerror = function() {
        if (!img.getAttribute('src')) return;
        img.style.display = 'none';
        msg.style.display = 'block';
        msg.className = 'msg error';
        msg.innerHTML = '❌ Could not display video.<br><br>' +
            'Check FFmpeg, RTSP credentials and camera codec.';
        status.textContent = 'ERROR';
        status.style.color = '#f77';
    };
    img.src = '/api/stream/' + streamId;

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
<html lang="en">
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
    .topbar input:focus { border-color: #E67E22; background: #fff; }
    .topbar button { margin-left: 10px; padding: 8px 14px; background: #E67E22; color: #fff;
                     border: none; border-radius: 4px; font-size: 12px; cursor: pointer; font-weight: 600; }
    .topbar button:hover { background: #2980b9; }
    .topbar .run-badge { margin-left: auto; padding: 6px 12px; background: #e8f4ff;
                         border: 1px solid #3498db; border-radius: 4px; font-family: monospace;
                         font-size: 11px; color: #2c3e50; font-weight: 600; }
    .topbar .action-btn { background: linear-gradient(180deg, #4a90e2 0%, #2d6fbe 100%); }
    .topbar .action-btn.secondary { background: linear-gradient(180deg, #28a745 0%, #1e7e34 100%); }
    .topbar .action-btn.warning { background: linear-gradient(180deg, #f39c12 0%, #d97706 100%); }
    .topbar .action-btn:hover { filter: brightness(1.06); }
    .os-summary-card { display: flex; gap: 14px; align-items: center; padding: 14px; background: linear-gradient(135deg,#f7fafc,#edf6ff); border: 1px solid #cfe3ff; border-radius: 12px; margin-bottom: 16px; }
    .os-summary-icon { width: 54px; height: 54px; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 26px; background: linear-gradient(135deg,#e6f1ff,#dff7ee); }
    .os-summary-meta { flex: 1; }
    .os-summary-title { display: flex; align-items: center; gap: 8px; font-size: 1.1em; font-weight: 700; color: #1f2d3d; }
    .os-summary-sub { color: #5d6d7e; font-size: 0.85em; margin-top: 4px; }
    .os-badge { display: inline-flex; align-items: center; gap: 5px; padding: 5px 10px; border-radius: 999px; background: #dfeef9; color: #1b4f72; font-weight: 700; font-size: 0.75em; }
    .service-cell { display: flex; flex-direction: column; gap: 6px; }
    .service-name { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
    .service-version { display: inline-flex; align-items: center; gap: 6px; color: #2c6f9f; font-size: 0.78em; background: #edf7ff; padding: 4px 8px; border-radius: 999px; border: 1px solid #d4e9ff; width: fit-content; }
    .panel-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; background: #eef7f1; color: #1e7a4f; border-radius: 999px; font-size: 0.76em; font-weight: 600; }
    #network-container { width: 100vw; height: 100vh; background-color: #f5f5f5;
        background-image: linear-gradient(rgba(0,0,0,0.04) 1px, transparent 1px),
                          linear-gradient(90deg, rgba(0,0,0,0.04) 1px, transparent 1px);
        background-size: 32px 32px; }

    .topbar .logo { position: absolute; left: 50%; top: 50%;
                    transform: translate(-50%, -50%);
                    height: 40px; width: auto;
                    pointer-events: none; user-select: none; }

                    
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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
<div class="topbar">
    <input type="text" id="search" placeholder="Search IP / LAN / host" />
    <button id="btn-fit">Fit view</button>
    <button id="btn-export-json" class="action-btn">Export JSON</button>
    <button id="btn-import-json" class="action-btn secondary">Import JSON</button>
    <input type="file" id="import-json-input" accept="application/json,.json" hidden>
    <img src="logo_nethunter.png" alt="NetHunter" class="logo">
    <span class="run-badge" id="run-badge">RUN: —</span>
</div>
<div id="network-container"></div>
<div id="status">⏳ Starting...</div>

<div class="detail-panel" id="detail-panel">
    <span class="close-btn" onclick="closePanel()">✕</span>
    <h3 id="panel-title">Details</h3>
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
                setStatus('⏳ Fetching topology (' + a + '/' + n + ')...');
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

        document.getElementById('btn-export-json').addEventListener('click', function() {
            fetch('/api/topology/export', { cache: 'no-store' })
            .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function(payload) {
                const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'net_hunter_topology_' + (payload.run_id || Date.now()) + '.json';
                a.click();
                URL.revokeObjectURL(url);
            })
            .catch(function(e) { alert('Could not export topology: ' + e.message); });
        });

        const importInput = document.getElementById('import-json-input');
        document.getElementById('btn-import-json').addEventListener('click', function() {
            importInput.click();
        });
        importInput.addEventListener('change', function(event) {
            const file = event.target.files && event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function() {
                try {
                    const payload = JSON.parse(reader.result);
                    fetch('/api/topology/import', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    }).then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
                    .then(function(body) {
                        if (body.ok) {
                            alert('Topology imported successfully (' + body.devices + ' devices).');
                            window.location.reload();
                        } else {
                            alert('Import failed: ' + (body.error || 'Invalid JSON'));
                        }
                    }).catch(function(e) { alert('Could not import: ' + e.message); });
                } catch (err) {
                    alert('Invalid JSON: ' + err.message);
                }
                importInput.value = '';
            };
            reader.readAsText(file);
        });

        waitForVis(5000).then(function() { return fetchTopology(3); })
        .then(function(data) {
            console.log('[API] Nodes:', data.nodes ? data.nodes.length : 0);
            console.log('[API] RUN_ID:', data.run_id, '| Target:', data.target);

            runBadge.textContent = 'RUN: ' + (data.run_id || '—') +
                                    (data.target ? '  |  ' + data.target : '');

            if (data.devices && Array.isArray(data.devices)) {
                data.devices.forEach(function(d) {
                    if (d && d.ip) devicesByIp[d.ip] = d;
                });
            }

            if (!data.nodes || data.nodes.length === 0) { setStatus('No devices'); return; }

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
                    color: { color: '#b0b0b0', highlight: '#E67E22' },
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
            setStatus(uniqueNodes.length + ' devices · ' + uniqueEdges.length + ' connections');

            [200, 600, 1500, 3000].forEach(function(ms){ setTimeout(doFit, ms); });

            try {
                const qs = new URLSearchParams(window.location.search);
                if (qs.get('auto') === '1' && uniqueNodes.length > 0) {
                    const firstId = uniqueNodes[0].id;
                    setTimeout(function(){ window.openPanel(firstId); }, 900);
                }
            } catch(e) {}

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

    const devicesByIp = {};
    const cameraStreamCache = {};
    const pendingLiveOpen = {};
    const scanCompleted = {};

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
            }).catch(function(error) { console.error('Could not stop the stream:', error); });
        }
    }

    function buildCameraBanner(ip, statusMsg, statusColor) {
        return '<div style="padding:12px;background:linear-gradient(135deg,#fef5e7,#fdebd0);' +
               'border:1px solid #f0b27a;border-radius:6px;margin-bottom:14px">' +
               '<div style="font-weight:700;color:#a04000;margin-bottom:8px;font-size:0.95em">' +
               '📷 CCTV camera detected</div>' +
               '<button id="btn-live-window" data-cam-ip="' + htmlEscape(ip) + '"' +
               ' style="padding:10px 20px;background:#e67e22;color:#fff;border:none;' +
               'border-radius:4px;cursor:pointer;font-weight:600;font-size:0.95em">' +
               '🎥 View live (new window)</button>' +
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
                alert('No RTSP detected on ' + ip + '. Verify that it is an RTSP camera.');
                return;
            }
            const w = window.open('', 'cam_' + ip.replace(/\./g, '_'),
                'width=1000,height=620,resizable=yes,scrollbars=no');
            if (!w) {
                alert('The browser blocked the popup.\nAllow popups for this site.');
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
                    '<div class="sp"></div><p>⏳ Waiting for RTSP detection...</p>' +
                    '<p style="color:#999;font-size:0.85em">The window will connect automatically.</p>' +
                    '</div></body></html>');
                w.document.close();
            } catch(e) {}
            pendingLiveOpen[ip] = { window: w };
            btn.disabled = true;
            btn.textContent = '⏳ Waiting for scan...';
            const status = document.getElementById('live-open-status');
            if (status) status.textContent = '⏳ Waiting for RTSP port detection...';
        });
    }

    function openLiveWindow(ip, rtspUrl) {
        const w = window.open('', 'cam_' + ip.replace(/\./g, '_'),
            'width=1000,height=620,resizable=yes,scrollbars=no');
        if (!w) {
            alert('The browser blocked the popup.');
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
                '<div class="sp"></div><p>Starting RTSP stream...</p></div></body></html>');
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
                    '<p><strong>Could not start the stream</strong></p>' +
                    '<p style="font-size:0.9em;color:#ccc">' + htmlEscape(e.message) + '</p>' +
                    '<p style="font-size:0.85em;color:#999;margin-top:20px">Verify:<br>' +
                    '• That FFmpeg is installed and in PATH<br>' +
                    '• That the RTSP credentials are correct<br>' +
                    '• That the codec is supported</p></div>';
            } catch(_) { alert('Error: ' + e.message); }
        });
    }

    window.openPanel = function(ip) {
        stopCameraStream();
        const p = document.getElementById('detail-panel');
        const t = document.getElementById('panel-title');
        const c = document.getElementById('panel-content');
        p.style.display = 'block';
        t.textContent = ip;

        const devInfo = devicesByIp[ip] || {};
        const isCameraGuess = (devInfo.badge === 'CAMERA') ||
            ((devInfo.type || '').toLowerCase().indexOf('camera') !== -1);

        let html = renderFingerprintCard(devInfo);
        if (isCameraGuess) {
            html += buildCameraBanner(ip, '⏳ Detecting RTSP stream...', '#a04000');
        }
        html += '<p class="loading"><span class="progress"></span>SYN scan 1-65535 PARALLEL (5-10s)...</p>';
        c.innerHTML = html;

        if (isCameraGuess) attachCameraBannerListener(ip);

        currentIp = ip; currentPorts = [];
        if (socket) socket.emit('request_port_scan', { ip: ip });
    };
    window.closePanel = function() {
        stopCameraStream();
        document.getElementById('detail-panel').style.display = 'none';
    };

    const COMMON_RTSP_PATHS = [
        '/', '/stream1', '/stream2', '/live', '/live/ch0',
        '/Streaming/Channels/101', '/Streaming/Channels/102',
        '/cam/realmonitor?channel=1&subtype=0',
        '/onvif1', '/h264', '/mpeg4', '/video1', '/1'
    ];

    function getServiceIcon(service, port) {
        const s = (service || '').toLowerCase();
        if (s.includes('rtsp') || s.includes('camera') || port === 554 || port === 8554) return 'fa-solid fa-video';
        if (s.includes('http') || s.includes('web') || s.includes('https')) return 'fa-solid fa-globe';
        if (s.includes('ssh') || s.includes('telnet')) return 'fa-solid fa-terminal';
        if (s.includes('mysql') || s.includes('postgres') || s.includes('mongo') || s.includes('redis') || s.includes('database')) return 'fa-solid fa-database';
        if (s.includes('mssql') || s.includes('smb') || s.includes('rpc') || s.includes('rdp') || s.includes('windows')) return 'fa-brands fa-windows';
        if (s.includes('ftp') || s.includes('smtp') || s.includes('imap') || s.includes('pop')) return 'fa-solid fa-envelope';
        return 'fa-solid fa-server';
    }

    function renderFingerprintCard(devInfo) {
        const os = (devInfo && devInfo.os_fingerprint) || { family: 'Unknown', version: '', icon: '💻', icon_class: 'fa-solid fa-computer' };
        const hostname = (devInfo && devInfo.hostname) ? htmlEscape(devInfo.hostname) : 'No hostname';
        const vendor = (devInfo && devInfo.vendor && devInfo.vendor !== 'Unknown') ? htmlEscape(devInfo.vendor) : 'Vendor unavailable';
        const portCount = (devInfo && Array.isArray(devInfo.open_ports)) ? devInfo.open_ports.length : 0;
        const family = htmlEscape(os.family || 'Unknown');
        const version = os.version ? '<span class="os-badge"><i class="fa-solid fa-code-branch"></i> ' + htmlEscape(os.version) + '</span>' : '';
        const ttl = (devInfo && devInfo.ttl) ? '<span class="panel-chip"><i class="fa-solid fa-wave-square"></i> TTL ' + devInfo.ttl + '</span>' : '';
        return '<div class="os-summary-card">'
             + '<div class="os-summary-icon"><i class="' + (os.icon_class || 'fa-solid fa-computer') + '"></i></div>'
             + '<div class="os-summary-meta">'
             + '<div class="os-summary-title"><span>' + (os.icon || '💻') + '</span><span>' + family + '</span>' + version + '</div>'
             + '<div class="os-summary-sub"><i class="fa-solid fa-laptop"></i> ' + hostname + ' · <i class="fa-solid fa-id-card"></i> ' + vendor + '</div>'
             + '<div class="os-summary-sub" style="margin-top:6px;">' + (ttl || '') + '<span class="panel-chip" style="margin-left:6px;"><i class="fa-solid fa-network-wired"></i> ' + portCount + ' ports</span></div>'
             + '</div></div>';
    }

    function renderServiceCell(r) {
        let h = '<td><div class="service-cell"><div class="service-name">'
             + '<i class="' + getServiceIcon(r.service, r.port) + '" style="color:#2e86de"></i>'
             + '<span class="badge-open">' + htmlEscape(r.service || 'unknown') + '</span>';
        if (r.tcpwrapped) {
            h += ' <span class="badge-wrapped">tcpwrapped</span>';
        } else if (r.version) {
            h += ' <span class="badge-version">' + htmlEscape(r.version) + '</span>';
        }
        if (r.service === 'RTSP' || r.port === 554 || r.port === 8554) {
            h += ' <span class="badge-rtsp">📷 RTSP</span>';
        }
        h += '</div>';
        if (r.version) {
            h += '<div class="service-version"><i class="fa-solid fa-code-branch"></i> ' + htmlEscape(r.version) + '</div>';
        }
        if (r.banner) h += '<div class="banner-box">' + htmlEscape(r.banner) + '</div>';
        h += '</div></td>';
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
            if (!data.results || !data.results.length) { c.innerHTML = '<p>No open ports.</p>'; return; }
            currentPorts = data.results.map(function(r){ return r.port; });

            scanCompleted[data.ip] = true;
            const devInfo = devicesByIp[data.ip] || {};
            const rtspPortsEarly = data.rtsp_ports || [];
            const rtspPathsEarly = data.rtsp_paths || {};
            const hasRtspEarly = rtspPortsEarly.length > 0;
            const isCamera = (devInfo.badge === 'CAMERA') ||
                ((devInfo.type || '').toLowerCase().indexOf('camera') !== -1) ||
                hasRtspEarly;

            if (hasRtspEarly) {
                const rp = rtspPortsEarly[0];
                const dp = rtspPathsEarly[rp] || '/';
                cameraStreamCache[data.ip] = {
                    port: rp, path: dp,
                    url: 'rtsp://' + data.ip + ':' + rp + dp
                };
            }

            const devInfoFresh = devicesByIp[data.ip] || {};
            let h = renderFingerprintCard(devInfoFresh);
            if (isCamera) {
                const msg = hasRtspEarly
                    ? '✅ RTSP path detected: <code>' + htmlEscape(cameraStreamCache[data.ip].path) + '</code>'
                    : '⚠️ No RTSP detected. The device may not be a camera or the port is not open.';
                h += buildCameraBanner(data.ip, msg, hasRtspEarly ? '#1e8449' : '#a04000');
            }
            h += '<p><strong>' + data.results.length + ' open ports</strong> on ' + data.ip + '</p>';

            const rtspPorts = data.rtsp_ports || [];
            const rtspPaths = data.rtsp_paths || {};
            if (rtspPorts.length) {
                const rtspPort = rtspPorts[0];
                const detectedPath = rtspPaths[rtspPort] || '';
                const initialPath = detectedPath || '/';
                const initialUrl = 'rtsp://' + data.ip + ':' + rtspPort + initialPath;

                let hint;
                if (detectedPath) {
                    hint = '✅ Path automatically detected: <code>' +
                           htmlEscape(detectedPath) + '</code>. ' +
                           'If authentication is required, add <code>user:pass@</code> before the IP.';
                } else {
                    hint = '⚠️ Could not detect the path automatically. ' +
                           'Try one of the common paths:';
                }

                let chips = '';
                COMMON_RTSP_PATHS.forEach(function(p) {
                    const url = 'rtsp://' + data.ip + ':' + rtspPort + p;
                    chips += '<span class="path-chip" data-url="' +
                             htmlEscape(url) + '">' + htmlEscape(p) + '</span>';
                });

                h += '<section class="camera-stream"><strong>📷 RTSP camera detected</strong>'
                   + '<p class="camera-hint">' + hint + '</p>'
                   + '<div style="margin: 6px 0">' + chips + '</div>'
                   + '<input id="camera-url" type="text" value="' +
                     htmlEscape(initialUrl) + '" aria-label="RTSP URL">'
                   + '<button id="btn-camera-start">▶ View live</button>'
                   + '<button id="btn-camera-stop" class="stop-stream" style="display:none">■ Stop</button>'
                   + '<div id="camera-status" class="camera-status">FFmpeg converts the video to MJPEG for the browser.</div>'
                   + '<img id="camera-image" alt="Live video from camera" style="display:none"></section>';
            }

            h += '<button id="btn-discover" class="discover-btn">Discover services and versions</button>';
            h += '<table id="ports-table"><thead><tr>'
               + '<th style="width:80px">Port</th><th>Status</th></tr></thead><tbody>';
            data.results.forEach(function(r) {
                const isRtsp = rtspPorts.indexOf(r.port) !== -1;
                h += '<tr data-port="' + r.port + '">'
                   + '<td><strong>' + r.port + '</strong></td>'
                   + '<td><span class="badge-open">OPEN</span> '
                   + (isRtsp
                       ? '<span class="badge-rtsp">📷 RTSP · camera</span>'
                       : '<span class="badge-pending">waiting for analysis</span>')
                   + '</td></tr>';
            });
            h += '</tbody></table>';
            c.innerHTML = h;

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
                status.textContent = 'Connecting to the camera...';
                cameraStart.disabled = true;
                fetch('/api/stream/start', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: streamUrl})
                }).then(function(response) {
                    return response.json().then(function(body) {
                        if (!response.ok) throw new Error(body.error || 'Could not start the stream');
                        return body;
                    });
                }).then(function(body) {
                    currentStreamId = body.stream_id;
                    image.style.display = 'block';
                    stopButton.style.display = 'inline-block';
                    image.src = body.stream_url;
                    status.textContent = 'Stream active. If no video appears, verify the RTSP path and credentials.';
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
                document.getElementById('camera-status').textContent = 'Stream stopped.';
            });

            const cameraImage = document.getElementById('camera-image');
            if (cameraImage) cameraImage.addEventListener('error', function() {
                document.getElementById('camera-status').textContent =
                    'Could not display video. Verify FFmpeg, path, credentials, and camera codec.';
            });

            document.getElementById('btn-discover').addEventListener('click', function() {
                this.disabled = true;
                this.innerHTML = '<span class="progress"></span>Analyzing...';
                socket.emit('request_service_scan', { ip: currentIp, ports: currentPorts });
            });

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
                                '<p><strong>No RTSP detected on ' + htmlEscape(data.ip) + '</strong></p>' +
                                '<p style="color:#999;font-size:0.9em;margin-top:15px">The device may not be ' +
                                'a camera or the RTSP port is filtered.</p></div>';
                        } catch(_) {}
                    }
                }
            }
        });

        socket.on('service_scan_result', function(data) {
            const table = document.getElementById('ports-table');
            if (!table) return;
            if (data.ip && devicesByIp[data.ip]) {
                devicesByIp[data.ip].service_results = data.results || [];
                const dev = devicesByIp[data.ip];
                if (!dev.os_fingerprint || dev.os_fingerprint.family === 'Unknown') {
                    dev.os_fingerprint = {
                        family: 'Linux',
                        version: '',
                        icon: '🐧',
                        icon_class: 'fa-brands fa-linux'
                    };
                }
                const panel = document.getElementById('detail-panel');
                if (panel && panel.style.display !== 'none') {
                    const c = document.getElementById('panel-content');
                    c.innerHTML = renderFingerprintCard(dev) + '<p><strong>' + (data.results || []).length + ' services detected</strong> on ' + data.ip + '</p>' + '<table id="ports-table"><thead><tr><th style="width:80px">Port</th><th>Service</th></tr></thead><tbody>' + (data.results || []).map(function(r) {
                        return '<tr data-port="' + r.port + '"><td><strong>' + r.port + '</strong></td>' + renderServiceCell(r);
                    }).join('') + '</tbody></table>';
                }
            }
            data.results.forEach(function(r) {
                const row = table.querySelector('tr[data-port="' + r.port + '"]');
                if (row) row.innerHTML = '<td><strong>' + r.port + '</strong></td>' + renderServiceCell(r);
            });
            const btn = document.getElementById('btn-discover');
            if (btn) { btn.disabled = false; btn.innerHTML = '✅ Services discovered'; }
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
        _VENDOR_CACHE[mac] = "Randomized MAC"
        return "Randomized MAC"
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
    _VENDOR_CACHE[mac] = "Unknown"
    return "Unknown"

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


def _coalesce_os_version(text, prefer=None):
    candidates = []
    if prefer:
        candidates.append(prefer)
    if text:
        candidates.extend([
            text,
            text.replace('_', ' '),
            re.sub(r'\s+', ' ', text.strip())
        ])
    for value in candidates:
        if not value:
            continue
        m = re.search(r'(?:Windows\s+(?:Server\s+)?(?:NT\s+)?[0-9.]+|Windows\s+[0-9]+(?:\.[0-9]+)?)', value, re.I)
        if m:
            return m.group(0)
        m = re.search(r'(?:Android\s+[0-9]+(?:\.[0-9]+)*)', value, re.I)
        if m:
            return m.group(0)
        m = re.search(r'(?:Ubuntu\s+[0-9]+(?:\.[0-9]+)*|Debian\s+[0-9]+(?:\.[0-9]+)*|CentOS\s+[0-9]+(?:\.[0-9]+)*|Raspbian\s+[0-9]+(?:\.[0-9]+)*|Linux\s+Kernel\s+[0-9]+(?:\.[0-9]+)*)', value, re.I)
        if m:
            return m.group(0)
        m = re.search(r'(?:Microsoft-IIS/\s*[0-9.]+|Apache/[0-9.]+|nginx/[0-9.]+|OpenSSH_[0-9.]+p?[0-9]*)', value, re.I)
        if m:
            return m.group(0)
        if 'windows' in value.lower():
            return 'Windows'
        if 'android' in value.lower():
            return 'Android'
        if 'ubuntu' in value.lower() or 'debian' in value.lower() or 'linux' in value.lower():
            return 'Linux'
    return ''


def build_os_fingerprint(ip, open_ports=None, vendor=None, ttl=None, hostname=None, service_results=None):
    ports = set(open_ports or [])
    host = (hostname or '').lower()
    vendor_l = (vendor or '').lower()
    banner_text = ''
    if service_results:
        for item in service_results:
            if not isinstance(item, dict):
                continue
            banner_text += ' ' + str(item.get('banner') or '') + ' ' + str(item.get('version') or '')
    banner_text = banner_text.lower()

    if 5555 in ports or 'android' in host or 'android' in banner_text:
        version = _coalesce_os_version(banner_text + ' ' + host + ' ' + vendor_l, 'Android')
        return {
            'family': 'Android',
            'version': version if version and version.lower() != 'android' else 'Android',
            'icon': '📱',
            'icon_class': 'fa-solid fa-mobile-screen-button',
            'confidence': 'high' if 5555 in ports else 'medium'
        }

    if any(port in ports for port in (3389, 445, 135, 139, 5900)) or 'microsoft-iis' in banner_text or 'windows' in banner_text:
        version = _coalesce_os_version(banner_text + ' ' + host + ' ' + vendor_l, 'Windows')
        return {
            'family': 'Windows',
            'version': version if version and version.lower() != 'windows' else 'Windows',
            'icon': '🪟',
            'icon_class': 'fa-brands fa-windows',
            'confidence': 'high' if any(port in ports for port in (3389, 445)) else 'medium'
        }

    if any(port in ports for port in (22, 80, 443, 3306, 5432, 8080, 8443, 6379, 631)) or 'ubuntu' in banner_text or 'debian' in banner_text or 'apache' in banner_text or 'nginx' in banner_text or 'openssh' in banner_text or 'linux' in banner_text or 'amd64' in banner_text or 'arm64' in banner_text:
        version = _coalesce_os_version(banner_text + ' ' + host + ' ' + vendor_l, 'Linux')
        return {
            'family': 'Linux',
            'version': version if version and version.lower() != 'linux' else 'Linux',
            'icon': '🐧',
            'icon_class': 'fa-brands fa-linux',
            'confidence': 'high' if any(port in ports for port in (22, 80, 443)) else 'medium'
        }

    if ttl is not None:
        if ttl <= 64:
            return {'family': 'Linux', 'version': 'TTL 64', 'icon': '🐧', 'icon_class': 'fa-brands fa-linux', 'confidence': 'medium'}
        if ttl <= 128:
            return {'family': 'Windows', 'version': 'TTL 128', 'icon': '🪟', 'icon_class': 'fa-brands fa-windows', 'confidence': 'medium'}

    if any(word in vendor_l for word in ('apple', 'macbook', 'imac')):
        return {'family': 'macOS', 'version': 'Apple', 'icon': '🍎', 'icon_class': 'fa-brands fa-apple', 'confidence': 'medium'}

    return {'family': 'Unknown', 'version': '', 'icon': '💻', 'icon_class': 'fa-solid fa-computer', 'confidence': 'low'}

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
    print(f"[*] Detecting TTL on {len(devices)} devices...")
    def worker(d):
        ip = d['ip']
        ttl = get_ttl_l3_tcp(ip)
        if ttl is None: ttl = get_ttl_l3_icmp(ip)
        if ttl is not None: results[ip] = ttl
    with ThreadPoolExecutor(max_workers=len(devices) or 1) as ex:
        for _ in as_completed([ex.submit(worker, d) for d in devices]): pass
    print(f"[*] {len(results)} TTLs obtained.")
    return results

# -------------------------------------------------------------------
# Device type detection
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
            return ('HP Printer', '🖨️', 'PRINTER')
    if 'apple' in vl:
        if 22 in p or 445 in p or 548 in p or 5900 in p: return ('macOS', '🍎', 'PC')
        return ('Apple (iPhone/iPad)', '📱', 'PHONE')
    if any(v in vl for v in MOBILE_VENDORS): return ('Mobile/Tablet', '📱', 'PHONE')
    if any(v in vl for v in PC_VENDORS):
        if ttl and ttl <= 64: return ('Linux PC', '🐧', 'HOST')
        return ('PC', '💻', 'HOST')
    if ttl:
        if ttl <= 64:  return ('Linux/Unix', '🐧', 'HOST')
        if ttl <= 128: return ('Windows PC', '🪟', 'HOST')
        if ttl >= 200: return ('Router/AP', '🌐', 'ROUTER')
    return ('Unknown', '💻', 'HOST')


def enrich_device_fingerprint(dev):
    if not isinstance(dev, dict):
        return dev
    dev['os_fingerprint'] = build_os_fingerprint(
        dev.get('ip'),
        dev.get('open_ports', []),
        dev.get('vendor', ''),
        dev.get('ttl'),
        dev.get('hostname', ''),
        dev.get('service_results', [])
    )
    return dev

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
# L2 / L3 / ICMP discovery
# -------------------------------------------------------------------
def scan_layer2(network_cidr, gateway_ip):
    seen = {}
    for rnd, timeout in enumerate([2, 3, 2], start=1):
        print(f"[*] Layer 2 (ARP) round {rnd}/3...")
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
    print(f"[*] Layer 3 (TCP SYN L2) — {len(targets)} IPs × {len(probe_ports)} ports")
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
    print(f"[*] Layer 3 (TCP SYN): {len(alive)} live hosts")
    return alive

def scan_icmp(network_cidr, gateway_ip, timeout=2.0, mac_map=None):
    net = ipaddress.ip_network(network_cidr, strict=False)
    all_ips = [str(ip) for ip in net.hosts() if str(ip) != gateway_ip]
    if not all_ips: return set()
    if mac_map is None: mac_map = arp_sweep(network_cidr, gateway_ip, timeout=2)
    targets = [(ip, mac_map[ip]) for ip in all_ips if ip in mac_map]
    if not targets: return set()
    print(f"[*] Layer 3 (ICMP Echo L2) — {len(targets)} IPs")
    packets = [Ether(dst=mac) / IP(dst=ip) / ICMP(type=8, code=0) for ip, mac in targets]
    alive = set()
    for i in range(0, len(packets), 500):
        try:
            answered, _ = srp(packets[i:i+500], timeout=timeout, verbose=0)
            for sent, received in answered:
                if received.haslayer(ICMP) and received[ICMP].type in (0, 3):
                    alive.add(received[IP].src)
        except Exception: pass
    print(f"[*] Layer 3 (ICMP): {len(alive)} live hosts")
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
# Classification
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
        return ('Printer', '🖨️', 'PRINTER')
    if (1688 in p and 7070 in p) or (10004 in p and 7070 in p) or (7680 in p and 7070 in p):
        return ('HP Printer', '🖨️', 'PRINTER')
    if rtsp_ports:
        return ('CCTV Camera', '📷', 'CAMERA')
    if 53 in p and (80 in p or 443 in p):
        return ('Router/Gateway', '🌐', 'ROUTER')
    if 3389 in p:
        return ('Windows Server', '🪟', 'SERVER')
    if 22 in p and (80 in p or 443 in p or 3306 in p):
        return ('Linux Server', '🖥️', 'SERVER')
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
        enrich_device_fingerprint(d)
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
    enrich_device_fingerprint(dev)
    border = "#d0d0d0"
    if   'Printer' in dtype: border = "#3498db"
    elif 'Camera'  in dtype: border = "#e74c3c"
    elif 'Server'  in dtype: border = "#27ae60"
    elif 'Router'  in dtype or 'AP' in dtype: border = "#9b59b6"
    elif 'Windows' in dtype: border = "#0078d4"
    elif 'Linux'   in dtype: border = "#f1c40f"
    elif 'macOS'   in dtype: border = "#7f8c8d"
    elif any(k in dtype for k in ('Android','iPhone','iPad','Apple','Mobile')):
        border = "#e67e22"
    elif 'IoT' in dtype or 'Web' in dtype: border = "#f39c12"
    vs = dev.get('vendor') or ''
    extra = []
    if dev.get('hostname'): extra.append(f"HOST: {dev['hostname'][:28]}")
    if vs and vs not in ('Unknown', 'Randomized MAC', 'N/A'):
        extra.append(f"VENDOR: {vs[:28]}")
    if dev.get('source'): extra.append(f"SRC: {dev['source']}")
    if dev.get('open_ports'):
        ps = ",".join(str(p) for p in dev['open_ports'][:5])
        if len(dev['open_ports']) > 5: ps += f" (+{len(dev['open_ports'])-5})"
        extra.append(f"PORTS: {ps}")
    if dev.get('ttl'): extra.append(f"TTL: {dev['ttl']}")
    os_f = dev.get('os_fingerprint', {})
    if os_f.get('family'):
        extra.append(f"OS: {os_f['family']} {os_f.get('version','')}".strip())
    return {
        "id": ip, "shape": "image",
        "image": make_node_svg(icon, ip, badge, ip, "|".join(extra), border),
        "size": 85,
        "title": f"{dtype}\nMAC: {dev.get('mac','N/A')}\n"
                 f"Vendor: {vs or 'N/A'}\nSource: {dev.get('source','?')}\n"
                 f"Host: {dev.get('hostname') or 'N/A'}\n"
                 f"OS: {os_f.get('family','N/A')} {os_f.get('version','')}\n"
                 f"Ports: {','.join(str(p) for p in dev.get('open_ports', [])[:15])}"
    }

# =====================================================================
# FULL PARALLEL SYN SCAN — L2
# =====================================================================
def syn_scan_full_l2_parallel(ip, mac, num_workers=12, chunk_size=1500, timeout=0.8):
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

    print(f"[*] SYN scan L2 PARALLEL: {num_workers} workers × chunks {chunk_size}, timeout {timeout}s")
    threads = [threading.Thread(target=worker, args=(g, i), daemon=True)
               for i, g in enumerate(groups)]
    for t in threads: t.start()
    for t in threads: t.join()

    elapsed1 = time.time() - t0
    print(f"    Pass 1 ({elapsed1:.1f}s): {len(responded_all)}/{len(all_ports)} responded, "
          f"{len(open_ports)} open: {sorted(open_ports)}")

    critical_ports = [9100, 631, 515, 80, 443, 8080, 8443, 8000, 8888, 9000,
                      21, 22, 23, 25, 161, 445, 3389, 1688, 7070, 10004,
                      7680, 5000, 3000, 53, 5355, 5357, 554, 8554, 5001]
    missing_critical = [p for p in critical_ports if p not in responded_all]

    if missing_critical:
        print(f"    Pass 2: verifying {len(missing_critical)} critical ports in parallel...")
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
                if r: print(f"        -> {r} OPEN (verified in P2)")

    elapsed = time.time() - t0
    return sorted(open_ports), elapsed


def connect_scan_full(ip, timeout=0.6, max_workers=300):
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
    if SINGLE_MODE:
        print(f"    [*] Single-target L3 scan of {ip} (no MAC)")
        ports = syn_scan_l3_single(ip, ports=None, timeout=1.0)
        print(f"    -> {len(ports)} open ports: {ports[:30]}")
        return ports

    mac = None
    for d in topology_data.get("devices", []):
        if d['ip'] == ip:
            mac = d.get('mac', ''); break
    if not mac or mac.startswith("N/A") or mac == "N/A (L3)":
        print(f"    [*] Resolving MAC of {ip}...")
        mac = get_mac_for_ip(ip)

    if not mac:
        print(f"    [!] No MAC → fallback connect_ex()")
        ports, elapsed = connect_scan_full(ip)
        print(f"    -> {len(ports)} ports in {elapsed:.1f}s: {ports[:30]}")
        return ports

    print(f"[*] PARALLEL SYN scan via L2 on {ip} (mac {mac})")
    ports, elapsed = syn_scan_full_l2_parallel(ip, mac,
                                                num_workers=ARGS.workers,
                                                chunk_size=1500,
                                                timeout=0.8)
    print(f"    -> {len(ports)} open ports in {elapsed:.1f}s: {ports[:30]}")

    if not ports:
        print(f"    [!] SYN L2 returned 0 → parallel connect_ex()")
        p2, e2 = connect_scan_full(ip)
        ports = sorted(set(ports) | set(p2))
        print(f"    -> connect_ex: {len(p2)} in {e2:.1f}s")
    return ports

# =====================================================================
# *** L3 SYN SCAN FOR SINGLE TARGET (public/private IP/DNS) ***
# =====================================================================
def syn_scan_full_l3_parallel(ip, ports=None, num_workers=12, chunk_size=1000, timeout=1.0):
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
    if num_workers is None:
        num_workers = ARGS.workers
    if ports is None:
        ports = list(range(1, 65536))

    open_ports = set()

    print(f"[*] Parallel connect scan on {ip} ({len(ports)} ports)...")
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
    print(f"    connect_ex: {len(open_ports)} open in {time.time()-t0:.1f}s")

    try:
        print(f"[*] Raw L3 SYN (cross-verification)...")
        op2, resp, el2 = syn_scan_full_l3_parallel(
            ip, ports=ports, num_workers=num_workers,
            chunk_size=2000, timeout=0.8)
        new_ports = set(op2) - open_ports
        if new_ports:
            print(f"    Raw SYN: +{len(new_ports)} new ({sorted(new_ports)[:20]})")
        open_ports.update(op2)
    except PermissionError:
        print(f"    [!] No privileges for raw SYN (OK, connect_ex already scanned)")
    except Exception as e:
        print(f"[!] Raw SYN failed: {e}")

    return sorted(open_ports)


def run_single_target_scan(target):
    hostname_dns = ""
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            hostname_dns = target
        except Exception as e:
            print(f"[!] Could not resolve '{target}': {e}")
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
        print(f"[*] Custom ports: {len(ports_to_scan)} ({ports_to_scan[:20]}"
              f"{'...' if len(ports_to_scan) > 20 else ''})")
    else:
        ports_to_scan = list(range(1, 65536))
        print(f"[*] Full scan 1-65535")

    print(f"\n[*] Phase 1: discovering open ports on {ip}...")
    t0 = time.time()
    open_ports = syn_scan_l3_single(ip, ports=ports_to_scan, timeout=1.0)
    print(f"[*] Phase 1 completed: {len(open_ports)} open ports in {time.time()-t0:.1f}s")

    if not open_ports:
        print("[!] No open ports found (or host is behind a firewall "
              "that drops packets).")
        return

    print(f"\n[*] Phase 2: identifying services and versions "
          f"({len(open_ports)} ports, parallel)...")
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
    print(f"[*] Phase 2 completed in {time.time()-t1:.1f}s")

    print("\n" + "=" * 60)
    print(f"  RESULTS — {ip}" + (f" ({hostname_dns})" if hostname_dns else ""))
    print("=" * 60)
    print(f"{'PORT':>7}  {'SERVICE':<24}  {'VERSION / BANNER'}")
    print("-" * 60)
    for r in results:
        ver = r.get('version') or r.get('banner') or ''
        if r.get('tcpwrapped'):
            ver = 'tcpwrapped'
        ver = ver.replace('\n', ' ').replace('\r', ' ').strip()
        print(f"{r['port']:>7}  {r['service']:<24}  {ver[:80]}")
    print("-" * 60)
    print(f"[*] Total: {len(results)} services identified.")
    print(f"[*] RUN_ID: {RUN_ID}")
    print("=" * 60)


# -------------------------------------------------------------------
# Probes
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
        return "DNS active (no version.bind)"
    except socket.timeout:
        return "DNS (version.bind does not respond)"
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
        return "SMB/CIFS present" if ("SMB" in d or "NT LM" in d) else d.strip()[:200]
    except Exception: return ""

def probe_rtsp(ip, port, timeout=2, uri=None, discover_path=False):
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
                        return banner + "\nPATH: " + path + " (auth required)"
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
    else: service, probe = "Unknown", lambda i,p: probe_banner(i,p)
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
# Flask routes
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
    print(f"[API] /api/topology → {len(topology_data['nodes'])} nodes, "
          f"{len(topology_data['edges'])} edges (run {RUN_ID})")
    return jsonify(topology_data)

@app.route('/api/topology/export')
def api_topology_export():
    payload = {
        'schema': 'net_hunter_topology_v1',
        'run_id': topology_data.get('run_id', RUN_ID),
        'target': topology_data.get('target'),
        'gateway': topology_data.get('gateway'),
        'exported_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'topology': topology_data,
    }
    return jsonify(payload)

@app.route('/api/topology/import', methods=['POST'])
def api_topology_import():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'Invalid JSON: expected an object with the topology.'}), 400
    incoming = payload.get('topology') if isinstance(payload.get('topology'), dict) else payload
    if not isinstance(incoming, dict):
        return jsonify({'error': 'The JSON does not contain a valid topology.'}), 400
    nodes = incoming.get('nodes', [])
    edges = incoming.get('edges', [])
    devices = incoming.get('devices', [])
    if not isinstance(nodes, list) or not isinstance(edges, list) or not isinstance(devices, list):
        return jsonify({'error': 'The topology must contain valid "nodes", "edges" and "devices".'}), 400
    for dev in devices:
        if isinstance(dev, dict):
            enrich_device_fingerprint(dev)
    topology_data.clear()
    topology_data.update({
        'nodes': nodes,
        'edges': edges,
        'devices': devices,
        'run_id': incoming.get('run_id', RUN_ID),
        'target': incoming.get('target'),
        'gateway': incoming.get('gateway')
    })
    return jsonify({'ok': True, 'devices': len(devices), 'nodes': len(nodes), 'edges': len(edges)})

@app.route('/api/debug')
def api_debug(): return jsonify(topology_data)

@app.route('/stream-popup/<stream_id>')
def stream_popup(stream_id):
    with _STREAM_SESSIONS_LOCK:
        if stream_id not in _STREAM_SESSIONS:
            return "Stream not found or expired", 404
    return render_template_string(POPUP_TEMPLATE, stream_id=stream_id)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/logo_nethunter.png')
def serve_logo():
    return send_from_directory(BASE_DIR, 'logo_nethunter.png')

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
        return jsonify({'error': 'Provide a valid RTSP URL (maximum 2048 characters).'}), 400

    try:
        parsed = urlsplit(stream_url)
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 554
    except ValueError:
        return jsonify({'error': 'The RTSP URL has an invalid host or port.'}), 400
    if (parsed.scheme.lower() != 'rtsp' or not host or parsed.fragment
            or port < 1 or port > 65535):
        return jsonify({'error': 'Use a complete RTSP URL, for example rtsp://IP:554/path.'}), 400

    try:
        target_ip = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            target_ip = socket.gethostbyname(host)
        except OSError:
            return jsonify({'error': 'Could not resolve the RTSP host.'}), 400
    device = next((item for item in topology_data.get('devices', [])
                   if item.get('ip') == target_ip), None)
    if not device:
        return jsonify({'error': 'The RTSP host does not belong to a detected device.'}), 403
    if port not in device.get('open_ports', []):
        return jsonify({'error': 'The RTSP port is not shown as open. Scan the device first.'}), 400

    path = parsed.path or '/'
    probe_uri = "rtsp://%s:%d%s%s" % (
        target_ip, port, path, ("?" + parsed.query) if parsed.query else "")
    response = probe_rtsp(target_ip, port, timeout=2, uri=probe_uri)
    if not response.upper().startswith("RTSP/"):
        return jsonify({'error': 'The open port did not respond as an RTSP service.'}), 400

    ffmpeg = shutil.which(ARGS.ffmpeg)
    if not ffmpeg:
        return jsonify({'error': 'FFmpeg was not found. Install it or specify its path with --ffmpeg.'}), 503

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
            return jsonify({'error': 'The stream does not exist or has already been stopped.'}), 404
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
                logging.exception("Could not start FFmpeg for the RTSP stream")
                return jsonify({'error': 'Could not start FFmpeg. Check the configured path.'}), 503
    if not session.get('process'):
        return jsonify({'error': 'The stream does not exist or has already been stopped.'}), 404
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
        return jsonify({'error': 'Missing stream identifier.'}), 400
    with _STREAM_SESSIONS_LOCK:
        session = _STREAM_SESSIONS.pop(stream_id, None)
    if session:
        _stop_stream_process(session.get('process'))
    return jsonify({'stopped': bool(session)})

@socketio.on('request_port_scan')
def handle_port_scan(data):
    target_ip = data['ip']
    print(f"\n[*] Phase 1: open ports on {target_ip}")
    def run_scan():
        try:
            t0 = time.time()
            opened = discover_open_ports(target_ip)
            print(f"    -> {len(opened)} ports in {time.time()-t0:.1f}s total")
            rtsp_ports, rtsp_paths = detect_rtsp_ports(target_ip, opened)
            if rtsp_ports:
                print(f"    -> RTSP detected on ports {rtsp_ports}, paths: {rtsp_paths}")
            dev = next((d for d in topology_data["devices"] if d['ip'] == target_ip), None)
            if dev:
                dev['open_ports'] = opened
                dev['rtsp_ports'] = rtsp_ports
                dev['rtsp_paths'] = rtsp_paths
                dev['os_fingerprint'] = build_os_fingerprint(target_ip, opened, dev.get('vendor',''), dev.get('ttl'), dev.get('hostname',''), dev.get('service_results', []))
                new_node = rebuild_node(dev)
                for i, n in enumerate(topology_data["nodes"]):
                    if n['id'] == target_ip:
                        topology_data["nodes"][i] = new_node; break
                else: topology_data["nodes"].append(new_node)
                socketio.emit('node_update', new_node, to=None)
                print(f"    -> Reclassified: {dev['type']}")
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
    print(f"\n[*] Phase 2: services on {target_ip}")
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
                dev['service_results'] = results
                dev['open_ports'] = sorted(set(dev.get('open_ports', []) +
                                               [r['port'] for r in results]))
                dev['os_fingerprint'] = build_os_fingerprint(target_ip, dev.get('open_ports', []), dev.get('vendor',''), dev.get('ttl'), dev.get('hostname',''), results)
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

# =====================================================================
# AUTOMATIC LOCAL NETWORK DETECTION (gateway + mask)
# =====================================================================
def detect_local_network():
    """
    Detects (local_ip, netmask_str, gateway) from the operating system.
    Cross-platform: Windows / Linux / macOS.
    """
    import platform
    system = platform.system()

    # 1) Gateway via Scapy (cross-platform, already in your dependencies)
    gateway = None
    try:
        for dest in ("8.8.8.8", "1.1.1.1", "0.0.0.0"):
            try:
                iface, out_ip, gw = conf.route.route(dest)
                if gw and gw != "0.0.0.0":
                    gateway = gw
                    break
            except Exception:
                continue
    except Exception:
        pass

    # 2) IP + mask by OS
    try:
        if system == "Windows":
            return _detect_local_windows(gateway)
        elif system == "Linux":
            return _detect_local_linux(gateway)
        elif system == "Darwin":
            return _detect_local_macos(gateway)
    except Exception:
        pass

    # 3) Fallback: psutil if installed
    try:
        import psutil
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if (a.family == socket.AF_INET
                        and not a.address.startswith("127.")
                        and not a.address.startswith("169.254.")):
                    return a.address, a.netmask, gateway
    except Exception:
        pass

    return None, None, gateway


def _detect_local_windows(gateway_hint=None):
    import subprocess, json, re
    try:
        ps_cmd = (
            "$c = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null} "
            "| Select-Object -First 1; "
            "if ($c) { "
            "  $ip = $c.IPv4Address.IPAddress; "
            "  $p  = $c.IPv4Address.PrefixLength; "
            "  $gw = $c.IPv4DefaultGateway.NextHop; "
            "  $mask = ([IPAddress]([UInt32]::MaxValue -shl (32 - $p))).IPAddressToString; "
            "  @{ IP=$ip; Mask=$mask; Gateway=$gw } | ConvertTo-Json -Compress "
            "}"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            timeout=15, text=True, errors="ignore"
        ).strip()
        if out:
            data = json.loads(out)
            return data.get("IP"), data.get("Mask"), data.get("Gateway") or gateway_hint
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ipconfig"], timeout=10, text=True, errors="ignore"
        )
    except Exception:
        return None, None, gateway_hint

    ipv4 = mask = gw = None
    current_block_has_ip = False
    for line in out.splitlines():
        m = re.search(r'IPv4[^:]*:\s*([\d.]+)', line)
        if m:
            candidate = m.group(1)
            if not (candidate.startswith("127.") or candidate.startswith("169.254.")):
                ipv4 = candidate
                current_block_has_ip = True
            continue
        m = re.search(r'(?:Subnet Mask|Máscara de subred)[^:]*:\s*([\d.]+)', line)
        if m and current_block_has_ip:
            mask = m.group(1); continue
        m = re.search(r'(?:Default Gateway|Puerta de enlace predeterminada)[^:]*:\s*([\d.]+)', line)
        if m and current_block_has_ip:
            gw = m.group(1); continue

    return ipv4, mask, gw or gateway_hint


def _detect_local_linux(gateway_hint=None):
    import subprocess, re
    try:
        route_out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            timeout=5, text=True, errors="ignore"
        )
        m = re.search(r'default\s+via\s+([\d.]+)\s+dev\s+(\S+)', route_out)
        if not m:
            return None, None, gateway_hint
        gw, iface = m.group(1), m.group(2)

        addr_out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            timeout=5, text=True, errors="ignore"
        )
        m = re.search(r'inet\s+([\d.]+)/(\d+)', addr_out)
        if not m:
            return None, None, gw
        ip_addr, prefix = m.group(1), int(m.group(2))
        netmask = str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
        return ip_addr, netmask, gw
    except Exception:
        return None, None, gateway_hint


def _detect_local_macos(gateway_hint=None):
    import subprocess, re
    try:
        route_out = subprocess.check_output(
            ["route", "-n", "get", "default"],
            timeout=5, text=True, errors="ignore"
        )
        gw_m = re.search(r'gateway:\s*([\d.]+)', route_out)
        if_m = re.search(r'interface:\s*(\S+)', route_out)
        if not gw_m or not if_m:
            return None, None, gateway_hint
        gw, iface = gw_m.group(1), if_m.group(1)

        ifconfig_out = subprocess.check_output(
            ["ifconfig", iface],
            timeout=5, text=True, errors="ignore"
        )
        m = re.search(r'inet\s+([\d.]+)\s+netmask\s+(0x[0-9a-fA-F]+)', ifconfig_out)
        if not m:
            return None, None, gw
        ip_addr = m.group(1)
        netmask = str(ipaddress.IPv4Address(int(m.group(2), 16)))
        return ip_addr, netmask, gw
    except Exception:
        return None, None, gateway_hint


def _guess_gateway(net):
    """
    Tries to guess the gateway of the target network by probing .1 and .254
    of the first /24 with ARP. Returns (gateway_ip, verified: bool).
    """
    if net.num_addresses < 2:
        return None, False
    hosts = list(net.hosts())
    if not hosts:
        return None, False

    first = str(hosts[0])
    p = first.split('.')
    candidates = [
        f"{p[0]}.{p[1]}.{p[2]}.1",
        f"{p[0]}.{p[1]}.{p[2]}.254",
        first,
        str(hosts[-1]),
    ]
    seen = set()
    candidates = [c for c in candidates if c not in seen and not seen.add(c)]

    for cand in candidates:
        try:
            mac = get_mac_for_ip(cand, timeout=1)
            if mac:
                return cand, True
        except Exception:
            pass

    return (candidates[0] if candidates else None), False


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def normalize_target(target):
    """
    Accepts:
      - IP without prefix:  192.168.83.172  → /24 (or local mask if on your network)
      - IP ending in .0:    192.168.83.0    → /24
      - CIDR:               192.168.80.0/22 → that network
      - IP/prefix:          192.168.83.172/22 → that network

    Automatically detects local IP, mask and gateway.
    Returns (network_cidr, gateway_ip, local_ip, local_mask).
    """
    print("[*] Detecting local network configuration...")
    local_ip, local_mask, system_gw = detect_local_network()
    if local_ip:
        print(f"    Local IP:   {local_ip}")
    if local_mask:
        print(f"    Mask:       {local_mask}")
    if system_gw:
        print(f"    Gateway:    {system_gw}")
    if not any((local_ip, local_mask, system_gw)):
        print("    [!] Could not detect the local configuration")

    if '/' in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            print(f"[!] Invalid format: {target}")
            sys.exit(1)
    else:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            print(f"[!] Invalid format: {target}")
            sys.exit(1)

        if target.endswith(".0"):
            net = ipaddress.ip_network(f"{target}/24", strict=False)
        else:
            if local_ip and local_mask:
                try:
                    local_net = ipaddress.ip_network(
                        f"{local_ip}/{local_mask}", strict=False
                    )
                    if ip in local_net:
                        net = local_net
                    else:
                        net = ipaddress.ip_network(f"{target}/24", strict=False)
                except Exception:
                    net = ipaddress.ip_network(f"{target}/24", strict=False)
            else:
                net = ipaddress.ip_network(f"{target}/24", strict=False)

    gateway = None
    verified = False
    if system_gw:
        try:
            if ipaddress.ip_address(system_gw) in net:
                gateway = system_gw
                verified = True
        except Exception:
            pass

    if gateway is None:
        gateway, verified = _guess_gateway(net)

    if gateway:
        tag = "verified" if verified else "guess"
        print(f"[*] Gateway for {net}: {gateway} ({tag})")
    else:
        print(f"[!] Could not detect gateway for {net}")

    return str(net), gateway, local_ip, local_mask


if __name__ == '__main__':
    # ------------------------------------------------------------------
    # Single-target mode:
    #   -s                    → opens browser with the target (L3 scan from web)
    #   -s --no-browser       → direct CLI scan
    # ------------------------------------------------------------------
    if ARGS.single:
        if ARGS.no_browser:
            run_single_target_scan(ARGS.target)
            sys.exit(0)

        hostname_dns = ""
        try:
            ipaddress.ip_address(ARGS.target)
            target_ip = ARGS.target
        except ValueError:
            try:
                target_ip = socket.gethostbyname(ARGS.target)
                hostname_dns = ARGS.target
            except Exception as e:
                print(f"[!] Could not resolve '{ARGS.target}': {e}")
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
        print("[*] Opening browser. The panel will open only if (?auto=1).")

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
    # Full network mode
    # ------------------------------------------------------------------
    network_cidr, gateway_ip, local_ip, local_mask = normalize_target(ARGS.target)

    print("=" * 60)
    print("  NETWORK TREE SCANNER")
    print(f"  Target network: {network_cidr}")
    print(f"  Gateway:        {gateway_ip or '(not detected)'}")
    print(f"  RUN_ID:         {RUN_ID}")
    modes = []
    if ARGS.layer2: modes.append("L2 (ARP)")
    if ARGS.layer3: modes.append(f"L3 (TCP SYN: {ARGS.ports_list})")
    if ARGS.icmp:   modes.append("ICMP (Echo)")
    print(f"  Mode:           {' + '.join(modes)}")
    print(f"  SYN workers:    {ARGS.workers}")
    print("=" * 60)

    seen = discover_hosts(network_cidr, gateway_ip)
    print(f"\n[*] {len(seen)} unique devices discovered.")

    if gateway_ip:
        central_id = gateway_ip
        central_svg = make_node_svg(
            '🌐', gateway_ip, 'ROUTER', gateway_ip,
            'Network gateway', '#3498db'
        )
        central_title = "Network gateway"
    else:
        central_id = "__network__"
        net_label = network_cidr.split('/')[0]
        central_svg = make_node_svg(
            '🌐', net_label, 'LAN', net_label,
            'Network (gateway not detected)', '#95a5a6'
        )
        central_title = f"Network {network_cidr} (gateway not detected)"

    nodes = [{
        "id": central_id, "shape": "image",
        "image": central_svg,
        "size": 85, "title": central_title
    }]
    edges = []; devices = []
    for ip, info in seen.items():
        mac = info.get("mac", "N/A")
        vendor = get_vendor(mac)
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "source": info.get("source", "?"),
            "type": "Unknown", "icon": "💻", "badge": "HOST",
            "os": "", "ttl": None, "hostname": "", "open_ports": [],
            "rtsp_ports": [], "rtsp_paths": {}
        })
        edges.append({"from": central_id, "to": ip})

    ttl_map = detect_ttls(devices)
    for d in devices: d['ttl'] = ttl_map.get(d['ip'])

    print("[*] Classifying devices in parallel...")
    t0 = time.time()
    classify_all_devices(devices)
    print(f"[*] Classification completed in {time.time()-t0:.1f}s")

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

    print(f"\n[*] Topology ready: {len(nodes)} nodes.")
    print(f"[*] URL: http://127.0.0.1:{ARGS.web_port}/?run={RUN_ID}")

    if not ARGS.no_browser:
        url = f'http://127.0.0.1:{ARGS.web_port}/?run={RUN_ID}'
        threading.Timer(1.5, lambda: webbrowser.open_new(url)).start()

    socketio.run(app, host='0.0.0.0', port=ARGS.web_port, debug=False,
                 allow_unsafe_werkzeug=True, log_output=False)