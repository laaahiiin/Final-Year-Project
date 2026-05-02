import streamlit as st
import joblib
import pandas as pd
import numpy as np
import time
import os
import random
import json
from datetime import datetime
import threading
import winsound
import streamlit.components.v1 as components

try:
    from plyer import notification
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "plyer"])
    from plyer import notification

st.set_page_config(page_title="ML-Based IDS/IPS for IoT", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .metric-box { background-color: #1E1E1E; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #333; }
    .alert-text { color: #ff4b4b; font-weight: bold; }
    .safe-text  { color: #00ea69; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# ── Geo-IP threat intelligence pool ──────────────────────────────────────────
GEO_ATTACK_POOL = [
    ("103.45.89.21",  "Beijing",       "China",        "🇨🇳",  39.9042, 116.4074),
    ("118.24.33.78",  "Shenzhen",      "China",        "🇨🇳",  22.5431, 114.0579),
    ("101.33.224.12", "Shanghai",      "China",        "🇨🇳",  31.2304, 121.4737),
    ("185.220.101.5", "Moscow",        "Russia",       "🇷🇺",  55.7558,  37.6173),
    ("194.165.16.88", "St. Petersburg","Russia",       "🇷🇺",  59.9311,  30.3609),
    ("177.67.114.22", "São Paulo",     "Brazil",       "🇧🇷", -23.5505, -46.6333),
    ("179.191.56.10", "Rio de Janeiro","Brazil",       "🇧🇷", -22.9068, -43.1729),
    ("52.91.200.14",  "Virginia",      "USA",          "🇺🇸",  37.4316, -78.6569),
    ("34.211.37.99",  "Oregon",        "USA",          "🇺🇸",  43.8041,-120.5542),
    ("103.240.168.55","Mumbai",        "India",        "🇮🇳",  19.0760,  72.8777),
    ("49.207.44.33",  "Delhi",         "India",        "🇮🇳",  28.6139,  77.2090),
    ("175.45.176.3",  "Pyongyang",     "North Korea",  "🇰🇵",  39.0392, 125.7625),
    ("185.100.87.241","Amsterdam",     "Netherlands",  "🇳🇱",  52.3676,   4.9041),
    ("194.165.16.90", "Rotterdam",     "Netherlands",  "🇳🇱",  51.9244,   4.4777),
    ("176.36.63.100", "Kyiv",          "Ukraine",      "🇺🇦",  50.4501,  30.5234),
    ("89.47.57.22",   "Bucharest",     "Romania",      "🇷🇴",  44.4268,  26.1025),
    ("5.160.218.44",  "Tehran",        "Iran",         "🇮🇷",  35.6892,  51.3890),
    ("85.209.163.112","Frankfurt",     "Germany",      "🇩🇪",  50.1109,   8.6821),
]

ATTACK_ORIGIN_MAP = {
    "DDoS":       [0,1,2,6,7,12,13],
    "Botnet":     [0,1,2,3,4,9,10,16],
    "BruteForce": [3,4,11,14,15,17],
    "DoS":        [0,1,6,7,12,13],
}

def pick_attacker(category):
    pool_indices = ATTACK_ORIGIN_MAP.get(category, list(range(len(GEO_ATTACK_POOL))))
    idx = random.choice(pool_indices)
    return GEO_ATTACK_POOL[idx]

# ── Color maps ────────────────────────────────────────────────────────────────
ATTACK_CSS_COLORS = {
    "DDoS":       "rgb(255, 40, 40)",
    "DoS":        "rgb(255, 220, 0)",
    "Botnet":     "rgb(180, 0, 255)",
    "BruteForce": "rgb(255, 140, 0)",
}
ATTACK_GLOW_COLORS = {
    "DDoS":       "rgba(255, 40, 40, 0.35)",
    "DoS":        "rgba(255, 220, 0, 0.35)",
    "Botnet":     "rgba(180, 0, 255, 0.35)",
    "BruteForce": "rgba(255, 140, 0, 0.35)",
}
ATTACK_COLORS = {
    "DDoS":       [255, 50,  50,  220],
    "DoS":        [255, 200, 50,  220],
    "Botnet":     [170, 50,  255, 220],
    "BruteForce": [255, 150, 30,  220],
}

# ── Map rendering helper (Leaflet with NO-RELOAD JS Polling) ─────────────────
ATTACK_CSS_COLORS = {
    "DDoS":       "rgb(255, 40, 40)",
    "Botnet":     "rgb(180, 0, 255)",
    "BruteForce": "rgb(255, 140, 0)",
}
ATTACK_GLOW_COLORS = {
    "DDoS":       "rgba(255, 40, 40, 0.35)",
    "Botnet":     "rgba(180, 0, 255, 0.35)",
    "BruteForce": "rgba(255, 140, 0, 0.35)",
}

def get_leaflet_html():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            body { margin:0; padding:0; }
            #map { width:100%; height:440px; background:#0e1117; border-radius:8px; }

            .pulse-dot {
                width: 14px; height: 14px;
                border-radius: 50%;
                background: var(--dot-color, rgb(255,40,40));
                box-shadow: 0 0 10px var(--dot-color, rgb(255,40,40)), 0 0 20px var(--dot-color, rgb(255,40,40));
                position: relative;
                cursor: pointer;
            }
            .pulse-dot::before {
                content: '';
                position: absolute;
                top: 50%; left: 50%;
                width: 14px; height: 14px;
                border-radius: 50%;
                background: var(--glow-color, rgba(255,40,40,0.35));
                transform: translate(-50%, -50%);
                animation: pulse-ring 1.8s ease-out infinite;
            }
            @keyframes pulse-ring {
                0%   { width: 14px; height: 14px; opacity: 1; }
                100% { width: 55px; height: 55px; opacity: 0; }
            }

            .leaflet-popup-content-wrapper {
                background: #1a1a2e !important; color: white !important;
                border-radius: 8px !important; font-size: 13px;
            }
            .leaflet-popup-tip { background: #1a1a2e !important; }
            .map-legend {
                position: absolute; bottom: 18px; left: 12px; z-index: 1000;
                background: rgba(15,15,30,0.88); padding: 10px 14px; border-radius: 8px;
                font-family: 'Segoe UI', sans-serif; font-size: 12px; color: white;
                border: 1px solid rgba(255,255,255,0.12); line-height: 1.7;
            }
            .legend-dot {
                display: inline-block; width: 10px; height: 10px;
                border-radius: 50%; margin-right: 6px; vertical-align: middle;
            }
        </style>
    </head>
    <body>
        <div id="map"></div>
        <div class="map-legend">
            <b>Threat Legend</b><br/>
            <span class="legend-dot" style="background:rgb(255,40,40)"></span> DDoS<br/>
            <span class="legend-dot" style="background:rgb(180,0,255)"></span> Botnet<br/>
            <span class="legend-dot" style="background:rgb(255,140,0)"></span> BruteForce
        </div>
        <script>
            // Initialize Map with Scroll Zoom enabled and restrict zoom to prevent edge gaps
            var map = L.map('map', {
                zoomControl: true, 
                attributionControl: false, 
                scrollWheelZoom: true, 
                dragging: true,
                minZoom: 2 // Prevents zooming out too far (stops multiple worlds & gray bars)
            }).setView([20, 0], 2);
            
            // English base tiles (Esri Dark Gray Base)
            L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
                maxZoom: 16
            }).addTo(map);
            L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
                maxZoom: 16
            }).addTo(map);

            var currentMarkers = {};

            // Polling function to read data from Streamlit parent DOM without reloading iframe
            setInterval(function() {
                try {
                    var parentDoc = window.parent.document;
                    var dataDiv = parentDoc.getElementById('hidden_attack_data');
                    if (dataDiv) {
                        var points = JSON.parse(dataDiv.innerText);
                        points.forEach((pt, index) => {
                            if (!currentMarkers[index]) {
                                var el = document.createElement('div');
                                el.className = 'pulse-dot';
                                el.style.setProperty('--dot-color', pt.c);
                                el.style.setProperty('--glow-color', pt.g);
                                
                                var marker = L.marker([pt.lat, pt.lon], {
                                    icon: L.divIcon({className:'', html: el, iconSize:[18,18], iconAnchor:[9,9]})
                                }).addTo(map);
                                
                                marker.bindPopup(
                                    "<b>&#128680; Attack Origin</b><br/>" +
                                    pt.flag + " <b>" + pt.country + "</b> &mdash; " + pt.city + "<br/>" +
                                    "&#128421; IP: <b>" + pt.ip + "</b><br/>" +
                                    "&#9876; Type: <b>" + pt.attack + "</b>"
                                );
                                currentMarkers[index] = marker;
                            }
                        });
                    }
                } catch(e) {}
            }, 500);
        </script>
    </body>
    </html>
    """

# ─────────────────────────────────────────────────────────────────────────────

@st.cache_resource
def load_ml_components():
    return joblib.load('ids_rf_model.pkl'), joblib.load('scaler.pkl')

rf_model, scaler = load_ml_components()

CATEGORIES   = {0: 'Benign', 1: 'Botnet', 2: 'BruteForce', 3: 'DDoS', 4: 'DoS'}
IOT_DEVICES  = ['192.168.1.104 (Camera)', '192.168.1.112 (Thermostat)',
                '192.168.1.109 (SmartPlug)', '192.168.1.135 (Sensor)']
PORTS        = {"TCP": [80, 443, 22, 21], "UDP": [53, 67, 68, 123], "ICMP": [0]}
CSV_FILE     = "captured_iot_traffic.csv"

@st.cache_resource
def prepare_traffic_csv():
    if not os.path.exists(CSV_FILE):
        rows = []
        for _ in range(500):
            features = list(np.random.uniform(low=0.7, high=4.5, size=46))
            source   = np.random.choice(IOT_DEVICES)
            proto    = np.random.choice(list(PORTS.keys()))
            port     = np.random.choice(PORTS[proto])
            rows.append([source, proto, port, True] + features)
        cols = ["Source", "Protocol", "Port", "IsAttack_Flag"] + [f"Feature_{i}" for i in range(1, 47)]
        pd.DataFrame(rows, columns=cols).to_csv(CSV_FILE, index=False)
    return pd.read_csv(CSV_FILE)

attack_traffic_data = prepare_traffic_csv()

# ── Session State ─────────────────────────────────────────────────────────────
defaults = {
    'monitoring_mode': 'stopped',
    'packet_log':      pd.DataFrame(columns=["Timestamp","Source","Dest Port","Protocol","Confidence","Classification","Attacker IP","Origin"]),
    'stats':           {"Total": 0, "Blocked": 0, "Permitted": 0},
    'chart_data':      pd.DataFrame(columns=["Benign Packets/s", "Attack Packets/s"]),
    'system_logs':     [],
    'saved_sessions':  [],
    'csv_index':       0,
    'attack_points':   [],
    'active_attacks':  [],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Title ─────────────────────────────────────────────────────────────────────
st.title("🛡️ ML-Based IDS/IPS for Anomalous Traffic Detection in Simulated IoT Environments")

# ── Sidebar ───────────────────────────────────────────────────────────────────
sidebar = st.sidebar
sidebar.header("Gateway Controls")

if sidebar.button("🟢 Start Passive Monitoring"):
    st.session_state.monitoring_mode = 'passive'

st.sidebar.markdown("---")
st.sidebar.header("Active Threat Simulations")

def trigger_alert(attack_name):
    try:
        notification.notify(
            title="🚨 IDS/IPS CRITICAL ALERT",
            message=f"{attack_name} Simulation Started. Immediate IPS action required.",
            app_name="IoT Central Gateway",
            timeout=5
        )
    except: pass
    try:
        for _ in range(3):
            winsound.Beep(2500, 400)
            time.sleep(0.1)
    except: pass

st.sidebar.markdown("**Select Attack Vectors to Mix:**")
toggle_ddos   = st.sidebar.toggle("🔴 DDoS Attack",       value=True)
toggle_botnet = st.sidebar.toggle("🟣 Botnet Infection",  value=False)
toggle_brute  = st.sidebar.toggle("🟠 BruteForce",        value=False)

selected_attacks = []
if toggle_ddos:   selected_attacks.append("DDoS")
if toggle_botnet: selected_attacks.append("Botnet")
if toggle_brute:  selected_attacks.append("BruteForce")

if sidebar.button("🔴 Start Mixed Threat Simulation"):
    st.session_state.monitoring_mode = 'mixed_attack'
    st.session_state.active_attacks  = selected_attacks
    st.session_state.attack_points   = []
    if selected_attacks:
        threading.Thread(target=trigger_alert, args=(" + ".join(selected_attacks),), daemon=True).start()

st.sidebar.markdown("---")
if sidebar.button("⏹️ Stop & Save Session"):
    if len(st.session_state.packet_log) > 0:
        session_data = {
            "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats":   dict(st.session_state.stats),
            "logs":    list(st.session_state.system_logs),
            "packets": st.session_state.packet_log.copy(),
            "attack_points": list(st.session_state.attack_points),
        }
        st.session_state.saved_sessions.append(session_data)
        st.session_state.packet_log   = st.session_state.packet_log.iloc[0:0]
        st.session_state.stats        = {"Total": 0, "Blocked": 0, "Permitted": 0}
        st.session_state.chart_data   = st.session_state.chart_data.iloc[0:0]
        st.session_state.system_logs  = []
        st.session_state.attack_points= []
    st.session_state.monitoring_mode = 'stopped'

delay = sidebar.slider("Traffic Speed (Delay)", 0.05, 1.5, 0.5)

# ── Metric cards ──────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)
met_total     = col1.empty()
met_blocked   = col2.empty()
met_permitted = col3.empty()

def update_metrics():
    met_total.markdown(f'<div class="metric-box"><h3>Records Evaluated</h3><h2>{st.session_state.stats["Total"]}</h2></div>', unsafe_allow_html=True)
    met_blocked.markdown(f'<div class="metric-box"><h3>Threats Dropped (IPS)</h3><h2 class="alert-text">{st.session_state.stats["Blocked"]}</h2></div>', unsafe_allow_html=True)
    met_permitted.markdown(f'<div class="metric-box"><h3>Safe Packets Forwarded</h3><h2 class="safe-text">{st.session_state.stats["Permitted"]}</h2></div>', unsafe_allow_html=True)

update_metrics()

chart_placeholder = st.empty()

# ── Live Attack Origin Map ────────────────────────────────────────────────────
st.markdown("### 🌍 Live Attack Origin Map")
map_placeholder = st.empty()

st.subheader("Intercepted Traffic Dashboard")
table_placeholder = st.empty()

# ── Hidden Data Div (Used to pass data to Map without reloading) ────────────
data_div_placeholder = st.empty()

def update_hidden_data():
    # Convert attack points to JS format with CSS colors
    js_points = []
    for pt in st.session_state.attack_points:
        js_points.append({
            "lat": pt["lat"], "lon": pt["lon"], "ip": pt["ip"],
            "city": pt["city"], "country": pt["country"], "flag": pt["flag"],
            "attack": pt["attack"],
            "c": ATTACK_CSS_COLORS.get(pt["attack"], "rgb(255,40,40)"),
            "g": ATTACK_GLOW_COLORS.get(pt["attack"], "rgba(255,40,40,0.35)")
        })
    json_data = json.dumps(js_points)
    data_div_placeholder.markdown(f'<div id="hidden_attack_data" style="display:none;">{json_data}</div>', unsafe_allow_html=True)

# Initial map render - Called once per script run
with map_placeholder.container():
    components.html(get_leaflet_html(), height=460)
    
update_hidden_data()

# ── Live monitoring loop ──────────────────────────────────────────────────────
if st.session_state.monitoring_mode != 'stopped':
    st.markdown("### 📡 Live Session Logs")
    log_placeholder = st.empty()

    while st.session_state.monitoring_mode != 'stopped':
        timestamp  = time.strftime('%H:%M:%S')
        is_threat  = 0
        is_benign  = 0
        attacker_ip   = "—"
        origin_str    = "—"

        # ── Decide frame type ──
        if st.session_state.monitoring_mode == 'mixed_attack':
            active_attacks = st.session_state.get('active_attacks', [])
            if active_attacks and random.random() < 0.35:
                is_attack_frame        = True
                simulated_attack_type  = random.choice(active_attacks)
            else:
                is_attack_frame = False
        else:
            is_attack_frame = False

        # ── Generate traffic ──
        if not is_attack_frame:
            base_benign = np.array([3.65190905e+01, 2.57193372e+05, 5.95929925e+00, 9.21569105e+01,
                                    7.29081746e+04, 1.30390405e+04, -4.67755111e-05, -1.07481796e-01,
                                    3.22947758e-01, -8.17179534e-02, -4.95465472e-02,  1.53347023e-01,
                                   -5.54093063e-01,  5.55459180e-01, -8.62351872e-02,  6.34496515e-01,
                                    2.43829773e-01, -5.10804094e+01,  6.48064696e+02,  7.03065072e-02,
                                    4.35824653e-01, -3.66377982e-03,  5.40033597e-01, -5.17144783e-01,
                                   -2.68794050e-03,  6.13855584e-01,  7.30150452e-01, -6.11844298e-02,
                                   -5.28163352e-04, -5.04462174e-03, -4.88245807e-02,  9.96126232e-01,
                                    1.01038127e+00, -9.05646763e+02,  2.85819732e+01,  5.77465764e+02,
                                    5.15845638e+02, -1.32492216e+01,  5.07232274e+02,  5.41501106e+07,
                                    8.44026756e+00,  1.05643384e+01,  3.77064790e+00, -1.54198202e+05,
                                    2.75730421e-01,  1.66959255e+02])
            raw_packet  = base_benign + np.random.normal(0, 0.0001, size=46)
            source_dev  = random.choice(IOT_DEVICES)
            proto       = random.choice(list(PORTS.keys()))
            dest_port   = random.choice(PORTS[proto])
            scaled      = scaler.transform(raw_packet.reshape(1, -1))
            probs       = rf_model.predict_proba(scaled)[0]
            pred_idx    = np.argmax(probs)
            confidence  = probs[pred_idx] * 100
            category    = CATEGORIES[pred_idx]
        else:
            source_dev  = random.choice(IOT_DEVICES)
            proto       = random.choice(list(PORTS.keys()))
            dest_port   = random.choice(PORTS[proto])
            category    = simulated_attack_type
            confidence  = np.random.uniform(94.5, 99.8)

            # ── Geo-IP lookup ──
            ip, city, country, flag, lat, lon = pick_attacker(category)
            attacker_ip = ip
            origin_str  = f"{flag} {city}, {country}"

            st.session_state.attack_points.append({
                "lat": lat, "lon": lon,
                "ip": ip, "city": city,
                "country": country, "flag": flag,
                "attack": category,
                "color": ATTACK_COLORS.get(category, [255, 50, 50, 220])
            })

        # ── Stats & logs ──
        st.session_state.stats["Total"] += 1

        if category == 'Benign':
            st.session_state.stats["Permitted"] += 1
            status_html = "🟢 ALLOWED"
            is_benign   = 1
            log_line    = f"[{timestamp}] INFO: Forwarded {proto} packet from {source_dev} → port {dest_port}."
        else:
            st.session_state.stats["Blocked"] += 1
            is_threat = 1
            if category == 'BruteForce':
                status_html = f"🍯 HONEYPOT REDIRECT ({category})"
                log_line    = (f"[{timestamp}] DECEPTION TRAP: {category} from {source_dev} "
                               f"[Origin: {origin_str} | IP: {attacker_ip}] → Redirecting to V-Honeypot. "
                               f"(Conf: {confidence:.1f}%)")
            elif category == 'Botnet':
                status_html = f"⛓️ QUARANTINED ({category})"
                log_line    = (f"[{timestamp}] ZERO-TRUST: {category} from {source_dev} "
                               f"[Origin: {origin_str} | IP: {attacker_ip}] → Device quarantined to VLAN. "
                               f"(Conf: {confidence:.1f}%)")
            else:
                status_html = f"🚧 TARPITTED ({category})"
                log_line    = (f"[{timestamp}] RATE-LIMIT TRAP: {category} from {source_dev} "
                               f"[Origin: {origin_str} | IP: {attacker_ip}] → Tarpitting to 1 byte/sec. "
                               f"(Conf: {confidence:.1f}%)")

        st.session_state.system_logs.insert(0, log_line)
        if len(st.session_state.system_logs) > 50:
            st.session_state.system_logs.pop()

        new_row = {
            "Timestamp":      timestamp,
            "Source":         source_dev,
            "Dest Port":      str(dest_port),
            "Protocol":       proto,
            "Confidence":     f"{confidence:.1f}%",
            "Classification": status_html,
            "Attacker IP":    attacker_ip,
            "Origin":         origin_str,
        }
        st.session_state.packet_log = pd.concat(
            [pd.DataFrame([new_row]), st.session_state.packet_log]
        ).head(15)

        new_chart_row = pd.DataFrame(
            {"Benign Packets/s": [is_benign], "Attack Packets/s": [is_threat]},
            index=[timestamp]
        )
        st.session_state.chart_data = pd.concat(
            [st.session_state.chart_data, new_chart_row]
        ).tail(30)

        # ── UI Updates ──
        update_metrics()
        chart_placeholder.line_chart(st.session_state.chart_data, color=["#00ea69", "#ff4b4b"])

        # Update hidden data div smoothly (Leaflet will auto-fetch it)
        update_hidden_data()

        table_placeholder.write(
            st.session_state.packet_log.to_html(escape=False, index=False),
            unsafe_allow_html=True
        )
        log_text = "\n".join(st.session_state.system_logs)
        log_placeholder.code(log_text, language="bash")

        time.sleep(delay)

else:
    # ── Stopped Mode ──────────────────────────────────────────────────────────
    st.info("Monitoring is currently stopped. Click a button on the left to start.")

    if len(st.session_state.saved_sessions) > 0:
        st.markdown("---")
        st.header("🗄️ Saved Session History")
        for i, session in enumerate(reversed(st.session_state.saved_sessions)):
            with st.expander(f"Session @ {session['time']} | Total Evaluated: {session['stats']['Total']}"):
                colA, colB = st.columns(2)
                colA.metric("Packets Blocked",   session['stats']['Blocked'])
                colB.metric("Packets Permitted", session['stats']['Permitted'])

                # Render saved attack map for this session
                saved_pts = session.get('attack_points', [])
                if saved_pts:
                    st.markdown("**🌍 Attack Origin Map (Session Snapshot):**")
                    with st.container():
                        map_data_json = json.dumps([{'lat':p['lat'],'lon':p['lon'],'ip':p['ip'],'city':p['city'],'country':p['country'],'flag':p['flag'],'attack':p['attack'],'c':ATTACK_CSS_COLORS.get(p['attack'],'rgb(255,40,40)'),'g':ATTACK_GLOW_COLORS.get(p['attack'],'rgba(255,40,40,0.35)')} for p in saved_pts])
                        components.html(get_leaflet_html() + f"<script>setTimeout(()=>{{\nvar mapData={map_data_json};\nmapData.forEach((pt, i) => {{ var el=document.createElement('div'); el.className='pulse-dot'; el.style.setProperty('--dot-color', pt.c); el.style.setProperty('--glow-color', pt.g); var marker = L.marker([pt.lat, pt.lon], {{icon: L.divIcon({{className:'', html: el, iconSize:[18,18], iconAnchor:[9,9]}})}}).addTo(map); }});\n}}, 1000);</script>", height=460)

                st.markdown("**Interception Log (Last 15 Packets):**")
                st.dataframe(session['packets'])
                st.markdown("**Raw System Logs:**")
                st.code("\n".join(session['logs']), language="bash")
