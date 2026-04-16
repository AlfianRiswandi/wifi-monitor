from flask import Flask, render_template_string
from scapy.all import ARP, Ether, srp
import json
import time
from datetime import datetime
import threading
import socket
from mac_vendor_lookup import MacLookup

app = Flask(__name__)

NETWORK = "192.168.0.0/24"
LOG_FILE = "devices.json"

mac_lookup = MacLookup()
mac_lookup.load_vendors()

# ================= KNOWN DEVICES =================
KNOWN_DEVICES = {
    "b4:8c:9d:d3:b7:0f": "Laptop Admin",
    "ac:15:a2:57:a8:52": "Router TP-Link",
    "ec:e6:4a:25:df:40": "Router FiberHome"
}

scan_status = {
    "progress": 0,
    "status": "Idle",
    "total": 0
}

HISTORY = {
    "labels": [],
    "values": []
}

ALERTS = []

# ================= HOSTNAME =================
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# ================= VENDOR =================
def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except:
        return "Unknown Vendor"

# ================= DEVICE TYPE =================
def detect_device_type(vendor):
    v = vendor.lower()

    if any(x in v for x in ["samsung","xiaomi","oppo","vivo","iphone","huawei"]):
        return "📱 HP"
    elif any(x in v for x in ["intel","dell","hp","lenovo","asus","acer"]):
        return "💻 Laptop"
    elif "tp-link" in v or "fiberhome" in v:
        return "📡 Router"
    else:
        return "❓ Unknown"

# ================= SCAN NETWORK =================
def scan_network():
    global scan_status

    scan_status["status"] = "Scanning..."
    scan_status["progress"] = 10

    arp = ARP(pdst=NETWORK)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    for _, received in result:
        mac = received.hwsrc.lower()
        vendor = get_vendor(mac)
        is_known = mac in KNOWN_DEVICES

        devices.append({
            "ip": received.psrc,
            "mac": mac,
            "name": KNOWN_DEVICES.get(mac, "Unknown Device"),
            "vendor": vendor,
            "type": detect_device_type(vendor),
            "status": "ONLINE",
            "status_class": "online",
            "danger": "danger" if not is_known else "",
            "last_seen": str(datetime.now())
        })

    scan_status["progress"] = 100
    scan_status["status"] = "Selesai"
    scan_status["total"] = len(devices)

    return devices

# ================= ALERT =================
def add_alert(msg):
    ALERTS.append(f"{datetime.now().strftime('%H:%M:%S')} - {msg}")
    if len(ALERTS) > 10:
        ALERTS.pop(0)

# ================= FILE =================
def load_devices():
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_devices(devices):
    with open(LOG_FILE, "w") as f:
        json.dump(devices, f, indent=4)

# ================= MONITOR =================
def monitor():
    while True:
        new_devices = scan_network()
        old_devices = load_devices()

        old_macs = [d["mac"] for d in old_devices]

        for d in new_devices:
            if d["mac"] not in old_macs:
                print(f"[BARU] {d['ip']} - {d['mac']}")

                if d["mac"] not in KNOWN_DEVICES:
                    add_alert(f"⚠️ Unknown Device: {d['ip']} ({d['mac']})")

        # OFFLINE DETECTION
        for old in old_devices:
            if old["mac"] not in [d["mac"] for d in new_devices]:
                old["status"] = "OFFLINE"
                old["status_class"] = "offline"
                new_devices.append(old)

        save_devices(new_devices)

        # ================= HISTORY (ONLINE ONLY) =================
        now = datetime.now().strftime("%H:%M:%S")

        online_count = sum(1 for d in new_devices if d["status"] == "ONLINE")

        HISTORY["labels"].append(now)
        HISTORY["values"].append(online_count)

        if len(HISTORY["labels"]) > 20:
            HISTORY["labels"].pop(0)
            HISTORY["values"].pop(0)

        time.sleep(20)

# ================= HTML =================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>WiFi IDS Dashboard</title>
<meta http-equiv="refresh" content="5">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {
    background:#0f172a;
    color:white;
    font-family:Arial;
    text-align:center;
}

.box {
    background:#1e293b;
    padding:15px;
    margin:10px auto;
    width:60%;
    border-radius:10px;
}

.danger { background:#7f1d1d; }
.online { color:#22c55e; }
.offline { color:#ef4444; }

#chartBox {
    width:60%;
    margin:auto;
}
canvas {
    max-height:250px;
}

table {
    width:95%;
    margin:auto;
    border-collapse:collapse;
}
td, th {
    padding:8px;
    border:1px solid #334155;
}

a {
    color:#38bdf8;
    text-decoration:none;
    font-weight:bold;
}
</style>
</head>

<body>

<h2>📡 WiFi Intrusion Detection System</h2>

<div class="box">
<p>Status: {{status}}</p>
<p>Total Device: {{total}}</p>
</div>

<div class="box">
<h3>🚨 Alerts</h3>
{% for a in alerts %}
<p>{{a}}</p>
{% endfor %}
</div>

<div id="chartBox">
<canvas id="chart"></canvas>
</div>

<table>
<tr>
<th>Name</th>
<th>Type</th>
<th>IP</th>
<th>MAC</th>
<th>Status</th>
<th>Router Access</th>
<th>Login Info</th>
</tr>

{% for d in devices %}
<tr class="{{d.danger}}">
<td>{{d.name}}</td>
<td>{{d.type}}</td>
<td>{{d.ip}}</td>
<td>{{d.mac}}</td>
<td class="{{d.status_class}}">{{d.status}}</td>

<td>
{% if "TP-Link" in d.name %}
<a href="http://192.168.0.1" target="_blank">🌐 Login</a>
{% elif "FiberHome" in d.name %}
<a href="http://192.168.1.1" target="_blank">🌐 Login</a>
{% else %}
-
{% endif %}
</td>

<td>
{% if "TP-Link" in d.name %}
admin / admin
{% elif "FiberHome" in d.name %}
user / user1234
{% else %}
-
{% endif %}
</td>
</tr>
{% endfor %}
</table>

<script>
new Chart(document.getElementById("chart"), {
    type: "line",
    data: {
        labels: {{labels | safe}},
        datasets: [{
            label: "Online Devices",
            data: {{values | safe}},
            tension: 0.4,
            fill: true,
            pointRadius: 2
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true,
                ticks: { precision: 0 }
            }
        }
    }
});
</script>

</body>
</html>
"""

# ================= ROUTE =================
@app.route("/")
def index():
    devices = load_devices()

    return render_template_string(
        HTML,
        devices=devices,
        status=scan_status["status"],
        total=scan_status["total"],
        labels=json.dumps(HISTORY["labels"]),
        values=json.dumps(HISTORY["values"]),
        alerts=ALERTS
    )

# ================= MAIN =================
if __name__ == "__main__":
    t = threading.Thread(target=monitor)
    t.daemon = True
    t.start()

    app.run(host="0.0.0.0", port=5000)