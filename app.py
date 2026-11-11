from flask import Flask, jsonify, request, send_from_directory
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress, platform, re, socket, subprocess, time
import psutil

app = Flask(__name__, static_folder=".", static_url_path="")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 3306: "MySQL", 5432: "PostgreSQL"
}

def local_network():
    candidates = []
    for _, addresses in psutil.net_if_addrs().items():
        for a in addresses:
            if a.family == socket.AF_INET and a.address and a.netmask:
                try:
                    iface = ipaddress.ip_interface(f"{a.address}/{a.netmask}")
                    if iface.ip.is_private and not iface.ip.is_loopback and iface.network.num_addresses > 1:
                        candidates.append(iface)
                except ValueError:
                    pass
    # Prefer the smallest private subnet; it is usually the active Wi-Fi/LAN segment.
    candidates.sort(key=lambda x: x.network.num_addresses)
    return candidates[0] if candidates else None

def get_gateway():
    system = platform.system().lower()
    commands = []
    if system == "linux":
        commands = [["ip", "route", "show", "default"]]
    elif system == "darwin":
        commands = [["route", "-n", "get", "default"]]
    elif system == "windows":
        commands = [["route", "print", "-4"]]
    for cmd in commands:
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=2)
            if system == "linux":
                m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            elif system == "darwin":
                m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            else:
                m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None

def ping_host(ip):
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-w", "850", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.8)
        return ip
    except Exception:
        return None

def arp_table():
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        return {}
    found = {}
    for line in out.splitlines():
        ips = re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", line)
        macs = re.findall(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ips:
            try:
                ip = str(ipaddress.ip_address(ips[0]))
                if macs:
                    found[ip] = macs[0].replace("-", ":").lower()
            except ValueError:
                pass
    return found

@app.get("/")
def home():
    return send_from_directory(".", "index.html")

@app.get("/api/status")
def status():
    iface = local_network()
    return jsonify({
        "online": True,
        "host": socket.gethostname(),
        "platform": platform.system(),
        "network": str(iface.network) if iface else None,
        "local_ip": str(iface.ip) if iface else None,
        "netmask": str(iface.netmask) if iface else None,
        "gateway": get_gateway(),
        "backend": "CyberNet Guardian local agent"
    })

@app.post("/api/discover")
def discover():
    iface = local_network()
    if not iface:
        return jsonify({"error": "No private IPv4 network interface was detected. Connect to Wi-Fi or Ethernet."}), 400
    network = iface.network
    if network.num_addresses > 256:
        return jsonify({"error": "Your subnet is larger than /24. For safety, automatic discovery is limited to 256 addresses."}), 400
    started = time.time()
    targets = [str(ip) for ip in network.hosts() if ip != iface.ip]
    responsive = set()
    with ThreadPoolExecutor(max_workers=48) as pool:
        futures = [pool.submit(ping_host, ip) for ip in targets]
        for f in as_completed(futures):
            result = f.result()
            if result:
                responsive.add(result)
    macs = arp_table()
    responsive.update(ip for ip in macs if ipaddress.ip_address(ip) in network and ip != str(iface.ip))
    devices = []
    for ip in sorted(responsive, key=lambda x: int(ipaddress.ip_address(x))):
        devices.append({
            "ip": ip,
            "mac": macs.get(ip, "Not visible in ARP table"),
            "method": "Ping response" if ip in responsive else "ARP",
            "note": "Device responded to local discovery; identity is not verified."
        })
    return jsonify({
        "network": str(network),
        "local_ip": str(iface.ip),
        "gateway": get_gateway(),
        "devices": devices,
        "count": len(devices),
        "duration_seconds": round(time.time() - started, 2),
        "limitations": "Some devices block ping or hide MAC addresses. A missing device is not proof it is offline."
    })

@app.post("/api/ports")
def ports():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("ip", "")).strip()
    try:
        target = ipaddress.ip_address(raw)
    except ValueError:
        return jsonify({"error": "Enter a valid IPv4 address."}), 400
    iface = local_network()
    if not target.is_private or target.version != 4 or not iface or target not in iface.network:
        return jsonify({"error": "For safety, port checks are limited to private IPv4 devices on this same local subnet."}), 403
    results = []
    for port, service in COMMON_PORTS.items():
        sock = socket.socket()
        sock.settimeout(0.35)
        try:
            code = sock.connect_ex((str(target), port))
            if code == 0:
                results.append({"port": port, "service": service, "state": "Open"})
        except OSError:
            pass
        finally:
            sock.close()
    return jsonify({
        "ip": str(target),
        "open_ports": results,
        "checked": len(COMMON_PORTS),
        "note": "Only a small set of common TCP ports was checked. Closed or filtered ports may not appear; this is not a full vulnerability scan."
    })

if __name__ == "__main__":
    print("\nCyberNet Guardian is starting...")
    print("On this laptop: http://127.0.0.1:5000")
    print("On your phone, use the laptop's LAN IPv4 address, e.g. http://192.168.1.5:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
