# CyberNet Guardian — Local Network Intelligence Lab

A beginner-friendly, real-data networking and security learning dashboard.

## Live features
- Reads the laptop's private IPv4 address, subnet and default gateway.
- Discovers responding devices on the same local subnet (maximum /24) using ping and the operating system ARP table.
- Shows MAC addresses only when the operating system exposes them.
- Checks a curated set of common TCP ports on a selected private IP on the same subnet.
- Builds an explainable Network Fingerprint from the collected local network facts.

## Run it on your laptop
1. Install Python 3.10 or newer.
2. Download/clone this repository to your laptop.
3. Open Terminal / PowerShell in the project folder.
4. Install dependencies: `python -m pip install -r requirements.txt`
5. Start the agent: `python app.py`
6. On the laptop open `http://127.0.0.1:5000`.
7. To use it on your iPhone, connect both devices to the same Wi-Fi. Find the laptop's private IPv4 address and open `http://LAPTOP-IP:5000` on the iPhone, for example `http://192.168.1.5:5000`.

If the phone cannot connect, allow Python through the laptop firewall on a private network. Do not expose port 5000 to the public internet.

## Important
- GitHub Pages is static hosting and cannot run this Python agent. The dashboard needs the Python process running on your laptop.
- iPhone Safari cannot perform raw LAN scans itself; the laptop agent performs the checks and serves results to the phone.
- Some devices block ping, sleep, use Wi-Fi client isolation, or do not expose MAC addresses. Discovery may not find every device.
- Port checks cover only common TCP ports. An open port is not automatically a vulnerability; this is not a full vulnerability scanner.
- Only scan networks and devices you own or have explicit permission to assess.

## Learning feature: Network Fingerprint
The fingerprint combines the local subnet, gateway, responding devices and exposed common ports into an explainable snapshot. It is a learning aid, not an enterprise asset inventory.
