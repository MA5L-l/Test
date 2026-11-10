#!/usr/bin/env python3
"""
camscan.py - Detecte les cameras potentielles sur le Wi-Fi local et en Bluetooth (BLE).

A lancer sur TON ordinateur, connecte au Wi-Fi de l'hotel.
    pip install bleak          # optionnel, pour le scan Bluetooth
    python3 camscan.py         # (sudo conseille sous Linux/macOS)

Options :
    --no-wifi        ne pas scanner le reseau
    --no-ble         ne pas scanner le Bluetooth
    --ble-time N     duree du scan Bluetooth en secondes (defaut 15)
    --subnet CIDR    forcer le sous-reseau (ex. 192.168.1.0/24)

Uniquement des tests passifs ou legers (ping, ouverture de port TCP, decouverte
ONVIF/SSDP). Aucune tentative de connexion avec identifiants.
"""
import argparse
import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

# Ports typiques des cameras IP / NVR
CAMERA_PORTS = {
    554: "RTSP (flux video)",
    8554: "RTSP alternatif",
    1935: "RTMP (streaming)",
    8000: "Hikvision SDK",
    37777: "Dahua",
    34567: "XMEye / NetSurveillance (cameras chinoises generiques)",
    8899: "ONVIF (cameras generiques)",
    6668: "Tuya (cameras/objets connectes)",
    9527: "Cameras chinoises generiques",
    80: "Interface web",
    8080: "Interface web alt.",
    443: "Interface web HTTPS",
}
STRONG_PORTS = {554, 8554, 1935, 8000, 37777, 34567, 8899, 9527}

# Prefixes MAC (OUI) de fabricants de cameras - liste indicative, non exhaustive
CAMERA_OUI = {
    "44:19:B6": "Hikvision", "28:57:BE": "Hikvision", "C0:56:E3": "Hikvision",
    "BC:AD:28": "Hikvision", "4C:BD:8F": "Hikvision", "54:C4:15": "Hikvision",
    "3C:EF:8C": "Dahua", "90:02:A9": "Dahua", "E0:50:8B": "Dahua", "38:AF:29": "Dahua",
    "2C:AA:8E": "Wyze", "D0:3F:27": "Wyze", "7C:78:B2": "Wyze",
    "00:62:6E": "Foscam", "C4:D6:55": "Foscam",
    "9C:8E:CD": "Amcrest",
    "EC:71:DB": "Reolink",
    "00:40:8C": "Axis", "AC:CC:8E": "Axis", "B8:A4:4F": "Axis",
    "18:B4:30": "Nest", "64:16:66": "Nest",
    "FC:65:DE": "Amazon (Ring/Blink possible)",
}

BLE_KEYWORDS = re.compile(
    r"cam|ipc|spy|hidden|dvr|nvr|wyze|arlo|blink|ring|eufy|reolink|hik|dahua|"
    r"tapo|yi[-_ ]|v380|imou|ezviz|xmeye|icsee|lookcam|mini.?dv|a9|x10",
    re.I,
)


def banner(t):
    print("\n" + "=" * 60 + f"\n{t}\n" + "=" * 60)


# ----------------------------------------------------------------------------- Wi-Fi
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def ping(ip):
    flag = "-n" if platform.system() == "Windows" else "-c"
    wflag = {"Windows": ["-w", "500"], "Darwin": ["-t", "1"]}.get(platform.system(), ["-W", "1"])
    try:
        subprocess.run(["ping", flag, "1", *wflag, str(ip)], timeout=3,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # pas de ping : une tentative TCP suffit a remplir la table ARP
        with socket.socket() as s:
            s.settimeout(0.3)
            s.connect_ex((str(ip), 80))


def arp_table():
    """Retourne {ip: mac} depuis la table ARP du systeme."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        out = ""
    if not out and platform.system() == "Linux":
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        except FileNotFoundError:
            out = open("/proc/net/arp").read()
    table = {}
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
        if ip and mac:
            parts = re.split(r"[:-]", mac.group(0))
            table[ip.group(1)] = ":".join(p.zfill(2) for p in parts).upper()
    return table


def open_ports(ip, timeout=0.6):
    found = []
    for port in CAMERA_PORTS:
        with socket.socket() as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
    return found


def onvif_discovery(timeout=3):
    """WS-Discovery : les cameras ONVIF repondent a cette sonde multicast."""
    msg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header><w:MessageID>uuid:%s</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
        '</d:Probe></e:Body></e:Envelope>' % uuid.uuid4()
    )
    return _multicast(msg.encode(), ("239.255.255.250", 3702), timeout)


def ssdp_discovery(timeout=3):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    return _multicast(msg.encode(), ("239.255.255.250", 1900), timeout)


def _multicast(payload, addr, timeout):
    res = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        s.sendto(payload, addr)
        while True:
            data, (ip, _) = s.recvfrom(65535)
            res.setdefault(ip, data.decode(errors="ignore"))
    except (socket.timeout, OSError):
        pass
    finally:
        s.close()
    return res


def scan_wifi(subnet=None):
    banner("SCAN RESEAU (Wi-Fi)")
    me = local_ip()
    if not me:
        print("Pas de connexion reseau detectee.")
        return []
    net = ipaddress.ip_network(subnet or f"{me}/24", strict=False)
    if net.num_addresses > 1024:
        print(f"Sous-reseau {net} trop grand, limite a {me}/24.")
        net = ipaddress.ip_network(f"{me}/24", strict=False)
    print(f"Ton IP : {me} - scan de {net} ...")

    with ThreadPoolExecutor(128) as ex:
        list(ex.map(ping, net.hosts()))

    onvif = onvif_discovery()
    ssdp = ssdp_discovery()
    arp = arp_table()
    hosts = {ip for ip in arp if ipaddress.ip_address(ip) in net} | set(onvif) | set(ssdp)
    hosts.discard(me)
    print(f"{len(hosts)} appareil(s) visible(s) sur le reseau.")
    if len(hosts) <= 1:
        print("! Tres peu d'appareils visibles : le Wi-Fi isole probablement les clients\n"
              "  (isolation AP). Une camera sur ce meme Wi-Fi resterait alors invisible.")

    with ThreadPoolExecutor(64) as ex:
        ports = dict(zip(hosts, ex.map(open_ports, hosts)))

    suspects = []
    for ip in sorted(hosts, key=lambda x: tuple(map(int, x.split(".")))):
        mac = arp.get(ip, "?")
        reasons, score = [], 0
        vendor = CAMERA_OUI.get(mac[:8])
        if vendor:
            reasons.append(f"fabricant camera : {vendor}"); score += 3
        if ip in onvif:
            reasons.append("repond a la decouverte ONVIF (camera IP)"); score += 3
        s = ssdp.get(ip, "")
        if re.search(r"camera|ipc|nvr|dvr|hikvision|dahua|video", s, re.I):
            reasons.append("annonce SSDP de type camera"); score += 2
        for p in ports[ip]:
            reasons.append(f"port {p} ouvert - {CAMERA_PORTS[p]}")
            score += 2 if p in STRONG_PORTS else 0
        level = "ELEVE" if score >= 3 else "moyen" if score >= 2 else "faible"
        print(f"\n  {ip:15}  MAC {mac}  -> risque {level}")
        for r in reasons:
            print(f"      - {r}")
        if score >= 2:
            suspects.append((ip, mac, level, reasons))
    return suspects


# ----------------------------------------------------------------------------- BLE
async def _ble(duration):
    from bleak import BleakScanner
    devs = await BleakScanner.discover(timeout=duration, return_adv=True)
    return devs.values()


def scan_ble(duration):
    banner(f"SCAN BLUETOOTH LE ({duration} s)")
    try:
        import bleak  # noqa: F401
    except ImportError:
        print("Module 'bleak' absent -> pip install bleak   (scan Bluetooth ignore)")
        return []
    try:
        results = asyncio.run(_ble(duration))
    except Exception as e:  # adaptateur coupe, permission refusee...
        print(f"Scan Bluetooth impossible : {e}")
        return []
    suspects = []
    rows = sorted(results, key=lambda r: -(r[1].rssi or -999))
    print(f"{len(rows)} appareil(s) Bluetooth detecte(s).")
    for dev, adv in rows:
        name = adv.local_name or dev.name or ""
        mac = (dev.address or "").upper()
        vendor = CAMERA_OUI.get(mac[:8])
        hit = bool(name and BLE_KEYWORDS.search(name)) or bool(vendor)
        dist = "tres proche" if adv.rssi > -55 else "proche" if adv.rssi > -70 else "loin"
        flag = "  <== SUSPECT" if hit else ""
        print(f"  {adv.rssi:4} dBm ({dist:11}) {mac:17} {name or '(sans nom)'}{flag}")
        if hit:
            suspects.append((mac, name, adv.rssi))
    print("\nAstuce : un appareil sans nom avec un signal tres fort (> -55 dBm) et que tu\n"
          "ne reconnais pas merite d'etre localise : deplace-toi, le signal monte en t'approchant.")
    return suspects


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--no-wifi", action="store_true")
    ap.add_argument("--no-ble", action="store_true")
    ap.add_argument("--ble-time", type=int, default=15)
    ap.add_argument("--subnet")
    a = ap.parse_args()

    wifi = [] if a.no_wifi else scan_wifi(a.subnet)
    ble = [] if a.no_ble else scan_ble(a.ble_time)

    banner("RESUME")
    if not wifi and not ble:
        print("Aucun appareil suspect detecte.\n"
              "Ce n'est PAS une garantie : une camera peut enregistrer sur carte SD sans\n"
              "reseau, ou etre sur un autre Wi-Fi. Fais aussi l'inspection visuelle.")
    for ip, mac, lvl, _ in wifi:
        print(f"  [Wi-Fi] {ip} ({mac}) - risque {lvl}")
    for mac, name, rssi in ble:
        print(f"  [BLE]   {mac} '{name}' - {rssi} dBm")
    print("\nVerification physique : eteins la lumiere et balaie la piece avec la lampe du\n"
          "telephone (un objectif renvoie un petit reflet), et filme avec la camera frontale\n"
          "pour reperer des LED infrarouges. Zones a verifier : detecteurs de fumee, reveils,\n"
          "chargeurs USB, prises, cadres, TV, ventilations, face au lit et a la douche.")


if __name__ == "__main__":
    sys.exit(main())
