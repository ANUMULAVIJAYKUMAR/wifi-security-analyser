from scapy.all import *
import re

def detect_encryption(pkt):
    if pkt.haslayer(Dot11Elt):
        crypto = set()
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%} \
                                  {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if re.search("privacy", capability):
            if pkt.haslayer(Dot11EltRSN):
                crypto.add("WPA2/WPA3")
            else:
                crypto.add("WEP/WPA")
        else:
            crypto.add("Open")
        return "/".join(crypto)
    return "Unknown"

def packet_handler(pkt, networks):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        bssid = pkt[Dot11].addr3
        signal = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else "N/A"
        stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else {}
        channel = stats.get("channel", "N/A")
        encryption = detect_encryption(pkt)
        networks[bssid] = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "signal": signal,
            "encryption": encryption,
        }

def scan_networks(iface):
    print(f"[+] Scanning Wi-Fi networks on interface: {iface}")
    networks = {}
    try:
        sniff(iface=iface, prn=lambda pkt: packet_handler(pkt, networks), timeout=20)
    except PermissionError:
        print("[-] Permission denied. Run as administrator or root.")
        return []
    return list(networks.values())
