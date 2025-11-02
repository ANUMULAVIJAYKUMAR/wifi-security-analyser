import csv
import os

OUTPUT_FILE = os.path.join("output", "networks.csv")

def ensure_output_dir():
    if not os.path.exists("output"):
        os.makedirs("output")

def save_to_csv(networks):
    ensure_output_dir()
    with open(OUTPUT_FILE, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["SSID", "BSSID", "Channel", "Signal", "Encryption"])
        for net in networks:
            writer.writerow([net["ssid"], net["bssid"], net["channel"], net["signal"], net["encryption"]])
    print(f"[+] Results saved to {OUTPUT_FILE}")
