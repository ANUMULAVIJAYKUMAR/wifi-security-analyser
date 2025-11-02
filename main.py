#!/usr/bin/env python3
"""
WiFi Security Analyzer — passive scanner and analyzer.
This script can either sniff Wi-Fi management frames using scapy
or run internal test cases when executed with --run-tests.
"""

import argparse
import csv
import sys
import time
from collections import OrderedDict

try:
    from scapy.all import sniff, Dot11, Dot11Elt
except Exception:
    sniff = None
    class Dot11:  # type: ignore
        pass
    class Dot11Elt:  # type: ignore
        pass

try:
    from tabulate import tabulate
except Exception:
    def tabulate(rows, headers=None, tablefmt=None):
        out = ''
        if headers:
            out += '\t'.join(headers) + '\n'
        for r in rows:
            out += '\t'.join(str(x) for x in r) + '\n'
        return out


def _iter_dot11elt(pkt):
    elt = None
    try:
        elt = pkt.getlayer(Dot11Elt)
    except Exception:
        elt = None
    while elt is not None:
        yield elt
        payload = getattr(elt, 'payload', None)
        if payload is None or not hasattr(payload, 'ID'):
            break
        elt = payload


def extract_ssid(pkt):
    for elt in _iter_dot11elt(pkt):
        try:
            if elt.ID == 0:
                raw = elt.info or b''
                return raw.decode(errors='ignore') if raw else '<hidden>'
        except Exception:
            continue
    return '<hidden>'


def extract_channel(pkt):
    for elt in _iter_dot11elt(pkt):
        try:
            if elt.ID == 3 and elt.info:
                return int(elt.info[0])
            if elt.ID == 61 and elt.info and len(elt.info) >= 1:
                return int(elt.info[0])
        except Exception:
            continue
    return None


def extract_signal(pkt):
    try:
        return getattr(pkt, 'dBm_AntSignal', None)
    except Exception:
        return None


def detect_encryption(pkt):
    try:
        cap = pkt.sprintf('%Dot11Beacon.cap%') or pkt.sprintf('%Dot11ProbeResp.cap%') or ''
    except Exception:
        cap = ''
    has_privacy = 'privacy' in cap.lower()
    found_rsn = False
    found_wpa = False
    for elt in _iter_dot11elt(pkt):
        try:
            if elt.ID == 48:
                found_rsn = True
            if elt.ID == 221 and elt.info and len(elt.info) >= 4 and elt.info[:4] == b'\x00P\xf2\x01':
                found_wpa = True
        except Exception:
            continue
    if not has_privacy:
        return 'OPEN'
    if found_rsn:
        return 'WPA2/WPA3 (RSN)'
    if found_wpa:
        return 'WPA (WPA1)'
    if has_privacy:
        return 'WEP/Unknown'
    return 'UNKNOWN'


class NetworkRecord:
    def __init__(self, ssid, bssid):
        self.ssid = ssid
        self.bssid = bssid
        self.channels = set()
        self.signal = None
        self.encryption = set()
        self.first_seen = time.time()
        self.last_seen = self.first_seen

    def update(self, channel, signal, enc):
        if channel is not None:
            try:
                self.channels.add(int(channel))
            except Exception:
                pass
        if signal is not None:
            try:
                if self.signal is None or signal > self.signal:
                    self.signal = signal
            except Exception:
                pass
        if enc:
            self.encryption.add(enc)
        self.last_seen = time.time()

    def to_row(self):
        enc = ','.join(sorted(self.encryption)) if self.encryption else 'UNKNOWN'
        ch = ','.join(str(c) for c in sorted(self.channels)) if self.channels else ''
        sig = self.signal if self.signal is not None else ''
        return [self.ssid, self.bssid, ch, sig, enc]


class WiFiAnalyzer:
    def __init__(self):
        self.networks = OrderedDict()

    def packet_handler(self, pkt):
        if not hasattr(pkt, 'type') or not hasattr(pkt, 'subtype'):
            return
        if pkt.type == 0 and pkt.subtype in (8, 5):
            bssid = getattr(pkt, 'addr3', None) or getattr(pkt, 'addr2', None)
            if not bssid:
                return
            ssid = extract_ssid(pkt)
            channel = extract_channel(pkt)
            signal = extract_signal(pkt)
            enc = detect_encryption(pkt)
            if bssid not in self.networks:
                self.networks[bssid] = NetworkRecord(ssid, bssid)
            self.networks[bssid].update(channel, signal, enc)

    def start(self, iface, timeout=None):
        if sniff is None:
            raise RuntimeError('scapy is not available; sniffing is disabled')
        sniff(iface=iface, prn=self.packet_handler, timeout=timeout)

    def summary_table(self):
        rows = []
        sorted_recs = sorted(self.networks.values(), key=lambda r: r.signal if r.signal is not None else -999, reverse=True)
        for rec in sorted_recs:
            rows.append(rec.to_row())
        headers = ['SSID', 'BSSID', 'Channels', 'Signal(dBm)', 'Encryption']
        return tabulate(rows, headers=headers, tablefmt='github')

    def export_csv(self, path):
        headers = ['SSID', 'BSSID', 'Channels', 'Signal(dBm)', 'Encryption']
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(headers)
            for rec in self.networks.values():
                w.writerow(rec.to_row())


def run_tests():
    import unittest

    class FakeElt:
        def __init__(self, ID, info=b'', payload=None):
            self.ID = ID
            self.info = info
            self.payload = payload

    class FakePacket:
        def __init__(self, elts=None, dBm_AntSignal=None, cap_str=''):
            self._elts = elts or []
            self.dBm_AntSignal = dBm_AntSignal
            self._cap = cap_str
            for i in range(len(self._elts) - 1):
                self._elts[i].payload = self._elts[i + 1]
            if self._elts:
                self._elts[-1].payload = None
            self.type = 0
            self.subtype = 8
            self.addr2 = '00:11:22:33:44:55'
            self.addr3 = '66:77:88:99:aa:bb'

        def getlayer(self, layer):
            if layer is Dot11Elt:
                return self._elts[0] if self._elts else None
            return None

        def sprintf(self, fmt):
            return self._cap

    class ParsingTests(unittest.TestCase):
        def test_extract_ssid_visible(self):
            pkt = FakePacket([FakeElt(0, b'MyNet')])
            self.assertEqual(extract_ssid(pkt), 'MyNet')

        def test_extract_ssid_hidden(self):
            pkt = FakePacket([FakeElt(0, b'')])
            self.assertEqual(extract_ssid(pkt), '<hidden>')

        def test_extract_channel_ds(self):
            pkt = FakePacket([FakeElt(3, b'\x06')])
            self.assertEqual(extract_channel(pkt), 6)

        def test_detect_encryption_open(self):
            pkt = FakePacket([FakeElt(0, b'MyNet')], cap_str='')
            self.assertEqual(detect_encryption(pkt), 'OPEN')

        def test_detect_encryption_rsn(self):
            pkt = FakePacket([FakeElt(48, b'')], cap_str='privacy')
            self.assertEqual(detect_encryption(pkt), 'WPA2/WPA3 (RSN)')

        def test_detect_encryption_wpa_vendor(self):
            pkt = FakePacket([FakeElt(221, b'\x00P\xf2\x01\x01')], cap_str='privacy')
            self.assertEqual(detect_encryption(pkt), 'WPA (WPA1)')

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ParsingTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="WiFi Security Analyzer")
    parser.add_argument("--iface", help="monitor-mode interface (e.g. wlan0mon)")
    parser.add_argument("--timeout", type=int, default=30, help="scan duration in seconds")
    parser.add_argument("--output", default="networks.csv", help="CSV file to save results")
    parser.add_argument("--run-tests", action="store_true", help="run built-in unit tests")
    args = parser.parse_args()

    if args.run_tests or not args.iface:
        print("Running unit tests...")
        run_tests()
        return

    analyzer = WiFiAnalyzer()
    analyzer.start(args.iface, timeout=args.timeout)

    print("\nScan complete. Summary:\n")
    print(analyzer.summary_table())
    analyzer.export_csv(args.output)
    print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
