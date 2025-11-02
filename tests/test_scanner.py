from analyzer.scanner import detect_encryption

class DummyPkt:
    def __init__(self, privacy=True, rsn=False):
        self.privacy = privacy
        self.rsn = rsn

    def haslayer(self, layer):
        if layer.__name__ == "Dot11EltRSN":
            return self.rsn
        if layer.__name__ == "Dot11Elt":
            return True
        return False

    def sprintf(self, fmt):
        return "privacy" if self.privacy else ""

def test_encryption_detection():
    pkt_open = DummyPkt(privacy=False)
    pkt_wep = DummyPkt(privacy=True, rsn=False)
    pkt_wpa2 = DummyPkt(privacy=True, rsn=True)

    assert detect_encryption(pkt_open) == "Open"
    assert "WEP" in detect_encryption(pkt_wep)
    assert "WPA2" in detect_encryption(pkt_wpa2)

if __name__ == "__main__":
    test_encryption_detection()
    print("[✓] All tests passed.")
