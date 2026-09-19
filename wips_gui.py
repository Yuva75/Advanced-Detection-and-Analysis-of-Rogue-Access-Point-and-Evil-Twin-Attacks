#!/usr/bin/env python3
# ==========================================================
# Rogue AP / Evil Twin WIPS (Auto-Discovery + GUI + Active IPS)
# MSc Cyber Security Project — Integrated Build
# ==========================================================

import sys
import os
import csv
import time
import datetime
import threading

from scapy.all import (
    sniff,
    sendp,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    RadioTap,
    conf
)

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
    QTextEdit,
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QListWidget,
    QMessageBox
)

DEFAULT_INTERFACE = "wlan0"
LOG_FILE = "detections.csv"
COOLDOWN = 60

# Dynamic Whitelist populated by Auto-Discovery
WHITELIST = []

def setup_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp", "SSID", "BSSID", "Channel",
                "Frequency", "Encryption", "Signal_dBm",
                "Status", "Reasons"
            ])

# ── 802.11 PARSING ────────────────────────────────────────
def get_information_elements(packet):
    elements = []
    elt = packet.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        elements.append(elt)
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return elements

def get_ssid(packet):
    for elt in get_information_elements(packet):
        if elt.ID == 0:
            try:
                return elt.info.decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
    return ""

def frequency_to_channel(frequency):
    if not frequency: return 0
    if frequency == 2484: return 14
    if 2412 <= frequency <= 2472: return int((frequency - 2407) / 5)
    if 5000 <= frequency <= 5900: return int((frequency - 5000) / 5)
    if 5955 <= frequency <= 7115: return int((frequency - 5950) / 5)
    return 0

def get_frequency(packet):
    try:
        if packet.haslayer(RadioTap):
            freq = getattr(packet[RadioTap], "ChannelFrequency", None)
            if freq: return int(freq)
    except Exception: pass
    return 0

def get_channel(packet):
    freq = get_frequency(packet)
    if freq:
        ch = frequency_to_channel(freq)
        if ch: return ch
    try:
        for elt in get_information_elements(packet):
            if elt.ID == 3 and elt.info:
                return int(elt.info[0])
    except Exception: pass
    return 0

def get_signal(packet):
    try:
        if packet.haslayer(RadioTap):
            sig = getattr(packet[RadioTap], "dBm_AntSignal", None)
            if sig is not None: return int(sig)
    except Exception: pass
    return -999

def get_encryption(packet):
    elements = get_information_elements(packet)
    has_rsn = any(elt.ID == 48 for elt in elements)
    has_wpa = False
    for elt in elements:
        if elt.ID == 221:
            try:
                info = bytes(elt.info)
                if len(info) >= 4 and info[0:3] == b"\x00\x50\xf2" and info[3] == 1:
                    has_wpa = True
            except Exception: pass
    if has_rsn: return "WPA2"
    if has_wpa: return "WPA"
    try:
        if packet.haslayer(Dot11Beacon) and (packet[Dot11Beacon].cap & 0x0010):
            return "WEP"
    except Exception: pass
    return "OPEN"

def check_whitelist(ssid, bssid, channel, encryption, signal):
    reasons = []
    matched = False

    for trusted in WHITELIST:
        if trusted["ssid"].lower() != ssid.lower():
            continue
        matched = True

        if trusted["bssid"].lower() != bssid.lower():
            reasons.append("BSSID mismatch")
        if channel != 0 and channel != trusted["channel"]:
            reasons.append(f"Channel mismatch (exp {trusted['channel']}, obs {channel})")
        if encryption.upper() != trusted["encryption"].upper():
            reasons.append(f"Encryption mismatch (exp {trusted['encryption']}, obs {encryption})")
        if signal != -999 and signal > (trusted["expected_signal"] + 15):
            reasons.append(f"Abnormal signal (exp {trusted['expected_signal']} dBm, obs {signal} dBm)")

        if len(reasons) >= 2:
            return "ROGUE", reasons
        elif len(reasons) == 1:
            return "WARNING", reasons
        else:
            return "TRUSTED", ["All fingerprint checks passed"]

    if not matched:
        return "UNLISTED", ["SSID not present in whitelist"]
    return "UNLISTED", ["No matching whitelist entry"]
def write_log(data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp, data["ssid"], data["bssid"], data["channel"],
            data["frequency"], data["encryption"], data["signal"],
            data["status"], " | ".join(data["reasons"])
        ])

# ── THREAD 1: AUTO-DISCOVERY SCANNER (10 SECONDS) ─────────
class DiscoveryThread(QThread):
    ap_discovered = Signal(dict)
    finished_scan = Signal(dict)

    def __init__(self, interface, timeout=10):
        super().__init__()
        self.interface = interface
        self.timeout = timeout
        self.discovered = {}

    def process_packet(self, packet):
        if not packet.haslayer(Dot11Beacon):
            return
        bssid = packet[Dot11].addr3 or packet[Dot11].addr2
        if not bssid: return
        bssid = bssid.upper()
        ssid = get_ssid(packet) or "<Hidden>"

        if bssid not in self.discovered:
            ap_info = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": get_channel(packet),
                "encryption": get_encryption(packet),
                "expected_signal": get_signal(packet)
            }
            self.discovered[bssid] = ap_info
            self.ap_discovered.emit(ap_info)

    def run(self):
        args = {"iface": self.interface, "prn": self.process_packet, "store": False, "timeout": self.timeout}
        if conf.use_pcap: args["monitor"] = True
        sniff(**args)
        self.finished_scan.emit(self.discovered)

# ── THREAD 2: WIPS CAPTURE & DEFENSE ENGINE ───────────────
class CaptureThread(QThread):
    network_detected = Signal(object)
    statistics = Signal(int, int)
    error = Signal(str)
    finished_capture = Signal()

    def __init__(self, interface, active_deauth=False):
        super().__init__()
        self.interface = interface
        self.active_deauth = active_deauth
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.beacon_count = 0
        self.last_status = {}
        self.alert_cache = {}

    def stop(self):
        self.stop_event.set()

    def inject_deauth(self, rogue_bssid, count=10):
        pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=rogue_bssid, addr3=rogue_bssid) / Dot11Deauth(reason=7)
        try:
            sendp(pkt, iface=self.interface, count=count, inter=0.05, verbose=False)
        except Exception as exc:
            self.error.emit(f"Deauth Injection Failed: {exc}")

    def process_packet(self, packet):
        self.packet_count += 1
        if not packet.haslayer(Dot11Beacon):
            return
        self.beacon_count += 1

        try:
            ssid = get_ssid(packet) or "<Hidden SSID>"
            bssid = packet[Dot11].addr3 or packet[Dot11].addr2
            if not bssid: return
            bssid = bssid.upper()

            frequency = get_frequency(packet)
            channel = get_channel(packet)
            encryption = get_encryption(packet)
            signal = get_signal(packet)

            status, reasons = check_whitelist(ssid, bssid, channel, encryption, signal)

            data = {
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                "ssid": ssid, "bssid": bssid, "channel": channel,
                "frequency": frequency, "encryption": encryption,
                "signal": signal, "status": status, "reasons": reasons
            }

            previous = self.last_status.get(bssid)
            if previous != status:
                write_log(data)
                self.last_status[bssid] = status

            if status == "ROGUE" and self.active_deauth:
                now = time.time()
                if bssid not in self.alert_cache or (now - self.alert_cache[bssid]) > COOLDOWN:
                    self.inject_deauth(bssid)
                    self.alert_cache[bssid] = now
                    data["reasons"].append("[IPS] Transmitted 10 Active Deauth Frames")

            self.network_detected.emit(data)
            if self.packet_count % 20 == 0 or status == "ROGUE":
                self.statistics.emit(self.packet_count, self.beacon_count)

        except Exception as exc:
            self.error.emit(f"Packet Processing Error: {exc}")

    def run(self):
        try:
            while not self.stop_event.is_set():
                args = {"iface": self.interface, "prn": self.process_packet, "store": False, "timeout": 1}
                if conf.use_pcap: args["monitor"] = True
                sniff(**args)
        except Exception as exc:
            self.error.emit(f"Capture Error: {exc}")
        finally:
            self.finished_capture.emit()

# ── MAIN GUI WINDOW ───────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Zero-Trust Rogue AP & Evil Twin Detector (WIPS)")
        self.resize(1400, 850)
        self.worker = None
        self.discovery_worker = None
        self.network_rows = {}
        self.network_data = {}

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        title = QLabel("ROGUE AP & EVIL TWIN DETECTOR")
        title.setObjectName("title")
        subtitle = QLabel("Zero-Trust Wireless Intrusion Prevention System | Multi-Factor Fingerprinting")
        subtitle.setObjectName("subtitle")
        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        # Controls
        control_box = QGroupBox("Capture & Defense Controls")
        control_layout = QHBoxLayout(control_box)
        
        control_layout.addWidget(QLabel("Interface:"))
        self.interface_input = QLineEdit(DEFAULT_INTERFACE)
        self.interface_input.setMaximumWidth(120)
        control_layout.addWidget(self.interface_input)

        self.discover_button = QPushButton("🔍 Auto-Discover (10s)")
        self.active_deauth_check = QCheckBox("Enable Active Deauth Injection")
        self.active_deauth_check.setStyleSheet("color: #f87171; font-weight: bold;")
        
        self.start_button = QPushButton("▶ Start WIPS")
        self.stop_button = QPushButton("■ Stop WIPS")
        self.clear_button = QPushButton("Clear Table")
        self.stop_button.setEnabled(False)

        control_layout.addWidget(self.discover_button)
        control_layout.addWidget(self.active_deauth_check)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addStretch()

        self.capture_status = QLabel("● WIPS OFF")
        self.capture_status.setObjectName("stopped")
        control_layout.addWidget(self.capture_status)
        main_layout.addWidget(control_box)

        # Stats Cards
        stats_layout = QGridLayout()
        self.packet_label = self.create_stat(stats_layout, 0, 0, "PACKETS", "0")
        self.beacon_label = self.create_stat(stats_layout, 0, 1, "BEACONS", "0")
        self.network_label = self.create_stat(stats_layout, 0, 2, "NETWORKS", "0")
        self.rogue_label = self.create_stat(stats_layout, 0, 3, "ROGUE APs", "0")
        main_layout.addLayout(stats_layout)

        # Table
        table_box = QGroupBox("Live Airspace Fingerprints")
        table_layout = QVBoxLayout(table_box)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "Channel", "Frequency", "Encryption", "Signal", "Status", "Reasons"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Stretch)
        table_layout.addWidget(self.table)
        main_layout.addWidget(table_box, stretch=5)

        # Bottom Pane
        bottom_layout = QHBoxLayout()
        details_box = QGroupBox("Selected Network Fingerprint")
        details_layout = QGridLayout(details_box)
        self.detail_labels = {}
        for row, field in enumerate(["SSID", "BSSID", "Channel", "Frequency", "Encryption", "Signal", "Status", "Reasons"]):
            details_layout.addWidget(QLabel(field + ":"), row, 0)
            val = QLabel("-")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            details_layout.addWidget(val, row, 1)
            self.detail_labels[field] = val
        bottom_layout.addWidget(details_box, stretch=1)

        log_box = QGroupBox("WIPS Event Log")
        log_layout = QVBoxLayout(log_box)
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        log_layout.addWidget(self.event_log)
        bottom_layout.addWidget(log_box, stretch=2)
        main_layout.addLayout(bottom_layout)

        # Signals
        self.discover_button.clicked.connect(self.start_autodiscovery)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_table)
        self.table.itemSelectionChanged.connect(self.show_selected_network)
        self.statusBar().showMessage("Ready. Click 'Auto-Discover' to build baseline.")
        self.apply_style()

    def create_stat(self, layout, row, col, title, val):
        box = QGroupBox()
        bl = QVBoxLayout(box)
        tl = QLabel(title)
        tl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tl.setObjectName("statTitle")
        vl = QLabel(val)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.setObjectName("statValue")
        bl.addWidget(tl)
        bl.addWidget(vl)
        layout.addWidget(box, row, col)
        return vl

    # ── AUTO-DISCOVERY DIALOG LOGIC ───────────────────────
    def start_autodiscovery(self):
        iface = self.interface_input.text().strip()
        if not iface:
            QMessageBox.warning(self, "Error", "Enter wireless interface name.")
            return

        self.add_event(f"[*] Starting 10s Auto-Discovery scan on {iface}...")
        self.discover_button.setEnabled(False)
        self.statusBar().showMessage("Scanning airspace for 10 seconds...")

        self.discovery_worker = DiscoveryThread(iface, timeout=10)
        self.discovery_worker.finished_scan.connect(self.show_discovery_results)
        self.discovery_worker.start()

    def show_discovery_results(self, discovered_dict):
        self.discover_button.setEnabled(True)
        self.statusBar().showMessage("Auto-Discovery complete.")

        if not discovered_dict:
            QMessageBox.warning(self, "Discovery Failed", "No APs detected during 10-second scan.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Select Trusted Access Point")
        dialog.resize(500, 300)
        d_layout = QVBoxLayout(dialog)

        d_layout.addWidget(QLabel("Discovered Access Points (Select one to Whitelist):"))
        list_widget = QListWidget()
        ap_list = list(discovered_dict.values())
        for ap in ap_list:
            list_widget.addItem(f"{ap['ssid']} ({ap['bssid']}) | Ch:{ap['channel']} [{ap['encryption']}] {ap['expected_signal']}dBm")
        d_layout.addWidget(list_widget)

        btn = QPushButton("Add to Whitelist")
        d_layout.addWidget(btn)

        def add_selected():
            idx = list_widget.currentRow()
            if idx >= 0:
                selected_ap = ap_list[idx]
                WHITELIST.clear()
                WHITELIST.append(selected_ap)
                self.add_event(f"[✓] WHITELIST UPDATED: '{selected_ap['ssid']}' ({selected_ap['bssid']}) Ch:{selected_ap['channel']}")
                QMessageBox.information(dialog, "Success", f"Whitelisted: {selected_ap['ssid']}")
                dialog.accept()

        btn.clicked.connect(add_selected)
        dialog.exec()

    def start_capture(self):
        if not WHITELIST:
            QMessageBox.warning(self, "Whitelist Empty", "Please run Auto-Discover first or define a trusted AP!")
            return

        iface = self.interface_input.text().strip()
        if self.worker is not None: return

        active = self.active_deauth_check.isChecked()
        self.worker = CaptureThread(iface, active_deauth=active)
        self.worker.network_detected.connect(self.update_network)
        self.worker.statistics.connect(self.update_statistics)
        self.worker.error.connect(self.show_error)
        self.worker.finished_capture.connect(self.capture_finished)
        self.worker.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_input.setEnabled(False)
        self.discover_button.setEnabled(False)
        self.active_deauth_check.setEnabled(False)
        self.capture_status.setText("● WIPS ACTIVE")
        self.capture_status.setObjectName("running")
        self.capture_status.style().unpolish(self.capture_status)
        self.capture_status.style().polish(self.capture_status)
        self.add_event(f"[*] WIPS Engine Active on {iface} (Protecting {WHITELIST[0]['ssid']})")

    def stop_capture(self):
        if self.worker is None: return
        self.add_event("[*] Stopping WIPS engine...")
        self.worker.stop()
        self.worker.wait(3000)
        self.worker = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_input.setEnabled(True)
        self.discover_button.setEnabled(True)
        self.active_deauth_check.setEnabled(True)
        self.capture_status.setText("● WIPS OFF")
        self.capture_status.setObjectName("stopped")
        self.capture_status.style().unpolish(self.capture_status)
        self.capture_status.style().polish(self.capture_status)

    def capture_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_network(self, data):
        bssid = data["bssid"]
        if bssid in self.network_rows:
            row = self.network_rows[bssid]
        else:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.network_rows[bssid] = row

        self.network_data[bssid] = data
        vals = [
            data["ssid"], data["bssid"], str(data["channel"]),
            f'{data["frequency"]} MHz' if data["frequency"] else "-",
            data["encryption"], f'{data["signal"]} dBm' if data["signal"] != -999 else "-",
            data["status"], " | ".join(data["reasons"])
        ]

        for col, val in enumerate(vals):
            self.table.setItem(row, col, QTableWidgetItem(val))

        status = data["status"]
        bg = "#153d2a" if status == "TRUSTED" else "#493b12" if status == "WARNING" else "#4a1717" if status == "ROGUE" else "#252525"
        fg = "#4ade80" if status == "TRUSTED" else "#facc15" if status == "WARNING" else "#ff4d4d" if status == "ROGUE" else "#aaaaaa"

        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(QBrush(QColor(bg)))
                item.setForeground(QBrush(QColor(fg)))

        if status == "ROGUE":
            self.add_event(f"🚨 ROGUE AP | {data['ssid']} ({bssid}) | {' | '.join(data['reasons'])}")

        rogue_cnt = sum(1 for n in self.network_data.values() if n["status"] == "ROGUE")
        self.rogue_label.setText(str(rogue_cnt))
        self.network_label.setText(str(len(self.network_data)))

    def update_statistics(self, pkts, beacons):
        self.packet_label.setText(str(pkts))
        self.beacon_label.setText(str(beacons))

    def show_error(self, msg):
        self.add_event(f"[ERROR] {msg}")

    def add_event(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.event_log.append(f"[{ts}] {msg}")

    def show_selected_network(self):
        sel = self.table.selectedItems()
        if not sel: return
        bssid = self.table.item(sel[0].row(), 1).text()
        if bssid in self.network_data:
            d = self.network_data[bssid]
            for f in ["SSID", "BSSID", "Channel", "Frequency", "Encryption", "Signal", "Status"]:
                self.detail_labels[f].setText(str(d[f.lower()]))
            self.detail_labels["Reasons"].setText(" | ".join(d["reasons"]))

    def clear_table(self):
        self.table.setRowCount(0)
        self.network_rows.clear()
        self.network_data.clear()
        self.packet_label.setText("0")
        self.beacon_label.setText("0")
        self.network_label.setText("0")
        self.rogue_label.setText("0")
        self.event_log.clear()

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #101418; color: #e5e7eb; }
            QWidget { background-color: #101418; color: #e5e7eb; font-family: Arial; font-size: 13px; }
            QLabel#title { color: #60a5fa; font-size: 24px; font-weight: bold; }
            QLabel#subtitle { color: #9ca3af; font-size: 12px; }
            QGroupBox { border: 1px solid #30363d; border-radius: 8px; margin-top: 8px; padding: 12px; font-weight: bold; color: #93c5fd; }
            QLineEdit { background-color: #161b22; border: 1px solid #30363d; border-radius: 5px; padding: 6px; color: #e5e7eb; }
            QPushButton { background-color: #1d4ed8; border: none; border-radius: 5px; padding: 8px 14px; color: white; font-weight: bold; }
            QPushButton:hover { background-color: #2563eb; }
            QPushButton:disabled { background-color: #30363d; color: #777777; }
            QTableWidget { background-color: #0d1117; alternate-background-color: #161b22; gridline-color: #30363d; border: 1px solid #30363d; }
            QHeaderView::section { background-color: #1f2937; color: #93c5fd; padding: 6px; border: none; font-weight: bold; }
            QTextEdit { background-color: #0d1117; border: 1px solid #30363d; color: #d1d5db; font-family: monospace; }
            QLabel#statTitle { color: #9ca3af; font-size: 11px; font-weight: bold; }
            QLabel#statValue { color: #60a5fa; font-size: 24px; font-weight: bold; }
            QLabel#running { color: #4ade80; font-weight: bold; }
            QLabel#stopped { color: #f87171; font-weight: bold; }
        """)

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)
            self.worker = None
        event.accept()

def main():
    setup_log()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
