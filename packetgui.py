import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import threading
from collections import defaultdict, deque
import time

class PacketFilter:
    def __init__(self, protocols=None, ports=None, ip_address=None):
        self.protocols = protocols or []
        self.ports = ports or []
        self.ip_address = ip_address

    def filter_packet(self, packet):
        if TCP in packet and "TCP" in self.protocols and (packet[TCP].sport in self.ports or packet[TCP].dport in self.ports):
            return True
        if UDP in packet and ("UDP" in self.protocols or ("DNS" in self.protocols and (packet[UDP].sport == 53 or packet[UDP].dport == 53))):
            return True
        if IP in packet and self.ip_address and (packet[IP].src == self.ip_address or packet[IP].dst == self.ip_address):
            return True
        return False

class PacketProcessor:
    @staticmethod
    def decode_http(packet):
        if Raw in packet:
            payload = packet[Raw].load.decode("utf-8", errors="replace")
            if payload.startswith(("GET", "POST", "HTTP")):
                return f"[HTTP Data]: {payload}"
        return None

    @staticmethod
    def decode_dns(packet):
        if DNS in packet:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:
                return f"[DNS Query]: {dns_layer.qd.qname.decode('utf-8')}"
            elif dns_layer.qr == 1:
                return f"[DNS Response]: {dns_layer.an.rdata}"
        return None

    @staticmethod
    def process_packet(packet):
        output = f"\n[+] Packet Captured ({time.strftime('%H:%M:%S')}):\n"
        if IP in packet:
            output += f"  {packet[IP].src} -> {packet[IP].dst}, Protocol: {packet[IP].proto}\n"
            if TCP in packet:
                output += f"    TCP: {packet[TCP].sport} -> {packet[TCP].dport}\n"
                http_data = PacketProcessor.decode_http(packet)
                if http_data:
                    output += f"    {http_data}\n"
            elif UDP in packet:
                output += f"    UDP: {packet[UDP].sport} -> {packet[UDP].dport}\n"
                dns_data = PacketProcessor.decode_dns(packet)
                if dns_data:
                    output += f"    {dns_data}\n"
        return output

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20, bg="black", fg="green", font=("Courier", 10))
        self.text_area.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.sniffing = False
        self.packet_filter = PacketFilter(protocols=["TCP", "UDP", "DNS"], ports=[80, 443, 53])
        self.sniff_thread = None

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, "[*] Sniffing Started...\n")
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "[*] Sniffing Stopped.\n")

    def sniff_packets(self):
        sniff(prn=self.process_packet, filter="ip", store=False, lfilter=self.packet_filter.filter_packet)

    def process_packet(self, packet):
        if self.sniffing:
            packet_info = PacketProcessor.process_packet(packet)
            self.text_area.insert(tk.END, packet_info)
            self.text_area.see(tk.END)

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
