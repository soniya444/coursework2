# coursework2
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, DNS, DNSQR
from collections import defaultdict, deque
import argparse
import time

class PacketFilter:
    def __init__(self, protocols=None, ports=None, ip_address=None):
        self.protocols = protocols or []
        self.ports = ports or []
        self.ip_address = ip_address

    def filter_packet(self, packet):
        if TCP in packet and "TCP" in self.protocols and (packet[TCP].sport in self.ports or packet[TCP].dport in self.ports):
            return True
        if UDP in packet and ("UDP" in self.protocols or ("DNS" in self.protocols and packet[UDP].sport == 53 or packet[UDP].dport == 53)):
            return True
        if IP in packet and self.ip_address and (packet[IP].src == self.ip_address or packet[IP].dst == self.ip_address):
            return True
        return False

class TrafficStatistics:
    def __init__(self):
        self.packet_count = 0
        self.protocol_count = defaultdict(int)
        self.host_traffic = defaultdict(int)

    def update(self, packet):
        self.packet_count += 1
        if IP in packet:
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            self.protocol_count[proto] += 1
            self.host_traffic[packet[IP].src] += 1
            self.host_traffic[packet[IP].dst] += 1

    def display(self):
        print(f"\n=== Traffic Statistics ===\nTotal Packets: {self.packet_count}")
        for proto, count in self.protocol_count.items():
            print(f"  {proto}: {count} packets")
        for host, count in sorted(self.host_traffic.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {host}: {count} packets")

class PacketProcessor:
    @staticmethod
    def decode_http(packet):
        if Raw in packet:
            payload = packet[Raw].load.decode("utf-8", errors="replace")
            if payload.startswith(("GET", "POST", "HTTP")):
                print(f"\n[HTTP Data]:\n{payload}")

    @staticmethod
    def decode_dns(packet):
        if DNS in packet:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:
                print(f"[DNS Query]: {dns_layer[DNSQR].qname.decode('utf-8')}")
            elif dns_layer.qr == 1:
                print(f"[DNS Response]: {dns_layer.an.rdata}")

    @staticmethod
    def process_packet(packet):
        print(f"\n[+] Packet Captured:\n  Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        if Ether in packet:
            print(f"  Ethernet: {packet[Ether].src} -> {packet[Ether].dst}")
        if IP in packet:
            print(f"  IPv4: {packet[IP].src} -> {packet[IP].dst}, Protocol: {packet[IP].proto}")
            if TCP in packet:
                print(f"    TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
                PacketProcessor.decode_http(packet)
            elif UDP in packet:
                print(f"    UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
                PacketProcessor.decode_dns(packet)

class PacketSniffer:
    def __init__(self, filter_config):
        self.filter = PacketFilter(**filter_config)
        self.packet_queue = deque()
        self.stats = TrafficStatistics()

    def sniff_packets(self):
        print("Starting sniffer. Press Ctrl+C to stop.")
        try:
            sniff(filter="ip", prn=self._process_packet, store=False, lfilter=self.filter.filter_packet)
        except KeyboardInterrupt:
            print("\nSniffer stopped.")
            self.stats.display()

    def _process_packet(self, packet):
        self.packet_queue.append(packet)
        self.stats.update(packet)
        self._process_from_queue()

    def _process_from_queue(self):
        while self.packet_queue:
            PacketProcessor.process_packet(self.packet_queue.popleft())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--protocols", nargs="+", default=["TCP", "DNS"], help="Filter protocols")
    parser.add_argument("--ports", nargs="+", type=int, default=[80, 443, 53], help="Filter ports")
    parser.add_argument("--ip", help="Filter IP")
    args = parser.parse_args()

    sniffer = PacketSniffer({"protocols": args.protocols, "ports": args.ports, "ip_address": args.ip})
    sniffer.sniff_packets()
