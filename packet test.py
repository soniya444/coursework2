import unittest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether
from collections import defaultdict
from packet import PacketFilter, TrafficStatistics, PacketProcessor  # Assuming the main script is named packet_sniffer.py

class TestPacketSniffer(unittest.TestCase):
    def setUp(self):
        self.packet_filter = PacketFilter(protocols=["TCP", "UDP", "DNS"], ports=[80, 443, 53], ip_address="192.168.1.1")
        self.stats = TrafficStatistics()
  
    def test_tcp_packet_filter(self):
        packet = IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        self.assertTrue(self.packet_filter.filter_packet(packet))

    def test_udp_packet_filter(self):
        packet = IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=12345, dport=53)
        self.assertTrue(self.packet_filter.filter_packet(packet))

    def test_dns_packet_filter(self):
        packet = IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=53, dport=12345) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        self.assertTrue(self.packet_filter.filter_packet(packet))

    def test_non_matching_packet_filter(self):
        packet = IP(src="192.168.2.2", dst="192.168.2.3") / TCP(sport=12345, dport=22)
        self.assertFalse(self.packet_filter.filter_packet(packet))

    def test_traffic_statistics(self):
        packet1 = IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        packet2 = IP(src="192.168.1.1", dst="192.168.1.3") / UDP(sport=12345, dport=53)
        self.stats.update(packet1)
        self.stats.update(packet2)
        self.assertEqual(self.stats.packet_count, 2)
        self.assertEqual(self.stats.protocol_count["TCP"], 1)
        self.assertEqual(self.stats.protocol_count["UDP"], 1)
        self.assertEqual(self.stats.host_traffic["192.168.1.1"], 2)

    def test_http_packet_processing(self):
        packet = IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=12345, dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        PacketProcessor.decode_http(packet)  # Should print HTTP data

    def test_dns_packet_processing(self):
        packet = IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=53, dport=12345) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        PacketProcessor.decode_dns(packet)  # Should print DNS query

if __name__ == "__main__":
    unittest.main()
