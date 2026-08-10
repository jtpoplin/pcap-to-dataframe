from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# Base class for the packet object
class PacketShape():
    def __init__(self, packet):
        self.time = float(packet.time) if hasattr(packet, "time") else None
        self.src_ip = None
        self.sport = None
        self.dst_ip = None
        self.dport = None
        self.len = len(packet)
        self.proto = None

        if packet.haslayer(IP):
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            self.src_ip = packet[IPv6].src
            self.dst_ip = packet[IPv6].dst

        if packet.haslayer(TCP):
            self.sport = packet[TCP].sport
            self.dport = packet[TCP].dport
            self.proto = "TCP"
        elif packet.haslayer(UDP):
            self.sport = packet[UDP].sport
            self.dport = packet[UDP].dport
            self.proto = "UDP"
        elif packet.haslayer(ICMP):
            self.proto = "ICMP"

# Creates the dictionary
    def create_dict(self):
        packet_dict = {
            "time": self.time,
            "src_ip": self.src_ip,
            "sport": self.sport,
            "dst_ip": self.dst_ip,
            "dport": self.dport,
            "len": self.len,
            "proto": self.proto
        }
        return packet_dict