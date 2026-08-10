from scapy.layers.dns import *
from packet import PacketShape

# Create HTTP class from PacketShape
class DNSShape(PacketShape):

    def __init__(self, packet):
        # Fetch packet shape
        super().__init__(packet)

        # Add DNS specific attributes
        self.qname = None
        self.qtype = None
        self.rname = None
        self.rdata = None

        if packet.haslayer(DNSQR):
            qname_bytes = packet[DNSQR].qname
            if isinstance(qname_bytes, bytes):
                self.qname = qname_bytes.decode("utf-8", errors="ignore").rstrip('.')
            else:
                self.qname = str(qname_bytes).rstrip('.')
            self.qtype = packet[DNSQR].qtype

        if packet.haslayer(DNSRR):
                response = packet[DNSRR]

                rrname_bytes = getattr(response, "rrname", None)
                if isinstance(rrname_bytes, bytes):
                    self.rname = rrname_bytes.decode("utf-8", errors="ignore").rstrip('.')
                elif rrname_bytes:
                     self.rname = str(rrname_bytes).rstrip('.')

                self.rdata = getattr(response, "rdata", None)

    def create_dict(self):
        # Inherit PacketShape dictionary
        packet_dict = super().create_dict()

        # Add DNS-specific fields to dictionary
        packet_dict.update({
            "qname": self.qname,
            "qtype": self.qtype,
            "rname": self.rname,
            "rdata": self.rdata
        })
        return packet_dict