from scapy.layers.tls.handshake import TLSClientHello
from packet import PacketShape

# Create TLS class from PacketShape
class TLSShape(PacketShape):

    def __init__(self, packet):
        # Fetch packet shape
        super().__init__(packet)

        client_hello = packet[TLSClientHello]

        # Add TLS specific attributes
        self.version = getattr(client_hello, "version", None)
        self.ciphers = getattr(client_hello, "ciphers", [])

        self.ext = []
        if hasattr(client_hello, "ext"):
            self.ext = [ext.type for ext in client_hello.ext if hasattr(ext, "type")]

        self.sni = None
        if hasattr(client_hello, "ext"):
            for ext in client_hello.ext:
                if getattr(ext, "type", None) == 0:
                    if hasattr(ext, "servernames") and ext.servernames:
                        name_value = ext.servernames[0].servername
                        if isinstance(name_value, bytes):
                            self.sni = name_value.decode("utf-8", errors="ignore")
                        else:
                            self.sni = str(name_value)
                        break

    def create_dict(self):
        # Inherit PacketShape dictionary
        packet_dict = super().create_dict()

        # Add TLS-specific fields to dictionary
        packet_dict.update({
            "tls_version": self.version,
            "ciphers": self.ciphers,
            "extensions": self.ext,
            "sni": self.sni
        })
        return packet_dict