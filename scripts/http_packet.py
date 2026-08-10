from scapy.layers.http import HTTP, HTTPRequest
from packet import PacketShape

# Create HTTP class from PacketShape
class HTTPShape(PacketShape):

    def __init__(self, packet):
        # Fetch packet shape
        super().__init__(packet)

        # Add HTTP specific attributes
        self.request_method = None
        self.user_agent = None
        self.path = None
        self.host = None

        if packet.haslayer(HTTP):
            request = packet[HTTPRequest]
            method_value = getattr(request, "Method", None)
            path_value = getattr(request, "Path", None)
            host_value = getattr(request, "Host", None)
            ua_value = getattr(request, "User_Agent", None)

            if isinstance(method_value, bytes):
                self.request_method = method_value.decode("utf-8", errors="ignore")
            else:
                self.request_method = method_value
            if isinstance(path_value, bytes):
                self.path = path_value.decode("utf-8", errors="ignore")
            else:
                self.path = path_value
            if isinstance(host_value, bytes):
                self.host = host_value.decode("utf-8", errors="ignore")
            else:
                self.host = host_value
            if isinstance(ua_value, bytes):
                self.user_agent = ua_value.decode("utf-8", errors="ignore")
            else:
                self.user_agent = ua_value


            
    def create_dict(self):
        # Inherit PacketShape dictionary
        packet_dict = super().create_dict()

        # Add HTTP-specific fields to dictionary
        packet_dict.update({
            "method": self.request_method,
            "user-agent": self.user_agent,
            "path": self.path,
            "host": self.host
        })
        return packet_dict
