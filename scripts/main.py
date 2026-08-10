from scapy.all import sniff, load_layer, TCPSession
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from tls_ssl_packet import TLSShape
from dns_packet import DNSShape
from http_packet import HTTPShape
from packet import PacketShape
from visualizer import plot_dns_queries, plot_rare_dns_queries, plot_top_talkers, detect_and_plot_beacons, plot_unusal_ports, plot_sni, plot_uris, plot_rare_uris
from report_generator import generate_pdf_report
import pandas as pd
import sys
import time
import os

def read_pcap():
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_pcap>")
        sys.exit(1)
    return sys.argv[1]

def main():
    load_layer("tls")
    load_layer("http")
    pklist = []

    pcap_path = read_pcap()
    print(f"[*] Ingesting PCAP: {pcap_path}")
    start_time = time.time()

    output_dir = os.path.dirname(os.path.abspath(pcap_path))
    
    packet_count = [0]
    error_count = [0]

    def process_packet(packet):
        try:
            if packet.haslayer(TLSClientHello):
                packet_obj = TLSShape(packet)
            elif packet.haslayer(DNS):
                packet_obj = DNSShape(packet)
            elif packet.haslayer(HTTPRequest):
                packet_obj = HTTPShape(packet)
            else:
                packet_obj = PacketShape(packet)

            pklist.append(packet_obj.create_dict())
            packet_count[0] += 1

            if packet_count[0] % 100000 == 0:
                print(f"[*] Processed {packet_count[0]:,} packets...")

        except Exception:
            error_count[0] += 1

    sniff(
        offline=pcap_path,
        session=TCPSession,
        prn=process_packet,
        store=False
    )

    elapsed = time.time() - start_time
    print(f"[+] Finished! Parsed {packet_count[0]:,} packets in {elapsed:.2f} seconds.")
    if error_count[0] > 0:
        print(f"[-] Skipped {error_count[0]:,} malformed/unparsable packets.")

    df = pd.DataFrame(pklist)

    plot_top_talkers(df, output_dir=output_dir)
    detect_and_plot_beacons(df, output_dir=output_dir)
    plot_unusal_ports(df, output_dir=output_dir)
    plot_dns_queries(df, output_dir=output_dir)
    plot_rare_dns_queries(df, output_dir=output_dir)
    plot_sni(df, output_dir=output_dir)
    plot_uris(df, output_dir=output_dir)
    plot_rare_uris(df, output_dir=output_dir)

    generate_pdf_report(output_dir=output_dir)
 
    return df

if __name__ == "__main__":
    main()