## PCAP to DataFrame: A Simple Packet Capture Analyzer
##### A self-contained automated Packet Capture (PCAP) analyzer designed to parse packets with the Python Scapy library and convert them to Pandas DataFrames for visualizations.

### Overview
##### This processor identifies high IP communication pairs, HTTP requests, DNS queries, TLS Server Name Indication (SNI) hostnames, and destination ports.  It maps out traffic patterns using Seaborn visualizations packages them into a ReportLab PDF document.

### Key Features
- Utilizes custom object-oriented packet shape classes to parse TCP, UDP, TLS, DNS, and HTTP traffic.
- Visual Analytics: Creates high-resolution Seaborn/Matplotlib chart (.png files) displaying top talkers, interesting queries, and anomaly distributions.
- Automated PDF Generation: Exports charts into a multi-page document using ReportLab.
- Containerization: Encapsulated in a Docker container (pcap-analyzer), ingesting PCAP data and extracting only a finalized PDF and chart products to the host machine.

### Struture
```text
├── Dockerfile                  # Container build instructions (Python 3.10 on Debian slim)
├── pcap-analyzer-container.sh  # Host automation wrapper script
├── requirements.txt            # Python dependencies (Scapy, Pandas, Seaborn, ReportLab, etc.)
└── scripts/
    ├── main.py                 # Core orchestration and packet sniffing pipeline
    ├── visualizer.py           # Statistical analysis and chart generation
    ├── report_generator.py     # PDF report layout and compilation
    ├── packet.py               # Base packet shape and telemetry mapping
    ├── http_packet.py          # HTTP request attributes
    ├── dns_packet.py           # DNS query extraction
    └── tls_ssl_packet.py       # TLS SNI and attributes
```    

### Requirements
- Docker Desktop/Engine installed and running on the host machine.
- A target .pcap file.

### Execution
```bash
chmod +x pcap-analyzer-container.sh
```

```bash
./pcap-analyzer-container.sh ./path/to/your/capture.pcap
```

### Products
##### Once complete, all charts (.png files) and finalized PDF will be available in host working directory. 



