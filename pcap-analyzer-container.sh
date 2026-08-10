#!/bin/bash

# Check if pcap file was provided
if [ $# -eq 0 ]
then
  echo "Please provide path to PCAP file for analysis."
  exit 1
fi

# Validate that the file actually exists on the host
if [ ! -f "$1" ]; then
  echo "Error: PCAP file '$1' not found on the host machine!"
  exit 1
fi

image_name="pcap-analyzer"
container_name="${image_name}_$(date +%s)"

# Build container if it doesn't exist
if [[ "$(docker images -q $image_name 2> /dev/null)" == "" ]]; then
  echo "[*] Building Docker image..."
  docker build -t $image_name .
fi

# Resolve absolute path safely
pcap_path=$(realpath "$1")
pcap_dir=$(dirname "$pcap_path")
pcap_filename=$(basename "$pcap_path")

# Run container in background
docker run -d --network none --name $container_name --entrypoint tail $image_name -f /dev/null

# Stream the PCAP cleanly into the container using absolute pathing
echo "[*] Streaming PCAP into container..."
tar -C "$pcap_dir" -cf - "$pcap_filename" | docker exec -i $container_name tar -xf - -C "/home/app"

# Process pcap file for analysis
echo "[*] Running analysis..."
docker exec "$container_name" python3.10 main.py "/home/app/$pcap_filename"

# Bundle post-analysis PNGs and PDF report inside the container
docker exec "$container_name" sh -c "cd /home/app && tar -czf /tmp/reports.tar.gz *.png *.pdf 2>/dev/null"

# Copy bundle to host machine and extract to current directory
docker cp "$container_name:/tmp/reports.tar.gz" .
if [ -f "reports.tar.gz" ]; then
  tar -xzf reports.tar.gz
  rm reports.tar.gz
  echo "[+] Success! Reports extracted to current directory."
else
  echo "[-] Warning: No report files found to extract."
fi

# After the Docker container has finished running, kill and remove it
docker kill $container_name > /dev/null 2>&1
docker rm $container_name > /dev/null 2>&1
docker rm $image_name > /dev/null 2>&1

echo "Project complete!"