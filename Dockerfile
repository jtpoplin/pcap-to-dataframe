# Build from a slim Debian/Linux image
FROM debian:stable-slim

# Update apt
RUN apt update && apt upgrade -y

# Install build tooling
RUN apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

# Download Python interpreter code and unpack it
RUN wget https://www.python.org/ftp/python/3.10.8/Python-3.10.8.tgz
RUN tar -xf Python-3.10.*.tgz
RUN rm Python-3.10.*.tgz

# Build the Python interpreter
RUN cd Python-3.10.8 && ./configure --enable-optimizations && make && make altinstall

# Set working directory
RUN mkdir -p /home/app
WORKDIR /home/app

# Install requirements
COPY requirements.txt .
RUN python3.10 -m pip install --no-cache-dir -r requirements.txt

# Copy Python project files
COPY scripts/ .

# Configure container to execute main.py on run
ENTRYPOINT ["sleep", "infinity"]

