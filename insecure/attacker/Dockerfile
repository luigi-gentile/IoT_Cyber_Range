FROM python:3.11-slim

# Install network and MQTT tools for attack demonstrations
RUN apt-get update && apt-get install -y --no-install-recommends \
    mosquitto-clients \
    tcpdump \
    nmap \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir paho-mqtt==1.6.1 requests

WORKDIR /attacks
COPY . .

# Container stays alive for interactive docker exec sessions
CMD ["tail", "-f", "/dev/null"]
