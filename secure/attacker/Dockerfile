FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    mosquitto-clients tcpdump nmap netcat-openbsd curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==1.6.1 requests
WORKDIR /attacks
COPY attack_01_sniff.py .
COPY attack_02_cmd_inject.py .
CMD ["tail", "-f", "/dev/null"]
