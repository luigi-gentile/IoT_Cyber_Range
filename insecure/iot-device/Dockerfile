FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==1.6.1
COPY device.py .
CMD ["python", "-u", "device.py"]
