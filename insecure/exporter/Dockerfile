FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 paho-mqtt==1.6.1
COPY exporter.py .
EXPOSE 8000
CMD ["python", "-u", "exporter.py"]
