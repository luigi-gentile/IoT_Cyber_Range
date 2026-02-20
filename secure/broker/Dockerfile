FROM eclipse-mosquitto:2.0
RUN mkdir -p /mosquitto/data /mosquitto/log /mosquitto/certs
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY acl /mosquitto/config/acl
EXPOSE 8883
