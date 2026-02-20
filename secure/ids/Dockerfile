FROM jasonish/suricata:latest
COPY rules/ /etc/suricata/rules/custom/
RUN mkdir -p /var/log/suricata
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0", "--init-errors-fatal"]
