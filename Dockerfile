FROM python:3.12-slim

WORKDIR /app

COPY wifi_proxy.py .
COPY index.html .

ENV WIFI_DASHBOARD_DIR=/app
ENV WIFI_POLICY_FILE=/data/wifi-policy.json
ENV WIFI_DASHBOARD_PORT=8080

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

CMD ["python", "-u", "wifi_proxy.py"]
