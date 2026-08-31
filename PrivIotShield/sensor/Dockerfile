FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY priviot_sensor.py /app/priviot_sensor.py

ENV PRIVIOT_API_URL="http://priviot-server:5000/api/v2/telemetry/ingest"
ENV PRIVIOT_SENSOR_TOKEN=""
ENV BATCH_SIZE=50
ENV FLUSH_INTERVAL=5.0

USER nobody

CMD ["python", "-u", "priviot_sensor.py"]
