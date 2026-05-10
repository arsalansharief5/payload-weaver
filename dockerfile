FROM zaproxy/zap-stable:latest

WORKDIR /app

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-dev \
    build-essential \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/instance /app/static/reports /var/log

EXPOSE 5000
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:5000/home || exit 1

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]