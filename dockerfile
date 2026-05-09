FROM zaproxy/zap-stable:latest

WORKDIR /app

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip python3-dev build-essential supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/instance /app/static/reports /var/log

EXPOSE 5000
EXPOSE 8080

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
