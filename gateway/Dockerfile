# egress-gw: policy-enforcing egress gateway (HTTP/HTTPS proxy, SOCKS5, TCP service ports, NXDOMAIN DNS)
FROM docker.io/library/python:3.15-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data CA_EXPORT_DIR=/ca
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && groupadd -g 10001 gw && useradd -u 10001 -g gw -d /data -M -s /usr/sbin/nologin gw \
 && mkdir -p /data /ca && chown gw:gw /data /ca

COPY egressgw /app/egressgw
COPY presets /app/presets
COPY run.py /app/run.py
ENV PRESET_DIR=/app/presets

USER 10001:10001
WORKDIR /app
EXPOSE 3128 1080 53/udp 8081
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://{os.environ.get(\"GW_API_HOST\",\"127.0.0.1\")}:{os.environ.get(\"GW_API_PORT\",\"8081\")}/health')" || exit 1
ENTRYPOINT ["python", "/app/run.py"]
