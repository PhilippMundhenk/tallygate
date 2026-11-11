# egress-gw: policy-enforcing egress gateway (HTTP/HTTPS proxy, SOCKS5, TCP service ports, NXDOMAIN DNS)
# Build context: the repository root (the default config lives in config/).
FROM docker.io/library/python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data CA_EXPORT_DIR=/ca
COPY gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && groupadd -g 10001 gw && useradd -u 10001 -g gw -d /data -M -s /usr/sbin/nologin gw \
 && mkdir -p /data /ca /run/tallygate/gw && chown gw:gw /data /ca /run/tallygate/gw

COPY gateway/egressgw /app/egressgw
COPY gateway/presets /app/presets
COPY gateway/run.py /app/run.py
# Default static configuration; mount your own file over it to define grants, services or injection.
COPY config/gateway.yaml /etc/egressgw/config.yaml
ENV PRESET_DIR=/app/presets GW_CONFIG=/etc/egressgw/config.yaml

USER 10001:10001
WORKDIR /app
EXPOSE 3128 1080 53/udp 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --start-interval=2s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://{os.environ.get(\"GW_API_HOST\",\"127.0.0.1\")}:{os.environ.get(\"GW_API_PORT\",\"8081\")}/health')" || exit 1
ENTRYPOINT ["python", "/app/run.py"]
