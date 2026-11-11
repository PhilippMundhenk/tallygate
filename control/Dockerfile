# tallygate control plane: web UI, approvals (web/Matrix/Telegram), web console proxy, setup wizard
FROM docker.io/library/python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && groupadd -g 10002 ctl && useradd -u 10002 -g ctl -M -d /nonexistent -s /usr/sbin/nologin ctl \
 # /data: session secret + UI password hash; /run/tallygate/ttyd: console credential shared with the agent
 && mkdir -p /data /run/tallygate/ttyd && chown ctl:ctl /data /run/tallygate/ttyd && chmod 700 /data
COPY app /app/app
WORKDIR /app
USER 10002:10002
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --start-interval=2s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://{os.environ.get(\"CONTROL_BIND_HOST\",\"127.0.0.1\")}:{os.environ.get(\"CONTROL_PORT\",\"8080\")}/healthz')" || exit 1
ENTRYPOINT ["python", "-m", "app.main"]
