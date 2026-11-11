# tallygate control plane: web UI, approvals (web/Matrix/Telegram), web console proxy, setup wizard
FROM docker.io/library/python:3.13-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && groupadd -g 10002 ctl && useradd -u 10002 -g ctl -M -d /nonexistent -s /usr/sbin/nologin ctl
COPY app /app/app
WORKDIR /app
USER 10002:10002
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://{os.environ.get(\"CONTROL_BIND_HOST\",\"127.0.0.1\")}:{os.environ.get(\"CONTROL_PORT\",\"8080\")}/healthz')" || exit 1
ENTRYPOINT ["python", "-m", "app.main"]
