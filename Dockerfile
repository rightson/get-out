FROM python:3.12-slim
WORKDIR /app
RUN mkdir /data && chown 10001:10001 /data
COPY server.py Upload-File.ps1 ./
COPY web ./web
ENV HOST=0.0.0.0 PORT=8080 DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
CMD ["python", "server.py"]
