FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DIGISCOPE_HOST=0.0.0.0 \
    DIGISCOPE_PORT=8000

RUN groupadd --system digiscope && useradd --system --gid digiscope --create-home digiscope
WORKDIR /app
COPY requirements.txt pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir -r requirements.txt
COPY digiscope ./digiscope
COPY run.py ./run.py
RUN chown -R digiscope:digiscope /app
USER digiscope
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"
CMD ["python", "run.py"]
