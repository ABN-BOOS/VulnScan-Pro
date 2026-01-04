FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY vulnscan_pro.py .

RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

RUN mkdir -p /app/reports

ENV PYTHONUNBUFFERED=1

CMD ["python", "vulnscan_pro.py"]