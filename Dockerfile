FROM python:3.12.16-slim-trixie

WORKDIR /app
RUN mkdir -p /data
COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends curl socat \
    && rm -rf /var/lib/apt/lists/*
CMD ["python3", "c2.py"]
