FROM python:3.12-slim-trixie

WORKDIR /app 
RUN mkdir -p /data
COPY c2.py .
COPY mock_skill.sh .
COPY fake_secrets.txt .

RUN apt-get update && apt-get install -y --no-install-recommends curl socat
CMD ["python3", "c2.py"]
