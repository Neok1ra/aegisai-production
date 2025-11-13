FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap0.8
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY aegis_agent.py .
COPY models/anomaly_v3.pkl /models/
CMD ["python", "aegis_agent.py"]