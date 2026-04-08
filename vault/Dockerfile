FROM python:3.13-slim

WORKDIR /seed

RUN pip install --no-cache-dir hvac==2.3.0

COPY seed.py .
COPY seed_data.json .

CMD ["python", "seed.py"]
