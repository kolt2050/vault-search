FROM python:3.13-slim

WORKDIR /seed

RUN pip install --no-cache-dir hvac==2.3.0

COPY seed.py .
COPY seed_data.json .
COPY seed_acl.py .
COPY seed_acl_data.json .
COPY seed_oidc.py .
COPY load_tester.py .
COPY constant_load.py .

CMD ["python", "seed.py"]
