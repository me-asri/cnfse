FROM python:3.14-slim

RUN pip install --no-cache --prefer-binary uvloop

WORKDIR /app
COPY cnfse.py cnfse.py

ENV CNFSE_LISTEN_HOST=0.0.0.0
ENV CNFSE_LISTEN_PORT=80

EXPOSE 80/tcp

ENTRYPOINT [ "python", "cnfse.py" ]
