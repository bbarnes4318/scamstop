# ScamStop in a container. Use docker-compose.yml: it runs on the host network so
# ScamStop can reach rtpengine / Asterisk / FreeSWITCH and receive call audio.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# run packaging/build-installer.sh once first: it puts the speech model in packaging/cache/model
COPY packaging/cache/model /opt/scamstop/models/sherpa-onnx-streaming-zipformer-en-2023-06-21
COPY . /src
RUN pip install --no-cache-dir "/src[live]" && rm -rf /src

VOLUME ["/etc/scamstop", "/var/lib/scamstop", "/var/log/scamstop"]
ENTRYPOINT ["scamstop", "-c", "/etc/scamstop/config.yaml"]
CMD ["run"]
