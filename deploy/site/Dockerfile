# scamstop.pvnvoice.com: download page, /install, installer downloads and the shared feed.
# Build from the repo root:  docker compose -f deploy/site/compose.yml up -d --build
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates bzip2 \
    && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir build uv
WORKDIR /src
COPY . .
# builds dist/scamstop-<version>-py3-none-any.whl and dist/scamstop-installer-<version>-linux-x86_64.run
RUN ./packaging/build-installer.sh

FROM python:3.12-slim
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY --from=build /src/dist/scamstop-installer-*-linux-x86_64.run /srv/downloads/
RUN cd /srv/downloads && ln -s scamstop-installer-*-linux-x86_64.run scamstop-installer-linux-x86_64.run
VOLUME ["/data"]
EXPOSE 8095
CMD ["scamstop", "feed-server", "--db", "/data/feed.db", "--host", "0.0.0.0", "--port", "8095", "--trust-proxy", \
     "--downloads", "/srv/downloads", "--public-url", "https://scamstop.pvnvoice.com"]
