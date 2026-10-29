# TrustProbe sandbox image (Node servers).
# The build step is the ONLY step with network access: it installs the server's
# dependencies. The image is then run with --network none.
FROM node:20-slim

ENV NPM_CONFIG_UPDATE_NOTIFIER=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --create-home --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox \
    && mkdir /audit && chown 10001:10001 /audit

WORKDIR /app
COPY app/ /app/

# @@INSTALL@@

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

USER 10001:10001
