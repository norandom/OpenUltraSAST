# syntax=docker/dockerfile:1
# Supply digests from plane/task-base.digest; deliberately no floating fallback.
ARG TASK_BASE_TAG=base-unpublished
ARG TASK_BASE_DIGEST
FROM ghcr.io/norandom/ousast-task-base:${TASK_BASE_TAG}@${TASK_BASE_DIGEST} AS joern-build
ENV PATH="/opt/joern-cli:${PATH}"
ARG JOERN_VERSION=v4.0.625
ARG ARCHIVE=joern-cli-linux-x86_64.zip

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    cd /tmp; \
    curl -fsSL -O "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/${ARCHIVE}"; \
    curl -fsSL -O "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/${ARCHIVE}.sha512"; \
    sed 's@  target/@  @' "${ARCHIVE}.sha512" > checksum.sha512; \
    sha512sum -c checksum.sha512; \
    unzip -q "${ARCHIVE}" -d /opt; \
    rm -f "${ARCHIVE}" "${ARCHIVE}.sha512" checksum.sha512; \
    /opt/joern-cli/joern-parse --help > /dev/null

RUN if [ ! -e /opt/joern-cli/jssrc2cpg ] && [ -x /opt/joern-cli/jssrc2cpg.sh ]; then \
      ln -s jssrc2cpg.sh /opt/joern-cli/jssrc2cpg; \
    fi
COPY ops/frontend-retention/install.py /tmp/frontend-retention-install.py
RUN python3 /tmp/frontend-retention-install.py /opt/joern-cli \
 && rm /tmp/frontend-retention-install.py

FROM ghcr.io/norandom/ousast-task-base:${TASK_BASE_TAG}@${TASK_BASE_DIGEST} AS engine
ENV PATH="/opt/joern-cli:${PATH}"
COPY --from=joern-build /opt/joern-cli /opt/joern-cli
# Create runtime identity before the application layers.
RUN if getent passwd 1000 > /dev/null; then \
      usermod --login ousast --home /home/ousast --move-home "$(getent passwd 1000 | cut -d: -f1)"; \
    else useradd --create-home --uid 1000 ousast; fi
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip \
    /venv/bin/pip install --no-deps --no-cache-dir .
COPY --chown=1000 benchmarks ./benchmarks
RUN chown -R ousast /app
USER ousast
ENTRYPOINT ["python", "-m", "openultrasast.cli"]
CMD ["--help"]
