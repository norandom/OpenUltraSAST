# OpenUltraSAST with its CPG engine, in one image.
#
# The model layer's arbiter is Joern, and `openultrasast.cpg.backend` reaches it by subprocess. Shipping both
# in one image is what makes that simple: Joern is on PATH inside, so there is no container-to-container call,
# no docker socket, no path translation between host and container, and no second code path in the backend to
# get wrong. The alternative -- tool and engine as sibling services -- needs the tool to exec into the other
# container, which means mounting the docker socket, and that is a large amount of privilege for a linter.
#
# The image is big (a JRE plus ~2 GB of Joern). That is the honest cost of bundling an engine, and it buys a
# contributor a working tool from `docker compose run` with nothing installed on their machine.

FROM eclipse-temurin:21-jre-noble

ARG JOERN_VERSION=v4.0.625
ARG ARCHIVE=joern-cli-linux-x86_64.zip

# php-cli is required by php2cpg, which drives PHP-Parser and shells out to a real interpreter. Without it a
# PHP tree fails with an opaque "Process exited with code 1" -- measured on this project, not assumed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip unzip curl ca-certificates git php-cli \
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
ENV PATH="/opt/joern-cli:${PATH}"

# This release ships the JS launcher with a .sh suffix; the backend's direct fallback uses
# the same extensionless command convention as the other frontends.
RUN if [ ! -e /opt/joern-cli/jssrc2cpg ] && [ -x /opt/joern-cli/jssrc2cpg.sh ]; then \
      ln -s jssrc2cpg.sh /opt/joern-cli/jssrc2cpg; \
    fi

COPY ops/frontend-retention/install.py /tmp/frontend-retention-install.py
RUN python3 /tmp/frontend-retention-install.py /opt/joern-cli \
 && rm /tmp/frontend-retention-install.py

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY benchmarks ./benchmarks

# The core install is zero-dependency by design; `semantic` adds the tree-sitter grammars the candidate
# enumerator uses. The LLM endpoint stays optional and is configured by environment, never baked in.
RUN python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir -e ".[semantic]"
ENV PATH="/venv/bin:${PATH}"

# Analysis never needs root.
# Noble may already provide the ubuntu account at UID 1000. Reuse that identity rather than
# failing installation or creating a second account with the same UID.
RUN if getent passwd 1000 > /dev/null; then \
      usermod --login ousast --home /home/ousast --move-home "$(getent passwd 1000 | cut -d: -f1)"; \
    else \
      useradd --create-home --uid 1000 ousast; \
    fi \
 && chown -R ousast /app
USER ousast

ENTRYPOINT ["python", "-m", "openultrasast.cli"]
CMD ["--help"]
