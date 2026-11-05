FROM python:3.12-slim-bookworm

ARG CLI_REVISION
ARG HELPER_SHA256
LABEL org.opencontainers.image.description="Disposable PocketShell phone acceptance host; no published ports" \
      org.opencontainers.image.revision="${CLI_REVISION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server bash procps tini ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && useradd --create-home --uid 10000 --shell /bin/bash --password '*' orin \
    && install -d -m 0755 /run/sshd \
    && install -d -o orin -g orin -m 0700 /home/orin/.config /home/orin/.local/state

# Supply a clean `git archive` of the revision being tested and a separately
# verified linux-amd64 helper wheel. Credentials and host keys are runtime-only.
COPY cli/ /opt/pocketshell-source/
COPY helper/*.whl /opt/helper/
RUN python -m pip install --no-cache-dir /opt/pocketshell-source \
    && python -m pip install --no-index --no-deps /opt/helper/*.whl \
    && python -c 'import hashlib,pathlib,re,sys,sysconfig; expected=sys.argv[1]; assert re.fullmatch("[0-9a-f]{64}",expected), "trusted helper digest required"; helper=pathlib.Path(sysconfig.get_paths()["purelib"])/"pocketshell_gateway_link/bin/pocketshell-link"; assert hashlib.sha256(helper.read_bytes()).hexdigest()==expected, "helper digest mismatch"; helper.chmod(0o755)' "${HELPER_SHA256}"
COPY tests/docker/phone-host/entrypoint.sh /usr/local/bin/phone-host
RUN chmod 0755 /usr/local/bin/phone-host

USER orin
WORKDIR /home/orin
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/phone-host"]
