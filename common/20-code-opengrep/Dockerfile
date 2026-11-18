# The Opengrep image. Opengrep has no official image, so CI scan builds one
# from fixed inputs: Debian by digest, the Opengrep binary by its sha256.
#
# The binary unpacks itself into $HOME/.cache on its first run. The build
# runs it once, so that the scan needs no write there.

ARG OPENGREP=v1.33.1

# debian:13-slim
FROM debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS base

FROM base AS fetch-amd64
ARG OPENGREP
ADD --checksum=sha256:46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808 \
    https://github.com/opengrep/opengrep/releases/download/${OPENGREP}/opengrep_manylinux_x86 /opengrep

FROM base AS fetch-arm64
ARG OPENGREP
ADD --checksum=sha256:d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf \
    https://github.com/opengrep/opengrep/releases/download/${OPENGREP}/opengrep_manylinux_aarch64 /opengrep

ARG TARGETARCH
FROM fetch-${TARGETARCH} AS fetch

FROM base
COPY --from=fetch --chmod=555 /opengrep /opt/opengrep/bin/opengrep
# No log file, no settings file, no version check: the file system is
# read-only and there is no network. UTF-8, for the rules and the code.
ENV HOME=/opt/opengrep/home \
    LANG=C.UTF-8 \
    SEMGREP_LOG_FILE=/dev/null \
    SEMGREP_SETTINGS_FILE=/dev/null \
    SEMGREP_ENABLE_VERSION_CHECK=0
RUN /opt/opengrep/bin/opengrep --version && chmod -R a+rX /opt/opengrep
ENTRYPOINT ["/opt/opengrep/bin/opengrep"]
