# The OSV image: Python, OSV-Scanner and our program that writes the SARIF.
# Both bases are fixed by digest. Our program uses only the standard library
# of Python: nothing is installed.

# ghcr.io/google/osv-scanner:v2.7.1
FROM ghcr.io/google/osv-scanner@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde AS osv

# python:3.14-alpine (Python 3.14.10)
FROM python@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
COPY --from=osv --chmod=555 /osv-scanner /usr/local/bin/osv-scanner
COPY --chmod=555 osv_sarif.py osv-scanner.toml /opt/ci-scan/
# The file system is read-only: Python writes no cache.
ENV PYTHONDONTWRITEBYTECODE=1
RUN osv-scanner --version
ENTRYPOINT ["python", "-I", "/opt/ci-scan/osv_sarif.py"]
