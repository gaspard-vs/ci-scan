# The Grype image: Python, Grype and our program that writes the SARIF. Both
# bases are fixed by digest. Our program uses only the standard library of
# Python: nothing is installed.

# anchore/grype:v0.121.1
FROM anchore/grype@sha256:6b06708b036f74b2cd70e94b706b4586af96d1932e6ac46255940b2e39dd44a9 AS grype

# python:3.14-alpine (Python 3.14.10), the same base as the OSV image
FROM python@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
COPY --from=grype --chmod=555 /grype /usr/local/bin/grype
COPY --chmod=555 grype_sarif.py grype.yaml /opt/ci-scan/
# The file system is read-only: Python writes no cache.
ENV PYTHONDONTWRITEBYTECODE=1
RUN grype version
ENTRYPOINT ["python", "-I", "/opt/ci-scan/grype_sarif.py"]
