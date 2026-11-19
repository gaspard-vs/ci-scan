# The Syft image: Python, Syft and our program that writes the SARIF. Both
# bases are fixed by digest. Our program uses only the standard library of
# Python: nothing is installed.

# anchore/syft:v1.57.2
FROM anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a AS syft

# python:3.14-alpine (Python 3.14.10), the same base as the OSV image
FROM python@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
COPY --from=syft --chmod=555 /syft /usr/local/bin/syft
COPY --chmod=555 sbom_sarif.py syft.yaml /opt/ci-scan/
# The file system is read-only: Python writes no cache.
ENV PYTHONDONTWRITEBYTECODE=1
RUN syft version
ENTRYPOINT ["python", "-I", "/opt/ci-scan/sbom_sarif.py"]
