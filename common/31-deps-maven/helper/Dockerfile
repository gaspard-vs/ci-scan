# The helper of the Maven resolution: a proxy in Python, with only the
# standard library. The base is fixed by digest.

# python:3.14-alpine (Python 3.14.10)
FROM python@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
COPY --chmod=555 helper.py /opt/ci-scan/helper.py
# The file system is read-only: Python writes no cache.
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "-I", "-u", "/opt/ci-scan/helper.py"]
