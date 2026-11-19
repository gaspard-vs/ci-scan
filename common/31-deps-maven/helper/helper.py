"""The only way out of the Maven resolver.

The resolver is on a network with no route out. It reaches only this
proxy, as its Maven registry. The proxy:

  - forwards a GET of a POM file or of a maven-metadata.xml file to the
    upstream registry (Maven Central), with no redirect;
  - answers an empty POM for an internal package (--internal), and sends
    nothing out for it;
  - refuses all the other requests;
  - prints one JSON line for each request: the runner reads them.

It sees no code: only the names of the files that the resolver asks for.
"""

import argparse
import http.server
import json
import re
import sys
import urllib.error
import urllib.request

PORT = 8080
MAX_BYTES = 10 * 1024 * 1024
TIMEOUT = 30

SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9_.+-]*"
POM = re.compile(rf"^/maven2/((?:{SEGMENT}/)+)({SEGMENT})/({SEGMENT})/\2-\3\.pom$")
METADATA = re.compile(rf"^/maven2/((?:{SEGMENT}/)+)({SEGMENT})/maven-metadata\.xml$")

EMPTY_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>{group}</groupId>
  <artifactId>{artifact}</artifactId>
  <version>{version}</version>
</project>
"""


def is_internal(group, internal):
    return any(group == prefix.rstrip(".") or group.startswith(prefix) for prefix in internal)


def decide(method, path, internal):
    """What to do with a request: (action, value).

    forward   value: the path to ask upstream
    internal  value: the empty POM, or None for a metadata file
    refused   value: None
    """
    if method != "GET":
        return "refused", None
    pom = POM.match(path)
    metadata = METADATA.match(path)
    match = pom or metadata
    if not match:
        return "refused", None
    # A segment cannot start with a dot: no "." or "..".
    group = match.group(1).rstrip("/").replace("/", ".")
    if is_internal(group, internal):
        if pom:
            return "internal", EMPTY_POM.format(group=group, artifact=pom.group(2), version=pom.group(3))
        return "internal", None
    return "forward", path[len("/maven2"):]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(upstream, path):
    """Gives (status, body). A redirect is not followed."""
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(upstream + path, timeout=TIMEOUT) as response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                return 502, b""
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, b""
    except (urllib.error.URLError, TimeoutError, OSError):
        return 502, b""


def handler(upstream, internal, fetch=fetch):
    class Handler(http.server.BaseHTTPRequestHandler):
        def answer(self):
            action, value = decide(self.command, self.path, internal)
            if action == "forward":
                status, body = fetch(upstream, value)
            elif action == "internal" and value is not None:
                status, body = 200, value.encode()
            elif action == "internal":
                status, body = 404, b""
            else:
                status, body = 403, b""
            print(json.dumps({"method": self.command, "path": self.path, "action": action, "status": status}),
                  flush=True)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = answer

        def log_message(self, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, help="for example https://repo.maven.apache.org/maven2")
    parser.add_argument("--internal", action="append", default=[], help="a group prefix, for example ch.vs.")
    args = parser.parse_args()
    if not args.upstream.startswith("https://"):
        parser.error("--upstream must be https")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), handler(args.upstream.rstrip("/"), args.internal))
    print(json.dumps({"ready": PORT}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
