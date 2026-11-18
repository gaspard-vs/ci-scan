"""Tests of helper.py. They run in the image of the helper, from npm test."""

import http.client
import json
import threading
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

import helper

INTERNAL = ["ch.vs."]
LOG4J = "/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom"


class Decide(unittest.TestCase):
    def test_a_public_pom_is_forwarded(self):
        self.assertEqual(helper.decide("GET", LOG4J, INTERNAL),
                         ("forward", LOG4J[len("/maven2"):]))

    def test_a_public_metadata_file_is_forwarded(self):
        path = "/maven2/org/yaml/snakeyaml/maven-metadata.xml"
        self.assertEqual(helper.decide("GET", path, INTERNAL)[0], "forward")

    def test_an_internal_pom_is_an_empty_pom(self):
        action, pom = helper.decide("GET", "/maven2/ch/vs/sci/java-quarkus/2.1/java-quarkus-2.1.pom", INTERNAL)
        self.assertEqual(action, "internal")
        self.assertIn("<groupId>ch.vs.sci</groupId>", pom)
        self.assertIn("<artifactId>java-quarkus</artifactId>", pom)
        self.assertIn("<version>2.1</version>", pom)
        self.assertNotIn("<dependencies>", pom)

    def test_an_internal_metadata_file_is_not_found(self):
        self.assertEqual(helper.decide("GET", "/maven2/ch/vs/sci/x/maven-metadata.xml", INTERNAL), ("internal", None))

    def test_the_prefix_is_a_whole_group_name(self):
        self.assertEqual(helper.decide("GET", "/maven2/ch/vsx/a/1/a-1.pom", INTERNAL)[0], "forward")
        self.assertEqual(helper.decide("GET", "/maven2/ch/vs/a/1/a-1.pom", INTERNAL)[0], "internal")

    def test_the_other_requests_are_refused(self):
        for method, path in [
            ("POST", LOG4J),
            ("HEAD", LOG4J),
            ("GET", "/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"),
            ("GET", "/maven2/org/x/a/1/b-1.pom"),
            ("GET", LOG4J + "?q=1"),
            ("GET", "/maven2/../etc/a/1/a-1.pom"),
            ("GET", "/maven2/org/./a/1/a-1.pom"),
            ("GET", "/other/org/x/a/1/a-1.pom"),
            ("GET", "http://example.com" + LOG4J),
        ]:
            with self.subTest(method=method, path=path):
                self.assertEqual(helper.decide(method, path, INTERNAL), ("refused", None))


class Server(unittest.TestCase):
    def setUp(self):
        self.asked = []

        def fetch(upstream, path):
            self.asked.append(upstream + path)
            return 200, b"<project/>"

        handler = helper.handler("https://repo.example/maven2", INTERNAL, fetch)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        out = StringIO()
        with redirect_stdout(out):
            connection.request(method, path)
            response = connection.getresponse()
            body = response.read()
        connection.close()
        return response.status, body, [json.loads(line) for line in out.getvalue().splitlines()]

    def test_a_forwarded_request_is_logged(self):
        status, body, log = self.request("GET", LOG4J)
        self.assertEqual((status, body), (200, b"<project/>"))
        self.assertEqual(self.asked, ["https://repo.example/maven2" + LOG4J[len("/maven2"):]])
        self.assertEqual(log, [{"method": "GET", "path": LOG4J, "action": "forward", "status": 200}])

    def test_an_internal_package_never_leaves(self):
        status, body, log = self.request("GET", "/maven2/ch/vs/a/1/a-1.pom")
        self.assertEqual(status, 200)
        self.assertIn(b"<artifactId>a</artifactId>", body)
        self.assertEqual(self.asked, [])
        self.assertEqual(log[0]["action"], "internal")

    def test_a_refused_request_never_leaves(self):
        status, _, log = self.request("POST", LOG4J)
        self.assertEqual(status, 403)
        self.assertEqual(self.asked, [])
        self.assertEqual(log[0]["action"], "refused")


if __name__ == "__main__":
    unittest.main()
