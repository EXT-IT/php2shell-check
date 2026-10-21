"""Tiny HTTP server for the remote checks in run_tests.sh.

Each path answers with a fixed set of headers, so the tests never touch the
internet. Usage: python3 fixture_server.py PORTFILE
The chosen port is written to PORTFILE once the server listens.
"""
import http.server
import sys

ROUTES = {
    "/vulnerable": [("X-Powered-By", "PHP/8.3.35")],
    "/fixed": [("X-Powered-By", "PHP/8.3.36")],
    "/distro": [("X-Powered-By", "PHP/8.3.6")],
    "/eol": [("X-Powered-By", "PHP/7.4.30")],
    "/cloudflare": [("Server", "cloudflare"), ("CF-RAY", "8f00000000000000-FRA")],
    "/sucuri": [("Server", "Sucuri/Cloudproxy"), ("X-Sucuri-ID", "11001")],
    "/litespeed": [("Server", "LiteSpeed")],
    "/escape": [("X-Powered-By", "PHP/8.3.35\x1b]0;pwned\x07")],
    "/plain": [],
    "/redirect-same": [("Location", "/vulnerable")],
    "/redirect-access": [("Location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/x")],
}

# Requests that must never arrive: the redirect target on a foreign host.
FOREIGN_HITS = [0]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server naming)
        port = self.server.server_address[1]
        if self.path == "/redirect-foreign":
            self._answer(302, [("Location", "http://localhost:%d/foreign-hit" % port)])
            return
        if self.path == "/foreign-hit":
            FOREIGN_HITS[0] += 1
        if self.path == "/cf-blocked":
            self._answer(403, [("Server", "cloudflare"), ("CF-RAY", "8f00000000000001-FRA"),
                               ("cf-mitigated", "challenge")])
            return
        if self.path == "/cf-redirect":
            self._answer(301, [("Server", "cloudflare"), ("CF-RAY", "8f00000000000002-FRA"),
                               ("Location", "/vulnerable")])
            return
        if self.path == "/foreign-count":
            self._answer(200, [("X-Count", str(FOREIGN_HITS[0]))])
            return
        headers = ROUTES.get(self.path)
        if headers is None:
            self.send_response(404)
            self.end_headers()
            return
        status = 302 if any(n == "Location" for n, _ in headers) else 200
        self._answer(status, headers)

    def _answer(self, status, headers):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def main():
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    with open(sys.argv[1], "w") as fh:
        fh.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
