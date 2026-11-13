"""rc 묶음의 원격 A/B 가 쓰는 루프백 웹 서버 — 응답 헤더로 PHP 판만 알린다(본문은 없다).

리눅스 `rc/ab-net.sh` 와 Windows `host/rc/Invoke-AbNet.ps1` 가 함께 쓴다.
  usage: python -I -X utf8 net-mock.py <포트> <PHP 판>
"""
import http.server
import sys

PORT, VERSION = int(sys.argv[1]), sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def _head(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.58")
        self.send_header("X-Powered-By", "PHP/" + VERSION)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self._head()

    def do_GET(self):
        self._head()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
