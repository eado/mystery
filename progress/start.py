from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from threading import Thread
from json import dumps

progress = {}

def run1():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/':
                with open('index.html', 'r') as f:
                    s = f.read()
                    self.send_response(HTTPStatus.OK)
                    self.end_headers()
                    self.wfile.write(s.encode())
            elif self.path == "/progress":
                self.send_response(HTTPStatus.OK)
                self.end_headers()
                self.wfile.write(dumps(progress).encode())
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, Handler)
    httpd.serve_forever()

def run2():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.address_string().split(".")[2] == "0":
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            parts = self.path.split("/")
            if len(parts) < 3:
                self.send_error(HTTPStatus.NOT_FOUND)
            else:
                try:
                    if parts[1] not in progress:
                        progress[parts[1]] = int(parts[2])
                    elif progress[parts[1]] < int(parts[2]):
                        progress[parts[1]] = int(parts[2])

                    self.send_response(HTTPStatus.OK)
                    self.end_headers()
                except ValueError:
                    self.send_error(HTTPStatus.NOT_FOUND)
    server_address = ('', 8081)
    httpd = HTTPServer(server_address, Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    t1 = Thread(target=run1)
    t2 = Thread(target=run2)
    t1.start()
    t2.start()