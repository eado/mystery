DATA = b"""
HTTP/1.0 200 OK
Content-Type: text/plain

NETSIFT INTERNAL DOCS
<REDACTED>
DATA LINK PROTOCOLS DISCUSSION:
FRAMING:
PAGE 20 OF LECTURE NOTES BIT STUFFING
<REDACTED>

Hint: Check Tuesday's lecture notes on Bit Stuffing (page 20). 
The next host you should connect to is a protocol that's 4 characters long.
The port is the year that this protocol was created. (Check Wikipedia.)

"""
ERR404 = b"""
HTTP/1.0 404 Not Found
Content-Type: text/plain

Looks like you're searching in the wrong place!"""
ERR400 = b"""
HTTP/1.0 400 Bad Request
Content-Type: text/plain

Sorry, I've got no idea what you're trying to tell me."""

PANY = "^GET( | $|$)[/A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@%]*\\s*(\\s+HTTP|\\s+HTTP/1.0)?\\s*$"
PEXACT = "^GET( | $|$)/*\\s*(\\s+HTTP|\\s+HTTP/1.0)?\\s*$"

HOST = "0.0.0.0"
PORT = 2005
PROGRESS = 10

from http.client import HTTPConnection
from socket import socket, AF_INET, SOCK_STREAM
from re import match
from threading import Thread

def handle_client(conn, addr):
    with conn:
        print(f"Connected by {addr}")
        req = conn.recv(1024).decode()
        print(req)
        if not match(PANY, req):
            conn.send(ERR400)
        elif not match(PEXACT, req):
            conn.send(ERR404)
        else:
            httpconn = HTTPConnection("progress", 8081)
            httpconn.request("GET", "/" + addr[0] + "/" + str(PROGRESS))
            httpconn.close()
            conn.send(DATA)
        conn.close()

with socket(AF_INET, SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        t = Thread(target=handle_client, args=(conn, addr))
        t.start()
