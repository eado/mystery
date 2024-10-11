DATA = b"""
HTTP/1.0 200 OK
Content-Type: text/plain

Thanks for decoding that message. Now, you're the one who's going to
have to listen...

Hint: Create a server that listens on any address at port 3738.
"""
ERR404 = b"""
HTTP/1.0 404 Not Found
Content-Type: text/plain

NETSIFT INTERVIEW PROBLEM (CONFIDENTIAL):
Here's a sequence of bits from a (modified) HDLC connection (beginning/end stripped):
00110011 001101110 00110011 001110000

From left to right, these bits form an ASCII string.

HDLC uses bit stuffing with a sentinel pattern 011110.
Any time it sees a sequence of 3 1s in a row, it inserts a 0.
Your job is to "unstuff" these bits.

Hint: If the answer is 2467, send GET /2467
"""
ANSWER = 3738
ERR400 = b"""HTTP/1.0 400 Bad Request
Content-Type: text/plain

Sorry, I've got no idea what you're trying to tell me."""

PANY = "^GET( | $|$)[/A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@%]*\\s*(\\s+HTTP|\\s+HTTP/1.0)?\\s*$"
PEXACT = "^GET /+{}/*\\s*(\\s+HTTP|\\s+HTTP/1.0)?\\s*$".format(ANSWER)

HOST = "0.0.0.0"
PORT = 1979
PROGRESS = 20

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
