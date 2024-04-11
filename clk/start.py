DATA = b"""
HTTP/1.0 200 OK
Content-Type: text/plain

Let's keep this simple. 
There's nothing to see here! I promise. 
It's true that immortality allows for ***persistence***. 
I wrote that down on page 17 of my Tuesday's class notes. Hopefully I won't 
forget them again.
I should start uploading them on my servers. Maybe I'll have less of a request
for comments.

Hint: Check BruinLearn! The next host should be 3 characters and the port is 4 
digits."""
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
PORT = 1996
PROGRESS = 10

from http.client import HTTPConnection
from socket import socket, AF_INET, SOCK_STREAM
from re import match

with socket(AF_INET, SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
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