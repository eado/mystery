DATA = b"""
PTHT/1.0 200 OK|Content-Type: text/plain||Thanks for getting my notes to my
house in time. I'll be doing the requesting now.
Make sure to serve me well...use this answer once more. 
"""
ERR404 = b"""
PTHT/1.0 404 Not Found|Content-Type: text/plain||You got lucky last time...
you're gonna have to guess where I'm hiding this time. Here's a nice problem
for you:

Imagine I wanted to send my lab notes to my wife Mrs. Block at my house. 
Between my lab computer and my house, there's one router. Hence, there are two
links. Don't ask how I know this, but the first link from my lab to the router
has a:
- propagation delay of 20 ms
- transmission rate of 5 Mbps

The second link from the router to my house has a:
- propagation delay of 5 ms
- transmission rate of 2 Mbps

My notes are 1.5 MB and packets are 500 KB each. 

How long will it take for my notes to arrive at home? You'll be able to find
the next step to immortality in milliseconds...
"""
ANSWER = 6825
ERR400 = b"PTHT/1.0 400 Bad Request|Content-Type: text/plain||Sorry, I've got no idea what you're trying to tell me."

PANY = "^DOWNLOAD( | $|$)[/A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@%]*\\s*(\\s+PTHT|\\s+PTHT/1.0)?\\s*$"
PEXACT = "^DOWNLOAD /+{}/*\\s*(\\s+PTHT|\\s+PTHT/1.0)?\\s*$".format(ANSWER)

HOST = "0.0.0.0"
PORT = 2616
PROGRESS = 20

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