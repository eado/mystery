REQUEST = b"""
POST /roundtrip HTTP/1.0

When I created an HTML website for a recent project, complete with images, 
Java Applets, and CSS, one of my colleagues complained about the long load 
times. He's using Netscape 0.9, which relies on HTTP/1.0, allowing for 13 
parallel connections. Considering an upgrade to HTTP/1.1 might benefit from 
pipelined requests.

Let's assume:
- Each of the 63 files (HTML + 62 resources) fits in a single packet.
- Each packet has an average round-trip time of 22 ms.

Questions:
- How long, on average, does it take for my colleague to load my website? 
- How long would it be if Netscape used HTTP/1.1 (still with 13 max parallel
connections?)

Add these two answers together and respond with that status code (and its
message...look it up!) Feel free to put whatever you want in the body.
"""
RESPBAD = b"POST /thatsnotright HTTP/1.0"
RESPGOOD = b"""
POST /youdidit HTTP/1.0

geneblock{tH3_H0lY_gR4iL_iS_tH3_fRi3NdS_w3_m4De_4L0Ng_tHe_w4y}"""

RESPMATCH = "HTTP/1.0 418 I'm a teapot.*$"

HOST = "0.0.0.0"
PORT = 6825
PROGRESS = 30

NUMSERVERS = 1

from http.client import HTTPConnection
from socket import socket, AF_INET, SOCK_STREAM
from re import match
from threading import Thread
from time import sleep

def try_player(i):
    while True:
        with socket(AF_INET, SOCK_STREAM) as s:
            try:
                addr = f'10.0.0.1{i:02}'
                s.connect((addr, PORT))
                s.send(REQUEST)
                resp = s.recv(1024).decode()
                if match(RESPMATCH, resp):
                    httpconn = HTTPConnection("progress", 8081)
                    httpconn.request("GET", "/" + addr + "/" + str(PROGRESS))
                    httpconn.close()
                    s.send(RESPGOOD)
                else:
                    s.send(RESPBAD)
            except ConnectionError:
                sleep(5)
            
if __name__ == "__main__":
    for i in range(NUMSERVERS + 1):
        t = Thread(target=try_player, args=(i,))
        t.start()
