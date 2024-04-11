REQUEST = b"""
POST /roundtrip HTTP/1.0

While there are no clients for PTHT, there are
clients for HTTP--an odd protocol that never really took off. 

I decided to give it a try and create an HTML website for a recent project of 
mine.
Totally decked out with images, Java Applets, CSS, and the works. 

Unfortunately, one of my colleagues is complaining about how long it takes for
my website to load. He's currently using Netscape 0.9 that uses HTTP/1.0 (with
13 max parallel connections). I heard of a recent RFC detailing upcoming 
HTTP/1.1--which allows for pipelined requests. Maybe that will help?

Suppose my HTML and all my images, etc. (62 total not including HTML) are very 
small--each fits in a single packet. Don't ask how I know this, but each
roundtrip time (all delays, on average, to send a packet and receive one back)
is 22 ms. 

How long, on average, does it take for my colleague to load my website? 
How long would it be if Netscape used HTTP/1.1 (still with 13 max parallel
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
