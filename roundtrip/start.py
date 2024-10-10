RESPGOOD = b"""
POST /youdidit HTTP/1.0

georgevarghese{tH3_H0lY_gR4iL_iS_tH3_fRi3NdS_w3_m4De_4L0Ng_tHe_w4y}"""

HOST = "0.0.0.0"
PORT = 3738 
PROGRESS = 30

NUMSERVERS = 1

from http.client import HTTPConnection
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from time import sleep

def try_player(i):
    while True:
        with socket(AF_INET, SOCK_STREAM) as s:
            try:
                addr = f'10.0.0.1{i:02}'
                s.connect((addr, PORT))
                httpconn = HTTPConnection("progress", 8081)
                httpconn.request("GET", "/" + addr + "/" + str(PROGRESS))
                httpconn.close()
                s.send(RESPGOOD)
            except ConnectionError:
                sleep(5)

if __name__ == "__main__":
    for i in range(NUMSERVERS + 1):
        t = Thread(target=try_player, args=(i,))
        t.start()
