import random

from security import *
from time import sleep


HOST = "0.0.0.0"
PORT = 8080 

NUMSERVERS = 1

from http.client import HTTPConnection
from socket import socket, AF_INET, SOCK_STREAM
from multiprocessing import Process

def send_prog(add, num):
    httpconn = HTTPConnection("progress", 8081)
    httpconn.request("GET", "/" + add + "/" + str(num))
    httpconn.close()

def handle_client(c, a):
    state = 0
    nonce = None
    bad = random.randint(0, 1) == 0
    cip = None
    while True:
        if state == 0:
            load_private_key("server_key.bin")
            state += 1
            send_prog(a[0], 10)
        elif state == 1:
            nonce = bytes(c.recv(2000))
            if len(nonce) != 32:
                send_prog(a[0], 0)
                break
            derive_public_key()
            c.send(get_public_key())
            state += 1
            send_prog(a[0], 20)
        elif state == 2:
            pub_key = c.recv(2000)
            load_peer_public_key(pub_key)
            derive_secret()
            derive_keys()
            if nonce is not None:
                sig = sign(nonce)
                if bad:
                    arr = bytearray(sig)
                    arr[10] = 0
                    arr[11] = 0
                    arr[12] = 0
                    sig = bytes(arr)
                c.send(sig)
            state += 1
            send_prog(a[0], 30)
        elif state == 3:
            _ = c.recv(2000)
            pt = b"varghese{70_3ncryp7_0r_n07_70_3ncryp7}" if not bad else b"HACKER ALERT"
            iv, cip = encrypt_data(pt)
            c.send(iv)
            state += 1
            send_prog(a[0], 40)
        elif state == 4:
            _ = c.recv(2000)
            c.send(cip)
            state += 1
            send_prog(a[0], 0 if bad else 50)
            sleep(60)
            break
    c.close()


with socket(AF_INET, SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        t = Process(target=handle_client, args=(conn, addr))
        t.start()
