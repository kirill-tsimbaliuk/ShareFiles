import socket
import argparse
import os
import sys
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import platform

STOP_KEY = "\r\n\r\nEOF".encode("utf-8")
MIDDLE_KEY = "-EOS-".encode('utf-8')

PORT = 9000


def scan(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((address, PORT))
    if not result == 0:
        return f"INFO: Address {address} failed"
    sock.close()

    sock = socket.socket()
    sock.connect((address, PORT))
    sock.send(b"10")
    data = b""
    while True:
        packet = sock.recv(1024)
        data += packet
        if not packet:
            break

    return f"INFO: {data.decode()} find on IP {address}"


parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file_path')
parser.add_argument('-c', '--command', default='scan')
parser.add_argument('-o', '--output', default='output/')
parser.add_argument('-t', '--target', default='localhost')
parser.add_argument('-d', '--deep', default=False, type=bool)

args = parser.parse_args()

sock = socket.socket()
if args.command == 'up':
    keys = generate_eth_key()
    private_key = keys.to_hex()
    public_key = keys.public_key.to_hex()

    sock.bind(('0.0.0.0', PORT))
    sock.listen(1)
    print("LOG: server up")
    while True:
        conn, ad = sock.accept()
        print("LOG: client", ad, "start connection")

        request_code = conn.recv(2)
        if request_code == b'00':
            print('LOG: sending open key')
            conn.send(public_key.encode())
            conn.close()
            print("LOG: connection finished")

        elif request_code == b'01':
            print('LOG: upload the data')
            data = b""
            while not (STOP_KEY in data):
                data += conn.recv(1024)
            print("LOG: upload finished")

            data = data.replace(STOP_KEY, b'')

            data = decrypt(private_key, data)
            file_name = data[:data.find(MIDDLE_KEY)]
            data = data.replace(MIDDLE_KEY, b'', 1)
            data = data.replace(file_name, b'', 1)

            print(f"LOG: client want to send you file {file_name.decode('utf-8')}. Size is {len(data)} bytes.")
            print("Accept it?")
            answer = input("(y/n) > ")
            if answer == 'y' or answer == 'Y' or answer == "yes":
                os.makedirs(args.output, exist_ok=True)
                with open(f"{args.output}/{file_name.decode('utf-8')}", 'wb') as f:
                    f.write(data)
                print(f"LOG: file {file_name.decode('utf-8')} was successfully downloaded")
                conn.send(b'1')
            else:
                print(f"LOG: file {file_name.decode('utf-8')} was canceled")
                conn.send(b'0')
            print("LOG: connection finished")
            conn.close()

        elif request_code == b"10":
            print("LOG: send host name")
            conn.send(platform.node().encode())
            conn.close()
            print("LOG: connection finished")

elif args.command == "send":
    if not args.file_path:
        print("ERROR: Please, set a file to sending")
        sys.exit(1)
    if not os.path.exists(args.file_path):
        print("ERROR: File not exist")
        sys.exit(1)
    print("INFO: Start connect to", args.target, PORT)
    try:
        sock = socket.socket()
        sock.connect((args.target, PORT))
    except ConnectionRefusedError:
        print("ERROR: The target computer rejected the connection request")
        sys.exit(1)

    print("INFO: The connection was established successfully")
    sock.send(b'00')
    data = b""
    while True:
        packet = sock.recv(1024)
        data += packet
        if not packet:
            break
    sock.close()

    open_key = data.decode()

    with open(args.file_path, 'rb') as file:
        data = file.read()
    file_name = args.file_path[args.file_path.rfind(r"/") + 1:]

    encrypted = encrypt(open_key, file_name.encode('utf-8') + MIDDLE_KEY + data) + STOP_KEY

    sock = socket.socket()
    sock.connect((args.target, PORT))
    sock.send(b"01")
    sock.send(encrypted)
    print("INFO: Sending finished")
    print("INFO: Waiting for server answer")
    if sock.recv(1) == b'1':
        print("INFO: The file was accepted successfully")
    else:
        print("INFO: The server refused to accept the file")
    sock.close()

elif args.command == "scan":
    print("INFO: Scanning started")
    try:
        if args.deep:
            for i in range(1, 256):
                for j in range(1, 256):
                    ip = f"192.168.{i}.{j}"
                    print(scan(ip))
            print("INFO: Scanned all ips, from 192.168.1.1 to 192.168.256.256")
        else:
            for i in range(1, 256):
                ip = f"192.168.1.{i}"
                print(scan(ip))
            print("INFO: Scanned all ips, from 192.168.1.1 to 192.168.1.256")
    except KeyboardInterrupt:
        sys.exit(0)
