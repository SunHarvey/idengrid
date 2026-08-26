#!/usr/bin/env python3
import json
import os
import socket
import sys
import time

path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(path)
    server.listen(1)
    connection, _ = server.accept()
    with connection:
        request = b""
        while not request.endswith(b"\n"):
            chunk = connection.recv(4096)
            if not chunk:
                raise RuntimeError("client closed before request")
            request += chunk
        parsed = json.loads(request)
        if parsed["command"] != "status":
            raise RuntimeError("unexpected command")
        response = (
            b'{"status":"connected","socks_host":"127.0.0.1",'
            b'"socks_port":55233,"store_id":2,"device_id":"mac-test"}\n'
        )
        midpoint = len(response) // 2
        connection.sendall(response[:midpoint])
        time.sleep(0.05)
        connection.sendall(response[midpoint:])
        time.sleep(1.5)  # Client must return on newline, not wait for EOF.
