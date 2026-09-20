"""Run first: python plug_and_play/lab05_hashing/integrity_server.py"""
import hashlib, json, socket


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size-len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data


def receive_all(connection):
    chunks = []
    while True:
        size = int.from_bytes(receive_exact(connection, 4), "big")
        if size == 0:
            return b"".join(chunks)
        chunks.append(receive_exact(connection, size))


with socket.create_server(("127.0.0.1", 5000), reuse_port=True) as server:
    print("waiting on 127.0.0.1:5000")
    connection, address = server.accept()
    with connection:
        message = receive_all(connection)
        response = json.dumps({"bytes": len(message), "sha256": hashlib.sha256(message).hexdigest()}).encode()
        connection.sendall(len(response).to_bytes(4, "big") + response)
        print("received", repr(message), "from", address)
