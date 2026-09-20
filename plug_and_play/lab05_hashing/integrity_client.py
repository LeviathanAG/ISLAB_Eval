"""Run after server.  Change PARTS to one or many chunks."""
import hashlib, json, socket

PARTS = [b"message sent ", b"in multiple ", b"parts"]
original = b"".join(PARTS)


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size-len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data


with socket.create_connection(("127.0.0.1", 5000)) as connection:
    for part in PARTS:
        connection.sendall(len(part).to_bytes(4, "big") + part)
    connection.sendall((0).to_bytes(4, "big"))
    size = int.from_bytes(receive_exact(connection, 4), "big")
    response = json.loads(receive_exact(connection, size))
local_hash = hashlib.sha256(original).hexdigest()
print("server hash:", response["sha256"])
print("local hash :", local_hash)
print("integrity verified:", response["sha256"] == local_hash)
