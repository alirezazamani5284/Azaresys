"""Test the board with Python 3 and the standard library."""

# Test behavior is preserved: running this script performs a Modbus write.
import socket
import struct
import sys


# TCP is a byte stream: repeat recv until the requested byte count is complete.
# A closed socket before completion raises ConnectionError.
def receive_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Board closed the TCP connection")
        data.extend(chunk)
    return bytes(data)


# Build a Unit ID 1 request and correlate the reply using the transaction ID.
# MBAP length includes the Unit ID already read in the seven-byte header.
# An exception or unexpected function raises ValueError.
def exchange(connection, transaction, function, address, value):
    request = struct.pack(">HHHBBHH", transaction, 0, 6, 1, function, address, value)
    connection.sendall(request)
    header = receive_exact(connection, 7)
    response_transaction, protocol, length, unit = struct.unpack(">HHHB", header)
    if response_transaction != transaction or protocol != 0 or unit != 1:
        raise ValueError("Invalid Modbus response header")
    if not 2 <= length <= 254:
        raise ValueError("Invalid Modbus response length")
    response = receive_exact(connection, length - 1)
    if response[0] != function:
        raise ValueError("Modbus error response: " + response.hex(" "))
    return response


# LIVE BOARD TEST: reads registers, writes register 0 to 1234, then reads it back.
# This intentionally changes RAM register 0 until another write or reset.
# Network operations use five-second socket timeouts; no third-party package needed.
def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.10.50"
    with socket.create_connection((host, 502), timeout=5) as connection:
        connection.settimeout(5)
        response = exchange(connection, 1, 3, 0, 3)
        if len(response) != 8 or response[1] != 6:
            raise ValueError("Unexpected register response")
        print("Registers 0..2:", struct.unpack(">HHH", response[2:]))
        response = exchange(connection, 2, 6, 0, 1234)
        if response != struct.pack(">BHH", 6, 0, 1234):
            raise ValueError("Write acknowledgement mismatch")
        response = exchange(connection, 3, 3, 0, 1)
        if response != struct.pack(">BBH", 3, 2, 1234):
            raise ValueError("Register readback mismatch")
        print("PASS: register 0 written and read back as 1234")


if __name__ == "__main__":
    main()
