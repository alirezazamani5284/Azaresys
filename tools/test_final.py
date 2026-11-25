"""Final hardware acceptance test; Python 3 standard library only.
Writes ONLY demo holding registers 0..15 and restores their original contents.
Run against this release on the authorized test board, not another Modbus device.
"""
import argparse
import socket
import struct
import time


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        data = sock.recv(count-len(result))
        if not data:
            raise ConnectionError('Board closed the TCP connection')
        result.extend(data)
    return bytes(result)


class Client:
    def __init__(self, address):
        self.sock = socket.create_connection((address, 502), 3)
        self.sock.settimeout(4)
        self.transaction = 0

    def exchange(self, pdu, expected=None):
        self.transaction = (self.transaction+1) & 0xffff
        self.sock.sendall(struct.pack('>HHHB', self.transaction, 0, len(pdu)+1, 1)+pdu)
        tid, protocol, length, unit = struct.unpack('>HHHB', exact(self.sock, 7))
        assert (tid, protocol, unit) == (self.transaction, 0, 1), 'Invalid MBAP'
        assert 2 <= length <= 254, 'Invalid MBAP length'
        response = exact(self.sock, length-1)
        if expected is not None:
            assert response == expected, f'Unexpected PDU: {response.hex()}'
        return response

    def read(self, function, start, count):
        response = self.exchange(struct.pack('>BHH', function, start, count))
        assert response[:2] == bytes([function, count*2]), response.hex()
        assert len(response) == 2+count*2
        return struct.unpack('>'+str(count)+'H', response[2:])

    def write_many(self, start, values):
        count = len(values)
        pdu = struct.pack('>BHHB', 16, start, count, count*2)+struct.pack('>'+str(count)+'H', *values)
        self.exchange(pdu, struct.pack('>BHH', 16, start, count))

    def close(self):
        self.sock.close()


def expect_closed(sock):
    try:
        assert sock.recv(1) == b'', 'Unexpected data for malformed request'
    except (ConnectionResetError, ConnectionAbortedError):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address')
    parser.add_argument('--cycles', type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 100000:
        parser.error('cycles must be 1..100000')
    first = Client(args.address)
    second = None
    original = None
    try:
        identity = first.read(4, 0, 96)
        assert identity[0] == 0x4e49 and identity[1] == 0x0200, 'Wrong firmware/register map'
        original = first.read(3, 0, 16)
        pdu = struct.pack('>BHH', 6, 0, 1234)
        first.exchange(pdu, pdu)
        assert first.read(3, 0, 1) == (1234,)
        first.write_many(0, [111, 222, 333])
        assert first.read(3, 0, 3) == (111, 222, 333)
        first.exchange(bytes([3, 0, 16, 0, 1]), bytes([0x83, 2]))
        first.exchange(bytes([3, 0, 0, 0, 0]), bytes([0x83, 3]))
        first.exchange(bytes([99]), bytes([0xe3, 1]))
        first.exchange(bytes([16, 0, 0, 0, 2, 3, 0, 5, 0]), bytes([0x90, 3]))
        assert first.read(3, 0, 3) == (111, 222, 333), 'Malformed write changed registers'
        second = Client(args.address)
        t0 = time.perf_counter()
        for cycle in range(args.cycles):
            assert (first if cycle%2 else second).read(3, 0, 3) == (111, 222, 333)
        elapsed = time.perf_counter()-t0
        identity = first.read(4, 0, 96)
        print(f'PASS: FC03/04/06/16, exceptions, atomic validation, two clients, {args.cycles} reads in {elapsed:.3f}s')
        print(f'Board mode={identity[2]} (1=DHCP, 2=AutoIP); link={identity[3]}; observer fresh={identity[65]}')
        print(f'FreeRTOS heap free={(identity[45]<<16)|identity[46]}, minimum={(identity[47]<<16)|identity[48]} bytes')
    finally:
        try:
            if original is not None:
                first.write_many(0, original)
                assert first.read(3, 0, 16) == original
                print('Original demo registers restored.')
        finally:
            if second is not None:
                second.close()
            first.close()
    # Separate sessions for invalid MBAP and an incomplete frame deadline.
    time.sleep(0.1)
    with socket.create_connection((args.address, 502), 3) as sock:
        sock.settimeout(4)
        sock.sendall(bytes([0, 1, 0, 1, 0, 6, 1, 3, 0, 0, 0, 1]))
        expect_closed(sock)
    with socket.create_connection((args.address, 502), 3) as sock:
        sock.settimeout(4)
        sock.sendall(b'\x00\x01\x00')
        expect_closed(sock)
    again = Client(args.address)
    try:
        assert again.read(4, 0, 2) == (0x4e49, 0x0200)
    finally:
        again.close()
    print('PASS: malformed MBAP close, partial-frame deadline and reconnect')


if __name__ == '__main__':
    main()
