"""Discover F107 boards on local IPv4 subnets. Python 3, no dependencies."""

# Local IPv4 discovery client: standard library only; no firmware settings are changed.
import argparse
import ipaddress
import json
import os
import secrets
import select
import socket
import struct
import subprocess
import sys
import time

# Wire constants match Core/Src/ip_discovery.c; keep both ends consistent.
PORT = 30303
REQUEST_MAGIC = b"F107FIND"
RESPONSE_MAGIC = b"F107HERE"


# Decode exactly 60 bytes and reject unrelated or malformed replies.
# Validate nonce, sender, mask, unicast MAC, service port and printable ASCII name.
# The nonce provides correlation only; this protocol is not authenticated.
def parse_response(packet, nonce, peer):
    if len(packet) != 60 or packet[:8] != RESPONSE_MAGIC or packet[8:16] != nonce:
        raise ValueError("Unrelated or malformed discovery reply")
    if peer[1] != PORT:
        raise ValueError("Unexpected reply port")
    address = ipaddress.IPv4Address(packet[16:20])
    mask = str(ipaddress.IPv4Address(packet[20:24]))
    ipaddress.IPv4Network("0.0.0.0/" + mask)
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError("Invalid advertised IPv4 address")
    if str(address) != peer[0]:
        raise ValueError("Advertised address differs from sender")
    mac = packet[24:30]
    if mac == b"\x00" * 6 or mac[0] & 1:
        raise ValueError("Invalid unicast MAC")
    port = struct.unpack(">H", packet[30:32])[0]
    if port == 0:
        raise ValueError("Invalid Modbus port")
    name = packet[44:60].split(b"\x00", 1)[0].decode("ascii")
    if not name or any(ord(character) < 32 or ord(character) > 126 for character in name):
        raise ValueError("Invalid device name")
    return {
        "name": name,
        "ip": str(address),
        "netmask": mask,
        "mac": ":".join(f"{byte:02X}" for byte in mac),
        "uid": packet[32:44].hex().upper(),
        "modbus_port": port,
    }


# Windows: enumerate preferred IPv4 adapters via PowerShell without dependencies.
# Other systems: caller supplies the PC interface address and subnet prefix.
# Return IPv4Interface objects, not board addresses.
def local_interfaces(explicit_address=None, prefix=24):
    if explicit_address:
        return [ipaddress.IPv4Interface(f"{explicit_address}/{prefix}")]
    if os.name != "nt":
        raise RuntimeError("Use --interface YOUR_PC_IP --prefix YOUR_PREFIX on this OS")
    command = (
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | "
        "Where-Object { $_.AddressState -eq 'Preferred' -and "
        "$_.IPAddress -ne '127.0.0.1' } | "
        "Select-Object IPAddress,PrefixLength) | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, encoding="utf-8-sig", timeout=10, check=True,
    )
    rows = json.loads(result.stdout or "[]")
    if isinstance(rows, dict):
        rows = [rows]
    interfaces = set()
    for row in rows:
        interface = ipaddress.IPv4Interface(f"{row['IPAddress']}/{int(row['PrefixLength'])}")
        if not interface.ip.is_loopback and not interface.ip.is_unspecified and interface.network.prefixlen < 31:
            interfaces.add(interface)
    if not interfaces:
        raise RuntimeError("No usable IPv4 interface found")
    return sorted(interfaces, key=str)


# One nonblocking UDP socket per PC adapter, with broadcast enabled.
# Send at most three probes 0.6 s apart; timeout is the total scan window.
# Accept replies only from the receiving adapter subnet; deduplicate by full UID.
# Every retained socket is closed in finally, including failure paths.
def discover(interfaces, timeout=3.0):
    # Use one fresh correlation nonce for this scan and all its retry broadcasts.
    nonce = secrets.token_bytes(8)
    request = REQUEST_MAGIC + nonce
    sockets = {}
    devices = {}
    try:
        for interface in interfaces:
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                connection.bind((str(interface.ip), 0))
                connection.setblocking(False)
            except OSError as error:
                connection.close()
                print(f"Skipping {interface}: {error}", file=sys.stderr)
                continue
            sockets[connection] = interface
        if not sockets:
            raise RuntimeError("Could not bind a discovery socket")
        # A monotonic clock avoids wall-clock adjustments changing the scan duration.
        deadline = time.monotonic() + timeout
        next_send = time.monotonic()
        sends = 0
        successful_sends = 0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if sends < 3 and now >= next_send:
                for connection, interface in sockets.items():
                    try:
                        connection.sendto(request + interface.netmask.packed,
                                          (str(interface.network.broadcast_address), PORT))
                        successful_sends += 1
                    except OSError as error:
                        print(f"Broadcast on {interface} failed: {error}", file=sys.stderr)
                sends += 1
                next_send = now + 0.6
            wait = min(0.2, max(0.0, deadline - time.monotonic()))
            readable, _, _ = select.select(list(sockets), [], [], wait)
            for connection in readable:
                try:
                    packet, peer = connection.recvfrom(2048)
                except BlockingIOError:
                    continue
                try:
                    device = parse_response(packet, nonce, peer)
                    if ipaddress.IPv4Address(device["ip"]) not in sockets[connection].network:
                        continue
                except (ValueError, UnicodeError):
                    continue
                device["pc_interface"] = str(sockets[connection].ip)
                # Hardware UID avoids treating two boards with the same default MAC as one.
                devices[device["uid"]] = device
        if successful_sends == 0:
            raise RuntimeError("No discovery broadcasts could be sent")
        return sorted(devices.values(), key=lambda item: int(ipaddress.IPv4Address(item["ip"])))
    finally:
        for connection in sockets:
            connection.close()


# CLI returns 0 if at least one board is found; 1 for no devices or scan failure.
# --json changes output formatting only; explicit --interface is the PC address.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="PC Ethernet IPv4 address, not the board address")
    parser.add_argument("--prefix", type=int, default=24, help="PC network prefix for --interface")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    if not 1 <= arguments.prefix <= 30 or not 1 <= arguments.timeout <= 30:
        parser.error("prefix must be 1..30 and timeout must be 1..30 seconds")
    try:
        interfaces = local_interfaces(arguments.interface, arguments.prefix)
        if not arguments.json:
            print("Scanning PC interfaces: " + ", ".join(map(str, interfaces)))
        devices = discover(interfaces, arguments.timeout)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Discovery failed: {error}", file=sys.stderr)
        print("Try --interface 192.168.10.10 --prefix 24 for the current test setup.", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(devices, indent=2))
    else:
        for device in devices:
            print(f"FOUND {device['name']}  IP={device['ip']}  TCP={device['modbus_port']}")
            print(f"  MAC={device['mac']}  UID={device['uid']}  PC={device['pc_interface']}")
        if not devices:
            print("No board found on these subnets. Check Run state, Ethernet, and UDP firewall permissions.")
    return 0 if devices else 1


if __name__ == "__main__":
    raise SystemExit(main())
