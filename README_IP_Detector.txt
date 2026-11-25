F107 IP Detector v1 - local IPv4 discovery + working Modbus TCP v1.1

1. Extract into a new directory.
2. Open MDK-ARM/F107_ModbusTCP.uvprojx with Arm Compiler 5.06.
3. Rebuild all target files, download, reset and Run without breakpoints.
4. Open CMD in the extracted project directory.
5. Execute:
     py -3 tools\discover_devices.py

Windows uses PowerShell Get-NetIPAddress to enumerate PC IPv4 interfaces.
The program broadcasts three probes on each selected local subnet and collects
validated responses for three seconds. No board IP is supplied to the scanner.

For the current PC Ethernet configuration, an explicit interface can be used:
  py -3 tools\discover_devices.py --interface 192.168.10.10 --prefix 24
This is the PC address, not the board address.

Expected output includes:
  FOUND F107-ModbusTCP  IP=192.168.10.50  TCP=502
  MAC=00:80:E1:00:00:00  UID=<24 hex characters>  PC=192.168.10.10

Then verify Modbus again:
  py -3 tools\test_modbus.py 192.168.10.50
Initial register values may include 1234 if the Modbus test was already run.

This version discovers a board on the same IPv4 subnet / broadcast domain.
It does not assign an IP address or discover through a router or across
incompatible IPv4 subnets. Keep PC 192.168.10.10/24 for the existing static
board address 192.168.10.50/24. The transport is a custom discovery protocol.
Only the Modbus server uses the Modbus TCP protocol.

One board is the current hardware test target. Before placing several boards
on one LAN, provision distinct IP and MAC addresses. The supplied firmware
retains the previous fixed MAC. The scanner deduplicates by full hardware UID.

If Windows asks about Python network access, allow it on the network used for
this local test. If discovery fails, try the explicit PC interface command.

Useful Watch variables:
  discovery_listening      1 after UDP bind succeeds
  discovery_requests       valid probes accepted
  discovery_replies        responses handed successfully to lwIP
  discovery_last_error     most recent operation result, 0 means ERR_OK
  network_free_heap        free bytes in FreeRTOS heap
  network_min_free_heap    minimum free heap since boot
  debug_error_file / debug_error_line / debug_error_expression

Implementation notes:
  UDP 30303, Netconn API in its own FreeRTOS task, stack 512 words.
  A synchronous netifapi callback snapshots live IP, netmask and MAC in
  tcpip_thread, avoiding direct cross-thread reads of the interface.
  MEMP_NUM_NETBUF=8 accommodates UDP receive queues and TCP receive buffers.
  The received UDP netbuf is freed before allocating the reply netbuf.
  At most one discovery response is sent per 100 milliseconds.
  Each request contains a fresh 8-byte correlation nonce.
  Replies are unicast to the request's source IP and ephemeral port.
  The scanner validates magic, nonce, length, source address/port, netmask,
  unicast MAC, port and ASCII name. The nonce is correlation, not authentication.

Wire format, all integers in network byte order:
  Request: 16 bytes
    [0..7]   ASCII F107FIND
    [8..15]  request nonce
  Response: 60 bytes
    [0..7]   ASCII F107HERE
    [8..15]  copied nonce
    [16..19] board IPv4 address
    [20..23] subnet mask
    [24..29] MAC address
    [30..31] Modbus TCP port (502)
    [32..43] three STM32 UID words in network byte order
    [44..59] zero-padded ASCII device name

Host tests passed for actual embedded response-building functions under
AddressSanitizer/UndefinedBehaviorSanitizer, invalid lengths/magic, link-down,
allocation failure and recovery. Python tests cover cross-language decoding,
nonce/source validation, Windows adapter enumeration, broadcast retries,
deduplication and socket cleanup using controlled test doubles.
All 107 project C translation units preprocess with project paths and defines.
Full Arm Compiler 5.06 compilation and UDP discovery on the physical board
still need to be validated. Regeneration can overwrite the manual integration.
