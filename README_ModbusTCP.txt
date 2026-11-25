F107 Modbus TCP - first server test

Extract into a new folder. Open MDK-ARM/F107_ModbusTCP.uvprojx.
Use Arm Compiler 5.06, Rebuild, download, reset, and run without breakpoints.
The existing LAN configuration uses RMII PD8/PD9/PD10 and software checksums.

Board IP: 192.168.10.50, mask 255.255.255.0
PC Ethernet IP: 192.168.10.10, mask 255.255.255.0
TCP port: 502
Unit identifier: 1
Functions: 03 Read Holding Registers, 06 Write Single Register
Zero-based addresses: 0..15 (often displayed as 40001..40016)
Initial values after reset: address 0=100, 1=200, 2=300, all remaining=0.
One active client is served at a time. Idle receive timeout is 10 seconds.
Registers are in RAM and are initialized again on reset.
LEDs retain their diagnostic blinking. No register is mapped to GPIO yet.

From the extracted project folder, with Python 3 installed:
  python tools/test_modbus.py 192.168.10.50
Expected output on a fresh reset:
  Registers 0..2: (100, 200, 300)
  PASS: register 0 written and read back as 1234
The test leaves register 0 set to 1234 until changed or reset.

Watch variables:
  modbus_listening = 1 while listener is active
  modbus_requests counts complete received Modbus ADUs
  modbus_holding contains the register bank
  debug_error_file, debug_error_line, debug_error_expression identify assertions

Host verification completed: protocol parsing, fragmented/coalesced requests,
exceptions, unit filtering, invalid MBAP headers and lengths, maximum ADU length.
All project C sources preprocessed successfully. Full Keil compilation and board
execution of this Modbus version still require validation.

CubeMX regeneration may overwrite manual integration. Use the supplied project
for this first test and retain the previous successful LAN version separately.

Version 1.1 fixes timed sending for lwIP 2.0.3 using netconn_write_partly.
Partial writes are retried within an overall three-second send deadline.
