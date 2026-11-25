import importlib.util
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

root=Path(__file__).resolve().parents[1]
path=root/'tools/discover_devices.py'
spec=importlib.util.spec_from_file_location('scanner',path);scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)
packet=b'F107HERE12345678'+bytes([192,168,10,50,255,255,255,0,0,128,225,0,0,0,1,246])+bytes.fromhex('1234567890ABCDEF10203040')+b'F107-ModbusTCP'.ljust(16,b'\0');nonce=b'12345678';peer=('192.168.10.50',30303)
device=scanner.parse_response(packet,nonce,peer)
assert device['name']=='F107-ModbusTCP'
assert device['ip']=='192.168.10.50' and device['netmask']=='255.255.255.0'
assert device['modbus_port']==502 and device['uid']=='1234567890ABCDEF10203040'
for modified in [packet[:-1],packet+b'x',b'BADMAGIC'+packet[8:],packet[:8]+b'00000000'+packet[16:],packet[:20]+b'\xff\x00\xff\x00'+packet[24:],packet[:24]+b'\xff'*6+packet[30:],packet[:30]+b'\0\0'+packet[32:],packet[:44]+b'\xff'*16]:
 try: scanner.parse_response(modified,nonce,peer)
 except ValueError: pass
 else: raise AssertionError('Malformed response accepted')
for wrong_peer in [('192.168.10.51',30303),('192.168.10.50',30304)]:
 try: scanner.parse_response(packet,nonce,wrong_peer)
 except ValueError: pass
 else: raise AssertionError('Wrong sender accepted')

class FakeSocket:
 def __init__(self): self.queue=[];self.closed=False;self.sent=0
 def setsockopt(self,*args):pass
 def bind(self,address):assert address==('192.168.10.10',0)
 def setblocking(self,value):assert not value
 def sendto(self,data,target):
  assert target==('192.168.10.255',30303)
  assert len(data)==20 and data[16:]==bytes([255,255,255,0])
  self.queue.extend([(packet[:8]+data[8:16]+packet[16:],peer)]*2);self.sent+=1
 def recvfrom(self,size):return self.queue.pop(0)
 def close(self):self.closed=True
fake=FakeSocket();clock=[0.0]
def now():clock[0]+=0.025;return clock[0]
def ready(sockets,*args):return ([s for s in sockets if s.queue],[],[])
with patch.object(scanner.socket,'socket',return_value=fake),patch.object(scanner.time,'monotonic',side_effect=now),patch.object(scanner.select,'select',side_effect=ready):
 found=scanner.discover([ipaddress.IPv4Interface('192.168.10.10/24')],2.0)
assert len(found)==1 and fake.closed and fake.sent==3
# Windows auto-enumeration, filtering and duplicate interface entries.
rows=[{'IPAddress':'192.168.10.10','PrefixLength':24}]*2+[{'IPAddress':'127.0.0.1','PrefixLength':8}]
with patch.object(scanner.os,'name','nt'),patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(stdout=json.dumps(rows))):
 assert scanner.local_interfaces()==[ipaddress.IPv4Interface('192.168.10.10/24')]
print('Python parser, nonce/source validation, NIC enumeration, broadcast retries, deduplication and socket cleanup tests passed')
