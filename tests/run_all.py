"""Host validation (Python 3 + GCC); does not flash or contact a board."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parent
for name in ['test_link_host.py','test_addressing_host.py','test_observer_host.py','test_identity_host.py','test_discovery_host.py','test_modbus_host.py','test_scanner.py','check_syntax.py']:
    print('\nRUN '+name,flush=True)
    subprocess.run([sys.executable,str(root/name)],check=True)
print('\nPASS: all host checks. Keil build, Windows execution and hardware acceptance remain required.')
