"""Whole-scanner simulation: Core/Src/mbscan.c runs on the PC against modelled devices
(fake RTOS with virtual time, fake lwIP raw TCP, fake ETH/PHY). 13 scenarios."""
from pathlib import Path
import subprocess, tempfile, os
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
    exe = Path(d) / 'mbsim'
    subprocess.run(['gcc', '-std=gnu99', '-Wall', '-Wextra', '-Wno-unused-function', '-g',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
                    f'-I{root/"tests/sim_stubs"}', f'-I{root/"Core/Inc"}', f'-I{root/"Core/Src"}',
                    str(root/'tests/mbscan_sim.c'), str(root/'Core/Src/mbscan_core.c'), '-o', str(exe)], check=True)
    env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'}
    for i in range(1, 14):
        r = subprocess.run([str(exe), str(i)], env=env, capture_output=True, text=True, timeout=600)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr)
            raise SystemExit(f'scenario {i} failed')
print('PASS: mbscan simulation - 13 scenarios')
