"""Hardware independent discovery core: build with sanitizers and run the C unit tests."""
from pathlib import Path
import subprocess, tempfile, os
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
    exe = Path(d) / 'mbscan_core'
    subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=undefined', f'-I{root/"Core/Inc"}',
                    str(root / 'tests/mbscan_core_test.c'), str(root / 'Core/Src/mbscan_core.c'),
                    '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
