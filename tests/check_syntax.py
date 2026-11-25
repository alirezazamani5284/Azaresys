from pathlib import Path
import subprocess,tempfile,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1];proj=root/'MDK-ARM/F107_ModbusTCP.uvprojx';tree=ET.parse(proj)
inc=tree.find('.//Cads/VariousControls/IncludePath').text
includes=['-I'+str((proj.parent/x.replace('\\','/')).resolve()) for x in inc.split(';')]
defs=['-D'+x.strip() for x in tree.find('.//Cads/VariousControls/Define').text.split(',') if x.strip()]
# Only replace CPU/assembly declarations for host syntax checking, not application code.
shim='''
#ifndef PORTMACRO_H
#define PORTMACRO_H
#include <stdint.h>
typedef uint32_t StackType_t;
typedef int32_t BaseType_t;
typedef uint32_t UBaseType_t;
typedef uint32_t TickType_t;
#define portSTACK_TYPE uint32_t
#define portBASE_TYPE int32_t
#define portMAX_DELAY 0xffffffffUL
#define portTICK_PERIOD_MS 1
#define portBYTE_ALIGNMENT 8
#define portSTACK_GROWTH (-1)
#define portCRITICAL_NESTING_IN_TCB 0
#define portTICK_TYPE_IS_ATOMIC 1
#define portYIELD() ((void)0)
#define portDISABLE_INTERRUPTS() ((void)0)
#define portENABLE_INTERRUPTS() ((void)0)
#define portENTER_CRITICAL() ((void)0)
#define portEXIT_CRITICAL() ((void)0)
#define portSET_INTERRUPT_MASK_FROM_ISR() 0
#define portCLEAR_INTERRUPT_MASK_FROM_ISR(x) ((void)(x))
#endif
'''
with tempfile.TemporaryDirectory() as d:
    Path(d,'portmacro.h').write_text(shim)
    for name in ['Core/Src/network_identity','Core/Src/network_observer_core','Core/Src/network_observer','Core/Src/modbus_tcp','Core/Src/ip_discovery','Core/Src/freertos','LWIP/Target/ethernetif','LWIP/App/lwip']:
        p=root/f'{name}.c'
        r=subprocess.run(['gcc','-std=c99','-fsyntax-only','-Werror=implicit-function-declaration','-I'+d,*defs,*includes,str(p)],capture_output=True,text=True)
        if r.returncode:print(name,r.stderr);raise SystemExit(1)
    print('PASS: host syntax checks of 8 changed modules (CPU-port declarations stubbed)')
