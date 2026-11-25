#ifndef MODBUS_TCP_H
#define MODBUS_TCP_H

#include <stdint.h>
#include "cmsis_os.h"

/* Register addresses are zero-based: 0..15 (commonly shown as 40001..40016). */
#define MODBUS_REGISTER_COUNT 16U

/* Public diagnostic/register symbols; no persistent storage or sensor mapping.
 * requests counts complete ADUs, including ignored Unit IDs.
 * responses counts successful send_response completions, not remote acknowledgements.
 * last_error/error_stage/rx_bytes reset at the beginning of each accepted client.
 * error_stage: 0 none yet, 1 receive, 2 netbuf access, 3 parse/send.
 */
extern volatile uint16_t modbus_holding[MODBUS_REGISTER_COUNT];
extern volatile uint32_t modbus_requests;
extern volatile uint32_t modbus_listening;
extern volatile int32_t modbus_last_error;
extern volatile uint32_t modbus_error_stage;
extern volatile uint32_t modbus_rx_bytes;
extern volatile uint32_t modbus_responses;
/* Idempotent startup; NULL reports task creation failure. Call after lwIP init. */
osThreadId ModbusTCP_Start(void);

#endif
