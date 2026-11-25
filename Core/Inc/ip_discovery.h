#ifndef IP_DISCOVERY_H
#define IP_DISCOVERY_H

#include <stdint.h>
#include "cmsis_os.h"

/* Watch variables: UDP bind state, valid probes, successful send operations,
 * and latest operation status. ERR_OK can include an ignored request.
 */
extern volatile uint32_t discovery_listening;
extern volatile uint32_t discovery_requests;
extern volatile uint32_t discovery_replies;
extern volatile int32_t discovery_last_error;
/* Create the UDP service once after lwIP init; return task handle or NULL. */
osThreadId IPDiscovery_Start(void);

#endif
