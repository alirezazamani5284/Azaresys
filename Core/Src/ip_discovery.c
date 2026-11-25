/*
 * LOCAL IPv4 DISCOVERY SERVICE
 * Broadcast requests arrive on UDP 30303; replies are unicast to the requester.
 * Discovery reports current settings; it does not assign an IP or cross routers.
 */

#include "ip_discovery.h"
#include "network_identity.h"
#include "main.h"
#include "lwip/api.h"
#include "lwip/netifapi.h"
#include "lwip/sys.h"
#include <string.h>

/* Discovery uses its own UDP protocol, independent of Modbus TCP.
 * All sizes below are byte counts; the response layout is fixed at 60 bytes.
 */
#define DISCOVERY_PORT 30303U
#define REQUEST_SIZE 16U
#define RESPONSE_SIZE 60U

/* Live network interface is owned by the lwIP integration.
 * Snapshot access is marshalled synchronously into tcpip_thread.
 */
extern struct netif gnetif;
volatile uint32_t discovery_listening = 0;
volatile uint32_t discovery_requests = 0;
volatile uint32_t discovery_replies = 0;
volatile int32_t discovery_last_error = 0;
static osThreadId discovery_task;
/* Accessed by this task and its synchronous netifapi callback only. */
static uint8_t response[RESPONSE_SIZE];
static uint8_t interface_ready;

/* Write each STM32 UID word in network byte order for deterministic host decoding. */
static void write_u32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

/* Runs in tcpip_thread. The caller waits for the snapshot to complete. */
/* Copy IP, netmask and MAC as bytes in their existing network representation.
 * A response is allowed only when both administrative and physical link flags are up.
 */
static void snapshot_interface(struct netif *netif)
{
    interface_ready = netif_is_up(netif) && netif_is_link_up(netif) &&
        !ip4_addr_isany_val(*netif_ip4_addr(netif));
    memcpy(&response[16], &netif_ip4_addr(netif)->addr, 4);
    memcpy(&response[20], &netif_ip4_netmask(netif)->addr, 4);
    memcpy(&response[24], netif->hwaddr, 6);
}

/* Consumes and deletes received on every path; caller must not free it again.
 * Request: magic[8], nonce[8]. Reply: magic[8], nonce[8], IPv4[4], mask[4],
 * MAC[6], Modbus port[2], UID[12], zero-padded ASCII device name[16].
 * The nonce correlates a response with a scan; it is not authentication.
 * ERR_OK may also mean the request was ignored; discovery_replies counts sends.
 */
static err_t answer_request(struct netconn *connection, struct netbuf *received)
{
    uint8_t request[REQUEST_SIZE + 4U];
    uint16_t request_length = netbuf_len(received);
    ip_addr_t peer;
    uint16_t peer_port = netbuf_fromport(received);
    struct netbuf *reply;
    void *payload;
    err_t status;

    /* Preserve source address and port before releasing the received netbuf. */
    ip_addr_copy(peer, *netbuf_fromaddr(received));
    if ((request_length != REQUEST_SIZE && request_length != REQUEST_SIZE + 4U) ||
        netbuf_copy(received, request, request_length) != request_length ||
        memcmp(request, "F107FIND", 8) != 0 || peer_port == 0)
    {
        netbuf_delete(received);
        return ERR_OK;
    }
    /* Release the receive descriptor before allocating a transmit descriptor. */
    netbuf_delete(received);
    ++discovery_requests;
    /* Optional PC-reported mask; legacy 16-byte requests remain accepted. */
    NetworkIdentity_Discovery(&peer, peer_port,
        request_length == REQUEST_SIZE + 4U ? request + REQUEST_SIZE : NULL);
    memcpy(response, "F107HERE", 8);
    memcpy(&response[8], &request[8], 8);
    status = netifapi_netif_common(&gnetif, snapshot_interface, NULL);
    if (status != ERR_OK || !interface_ready)
        return status;
    response[30] = 0x01;
    response[31] = 0xF6; /* Modbus TCP port 502 in network order. */
    write_u32(&response[32], HAL_GetUIDw0());
    write_u32(&response[36], HAL_GetUIDw1());
    write_u32(&response[40], HAL_GetUIDw2());
    memset(&response[44], 0, 16);
    memcpy(&response[44], "F107-ModbusTCP", sizeof("F107-ModbusTCP") - 1U);

    /* Allocate reply ownership locally and release it after send or allocation failure. */
    reply = netbuf_new();
    if (reply == NULL)
        return ERR_MEM;
    payload = netbuf_alloc(reply, RESPONSE_SIZE);
    if (payload == NULL)
    {
        netbuf_delete(reply);
        return ERR_MEM;
    }
    memcpy(payload, response, RESPONSE_SIZE);
    status = netconn_sendto(connection, reply, &peer, peer_port);
    netbuf_delete(reply);
    if (status == ERR_OK)
        ++discovery_replies;
    return status;
}

/* Dedicated UDP task; listener setup failures are retried after 1000 ms.
 * A 1000 ms receive timeout keeps the listener active without treating idle as error.
 * Rate limiting is global to this task: one successful response per 100 ms.
 * last_reply/have_replied survive listener recreation within this task.
 */
static void discovery_entry(void const *argument)
{
    struct netconn *connection;
    struct netbuf *received;
    err_t status;
    u32_t last_reply = 0;
    uint8_t have_replied = 0;
    (void)argument;

    for (;;)
    {
        connection = netconn_new(NETCONN_UDP);
        if (connection == NULL)
        {
            discovery_last_error = ERR_MEM;
            osDelay(1000);
            continue;
        }
        status = netconn_bind(connection, IP_ADDR_ANY, DISCOVERY_PORT);
        discovery_last_error = status;
        discovery_listening = (status == ERR_OK);
        if (status == ERR_OK)
        {
            netconn_set_recvtimeout(connection, 1000);
            for (;;)
            {
                status = netconn_recv(connection, &received);
                if (status == ERR_TIMEOUT)
                    continue;
                if (status != ERR_OK)
                {
                    discovery_last_error = status;
                    break;
                }
                if (have_replied && (u32_t)(sys_now() - last_reply) < 100U)
                {
                    netbuf_delete(received);
                    continue;
                }
                {
                    uint32_t previous_replies = discovery_replies;
                    discovery_last_error = answer_request(connection, received);
                    if (discovery_replies != previous_replies)
                    {
                        last_reply = sys_now();
                        have_replied = 1;
                    }
                }
            }
        }
        discovery_listening = 0;
        netconn_delete(connection);
        osDelay(1000);
    }
}

/* Start once after the network stack is initialized.
 * Below-normal priority and 512 stack words are the existing task settings.
 */
osThreadId IPDiscovery_Start(void)
{
    if (discovery_task == NULL)
    {
        osThreadDef(IPDiscovery, discovery_entry, osPriorityBelowNormal, 0, 512);
        discovery_task = osThreadCreate(osThread(IPDiscovery), NULL);
    }
    return discovery_task;
}
