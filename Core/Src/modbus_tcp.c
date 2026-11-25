/*
 * MODBUS TCP SERVER
 * Scope: a single-client Netconn server with FC03/FC06 and 16 RAM registers, plus FC04 network identity.
 * No register is connected to a physical sensor or output in this version.
 */

#include "modbus_tcp.h"
#include "network_identity.h"
#include "lwip/api.h"
#include "lwip/sys.h"

/* Protocol constants: TCP listener port, accepted Unit ID, and maximum ADU bytes. */
#define MODBUS_PORT 502U
#define MODBUS_UNIT 1U
#define MODBUS_ADU_MAX 260U

/* RAM register bank: addresses 0..15; reset values 100, 200, 300, then zeros.
 * Only the server task writes this bank in the current application.
 * volatile supports debugger visibility; it does not provide task synchronization.
 */
volatile uint16_t modbus_holding[MODBUS_REGISTER_COUNT] = {100U, 200U, 300U};
volatile uint32_t modbus_requests = 0;
volatile uint32_t modbus_listening = 0;
/* Error stages: 1 receive, 2 buffer access, 3 parse/send. */
volatile int32_t modbus_last_error = 0;
volatile uint32_t modbus_error_stage = 0;
volatile uint32_t modbus_rx_bytes = 0;
volatile uint32_t modbus_responses = 0;
static osThreadId server_task;

/* Decode one unsigned 16-bit wire field. Caller provides two readable bytes. */
static uint16_t read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

/* Encode one unsigned 16-bit field, most significant byte first. */
static void write_u16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

/* Build the response in place after capturing the request parameters. */
/* Precondition: consume_bytes has assembled and validated the complete MBAP frame.
 * adu is writable and has MODBUS_ADU_MAX bytes of capacity.
 * Return response length in bytes, or zero for a different Unit ID.
 * FC03 reads holding registers; FC06 stores one register and echoes the request.
 * Exception codes: 01 unsupported function, 02 invalid address, 03 invalid value.
 * Transaction ID, protocol ID and Unit ID remain from the original request.
 */
static uint16_t make_response(uint8_t *adu, uint16_t size)
{
    uint8_t function = adu[7];
    uint8_t exception = 0;
    uint16_t address;
    uint16_t value;
    uint16_t index;
    uint16_t network_words[NETWORK_REGISTER_COUNT];

    /* Requests for another Unit ID are counted but receive no response. */
    if (adu[6] != MODBUS_UNIT)
        return 0;

    if (function != 3U && function != 4U && function != 6U)
        exception = 1U;
    else if (size != 12U)
        exception = 3U;
    else
    {
        address = read_u16(&adu[8]);
        value = read_u16(&adu[10]);
        if (function == 3U && (value == 0U || value > 125U))
            exception = 3U;
        else if (function == 4U)
        {
            if (value == 0U || value > 125U)
                exception = 3U;
            else if (address >= NETWORK_REGISTER_COUNT ||
                     value > NETWORK_REGISTER_COUNT - address)
                exception = 2U;
            else if (!NetworkIdentity_ReadRegisters(network_words))
                exception = 4U;
            else
            {
                adu[8] = (uint8_t)(2U * value);
                for (index = 0; index < value; ++index)
                    write_u16(&adu[9U + 2U * index], network_words[address + index]);
                write_u16(&adu[4], (uint16_t)(3U + 2U * value));
                return (uint16_t)(9U + 2U * value);
            }
        }
        else if (address >= MODBUS_REGISTER_COUNT)
            exception = 2U;
        else if (function == 3U && value > MODBUS_REGISTER_COUNT - address)
            exception = 2U;
        else if (function == 6U)
        {
            modbus_holding[address] = value;
            return 12U;
        }
        else
        {
            /* FC03 replaces the request payload after address/count have been captured.
             * MBAP length includes Unit ID; total ADU length includes the six-byte prefix.
             */
            adu[8] = (uint8_t)(2U * value);
            for (index = 0; index < value; ++index)
                write_u16(&adu[9U + 2U * index], modbus_holding[address + index]);
            write_u16(&adu[4], (uint16_t)(3U + 2U * value));
            return (uint16_t)(9U + 2U * value);
        }
    }

    adu[7] = (uint8_t)(function | 0x80U);
    adu[8] = exception;
    write_u16(&adu[4], 3U);
    return 9U;
}

/* lwIP 2.0.3 requires bytes_written when a send timeout is enabled. */
/* Task context; an overall 3000 ms budget covers all partial writes.
 * NETCONN_COPY lets lwIP copy the bytes before the request buffer is reused.
 * Unsigned subtraction tolerates the millisecond counter wrapping.
 */
static err_t send_response(struct netconn *client, const uint8_t *data,
                           uint16_t length)
{
    size_t offset = 0;
    size_t written;
    u32_t started = sys_now();
    u32_t elapsed;
    err_t status;

    while (offset < length)
    {
        elapsed = sys_now() - started;
        if (elapsed >= 3000U)
            return ERR_TIMEOUT;
        netconn_set_sendtimeout(client, (s32_t)(3000U - elapsed));
        written = 0;
        status = netconn_write_partly(client, data + offset,
                                      length - offset, NETCONN_COPY, &written);
        if (status != ERR_OK)
            return status;
        if (written == 0)
            return ERR_TIMEOUT;
        offset += written;
    }
    return ERR_OK;
}

/* TCP may split one ADU or combine several ADUs in one receive. */
/* Stream parser state: adu and used persist across netconn_recv calls.
 * The six-byte prefix carries protocol ID and remaining length.
 * A valid length of 2..254 bounds the full ADU to at most 260 bytes.
 * Each completed request resets used, allowing multiple ADUs per TCP chunk.
 * Invalid framing returns an error; serve_client then releases the connection.
 */
static err_t consume_bytes(struct netconn *client, uint8_t *adu,
                           uint16_t *used, const uint8_t *data, uint16_t count)
{
    uint16_t index;
    uint16_t length;
    uint16_t response_size;
    err_t status;

    for (index = 0; index < count; ++index)
    {
        adu[(*used)++] = data[index];
        if (*used < 6U)
            continue;

        length = read_u16(&adu[4]);
        if (read_u16(&adu[2]) != 0U || length < 2U || length > 254U)
            return ERR_VAL;

        if (*used == (uint16_t)(6U + length))
        {
            response_size = make_response(adu, *used);
            ++modbus_requests;
            if (response_size != 0U)
            {
                status = send_response(client, adu, response_size);
                if (status != ERR_OK)
                    return status;
                ++modbus_responses;
            }
            *used = 0;
        }
    }
    return ERR_OK;
}

/* Owns one accepted connection during receive/parse/send processing.
 * Idle receive timeout: 10000 ms. Partial request state lives on this task stack.
 * Each successfully received netbuf is deleted, including parser error paths.
 * The caller closes and deletes the netconn after this function returns.
 */
static void serve_client(struct netconn *client)
{
    uint8_t adu[MODBUS_ADU_MAX];
    uint16_t used = 0;
    struct netbuf *buffer;
    void *data;
    u16_t count;
    err_t status;

    modbus_last_error = 0;
    modbus_error_stage = 0;
    modbus_rx_bytes = 0;
    netconn_set_recvtimeout(client, 10000);
    netconn_set_sendtimeout(client, 3000);
    for (;;)
    {
        status = netconn_recv(client, &buffer);
        if (status != ERR_OK)
        {
            modbus_last_error = status;
            modbus_error_stage = 1;
            return;
        }
        /* A netbuf can contain several chained payload segments; consume every segment. */
        do
        {
            status = netbuf_data(buffer, &data, &count);
            if (status != ERR_OK)
            {
                modbus_error_stage = 2;
                break;
            }
            NetworkIdentity_ClientActivity();
            modbus_rx_bytes += count;
            status = consume_bytes(client, adu, &used, data, count);
            if (status != ERR_OK)
            {
                modbus_error_stage = 3;
                break;
            }
        } while (netbuf_next(buffer) >= 0);
        netbuf_delete(buffer);
        if (status != ERR_OK)
        {
            modbus_last_error = status;
            return;
        }
    }
}

/* Persistent listener task: allocation/bind/accept failures trigger a 1000 ms retry.
 * Clients are handled sequentially; this is not a concurrent multi-client server.
 * modbus_listening reports listener setup, not end-to-end network health.
 */
static void server_entry(void const *argument)
{
    struct netconn *listener;
    struct netconn *client;
    err_t status;
    (void)argument;

    for (;;)
    {
        listener = netconn_new(NETCONN_TCP);
        if (listener == NULL)
        {
            osDelay(1000);
            continue;
        }
        status = netconn_bind(listener, IP_ADDR_ANY, MODBUS_PORT);
        if (status == ERR_OK)
            status = netconn_listen(listener);
        modbus_listening = (status == ERR_OK);
        while (status == ERR_OK)
        {
            status = netconn_accept(listener, &client);
            if (status == ERR_OK)
            {
                NetworkIdentity_ClientOpen(client);
                serve_client(client);
                NetworkIdentity_ClientClose();
                netconn_close(client);
                netconn_delete(client);
            }
        }
        modbus_listening = 0;
        netconn_delete(listener);
        osDelay(1000);
    }
}

/* Start once after MX_LWIP_Init. Return the existing task on later calls.
 * The CMSIS-RTOS v1 FreeRTOS adapter uses 512 stack words (2048 bytes here).
 */
osThreadId ModbusTCP_Start(void)
{
    if (server_task == NULL)
    {
        osThreadDef(ModbusTCP, server_entry, osPriorityNormal, 0, 512);
        server_task = osThreadCreate(osThread(ModbusTCP), NULL);
    }
    return server_task;
}
