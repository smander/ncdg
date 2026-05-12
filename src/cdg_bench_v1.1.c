/*
 * CDG-Bench v1.1 - Synthetic ARM64 Vulnerability Benchmark
 *
 * Changes from v1.0:
 *   - V1 PATCHED: msg_process_alpha now has bounds check on hdr.index
 *   - V2, V3, V4 remain vulnerable
 *   - V5 (UAF) still absent, V6 (overflow) still absent
 *
 * Compile for ARM64:
 *   aarch64-linux-gnu-gcc -O1 -g -fno-inline -o cdg_bench_v11 cdg_bench_v1.1.c
 *
 * Compile for x86_64 (testing):
 *   gcc -O1 -g -fno-inline -o cdg_bench_v11 cdg_bench_v1.1.c
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 * CONFIGURATION TABLES
 * ============================================================ */

#define TABLE_SIZE_ALPHA 32
#define TABLE_SIZE_BETA  32
#define TABLE_SIZE_GAMMA 32
#define MAX_PAYLOAD_LEN  256
#define MSG_HEADER_SIZE  8

typedef struct {
    uint16_t msg_type;
    uint16_t index;
    uint16_t payload_len;
    uint16_t checksum;
} msg_header_t;

typedef struct {
    uint32_t param_a;
    uint32_t param_b;
    uint16_t flags;
    uint16_t priority;
} config_entry_t;

static config_entry_t config_alpha[TABLE_SIZE_ALPHA];
static config_entry_t config_beta[TABLE_SIZE_BETA];
static config_entry_t config_gamma[TABLE_SIZE_GAMMA];

static uint8_t result_buffer[MAX_PAYLOAD_LEN];

/* ============================================================
 * V1: CWE-125 — PATCHED in v1.1
 * Bounds check added before array access.
 * ============================================================ */
int msg_process_alpha(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;

    msg_header_t hdr;
    memcpy(&hdr, raw_msg, sizeof(msg_header_t));

    /* v1.1 FIX: bounds check on hdr.index */
    if (hdr.index >= TABLE_SIZE_ALPHA) return -1;

    config_entry_t *cfg = &config_alpha[hdr.index];

    uint32_t result = cfg->param_a + cfg->param_b;

    if (hdr.payload_len > 0 && hdr.payload_len <= MAX_PAYLOAD_LEN) {
        for (uint16_t i = 0; i < hdr.payload_len && (MSG_HEADER_SIZE + i) < msg_len; i++) {
            result_buffer[i] = raw_msg[MSG_HEADER_SIZE + i] ^ (uint8_t)(cfg->flags);
        }
    }

    return (int)result;
}

/* ============================================================
 * V2: CWE-125 — Still vulnerable in v1.1
 * ============================================================ */
int msg_process_beta(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;

    uint16_t msg_type   = (raw_msg[0] << 8) | raw_msg[1];
    uint16_t index      = (raw_msg[2] << 8) | raw_msg[3];
    uint16_t payload_len = (raw_msg[4] << 8) | raw_msg[5];
    uint16_t checksum   = (raw_msg[6] << 8) | raw_msg[7];

    (void)msg_type; (void)checksum;

    /* V2: No bounds check on index — STILL VULNERABLE */
    config_entry_t entry = config_beta[index];

    uint32_t result = entry.param_a * entry.param_b;

    if (payload_len > 0 && payload_len <= MAX_PAYLOAD_LEN) {
        for (uint16_t i = 0; i < payload_len && (MSG_HEADER_SIZE + i) < msg_len; i++) {
            result_buffer[i] = raw_msg[MSG_HEADER_SIZE + i] + (uint8_t)(entry.priority);
        }
    }

    return (int)(result & 0xFFFF);
}

/* ============================================================
 * V3: CWE-125 — Still vulnerable in v1.1
 * ============================================================ */
int msg_process_gamma(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;

    msg_header_t hdr;
    hdr.msg_type    = *(uint16_t *)(raw_msg + 0);
    hdr.index       = *(uint16_t *)(raw_msg + 2);
    hdr.payload_len = *(uint16_t *)(raw_msg + 4);
    hdr.checksum    = *(uint16_t *)(raw_msg + 6);

    uint32_t temp = hdr.msg_type ^ hdr.checksum;
    temp = (temp << 3) | (temp >> 29);

    /* V3: No bounds check — STILL VULNERABLE */
    config_entry_t *base = config_gamma;
    config_entry_t *cfg = base + hdr.index;

    uint32_t result = cfg->param_a ^ cfg->param_b ^ temp;

    if (hdr.payload_len > 0 && hdr.payload_len <= MAX_PAYLOAD_LEN) {
        size_t copy_len = hdr.payload_len;
        if (MSG_HEADER_SIZE + copy_len > msg_len) {
            copy_len = msg_len - MSG_HEADER_SIZE;
        }
        for (size_t i = 0; i < copy_len; i++) {
            result_buffer[i] = raw_msg[MSG_HEADER_SIZE + i] ^ (uint8_t)result;
        }
    }

    return (int)result;
}

/* ============================================================
 * V4: CWE-787 — Still vulnerable in v1.1
 * ============================================================ */
int buffer_copy(uint8_t *dest, size_t dest_size,
                const uint8_t *src, uint16_t length) {
    if (length == 0) return 0;

    /* Bug: should check length <= dest_size, but doesn't */
    memcpy(dest, src, length);

    return (int)length;
}

/* ============================================================
 * V5: CWE-416 — Still safe in v1.1
 * ============================================================ */
void msg_cleanup(uint8_t *buffer, size_t len) {
    if (buffer != NULL) {
        memset(buffer, 0, len);
        /* v1.1: still safe, no free here */
    }
}

/* ============================================================
 * V6: CWE-190 — Still safe in v1.1
 * ============================================================ */
uint32_t calc_offset(uint16_t base, uint16_t multiplier, uint16_t count) {
    return (uint32_t)base + (uint32_t)multiplier;
}

/* ============================================================
 * POST-PROCESSING
 * ============================================================ */
int post_process(const uint8_t *raw_msg, size_t msg_len, int module_result) {
    if (msg_len < MSG_HEADER_SIZE) return -1;

    uint16_t payload_len = (raw_msg[4] << 8) | raw_msg[5];

    uint8_t output[MAX_PAYLOAD_LEN];

    int copied = buffer_copy(output, sizeof(output),
                             raw_msg + MSG_HEADER_SIZE, payload_len);

    return copied + module_result;
}

/* ============================================================
 * DISPATCH
 * ============================================================ */
int dispatch_message(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;

    uint16_t msg_type = (raw_msg[0] << 8) | raw_msg[1];
    int result = 0;

    switch (msg_type) {
        case 0x0001:
            result = msg_process_alpha(raw_msg, msg_len);
            break;
        case 0x0002:
            result = msg_process_beta(raw_msg, msg_len);
            break;
        case 0x0003:
            result = msg_process_gamma(raw_msg, msg_len);
            break;
        default:
            return -2;
    }

    result = post_process(raw_msg, msg_len, result);
    return result;
}

/* ============================================================
 * INIT
 * ============================================================ */
void init_config(void) {
    for (int i = 0; i < TABLE_SIZE_ALPHA; i++) {
        config_alpha[i].param_a = (uint32_t)(i * 100 + 1);
        config_alpha[i].param_b = (uint32_t)(i * 50 + 2);
        config_alpha[i].flags = (uint16_t)(i & 0xFF);
        config_alpha[i].priority = (uint16_t)(i % 10);
    }
    memcpy(config_beta, config_alpha, sizeof(config_alpha));
    memcpy(config_gamma, config_alpha, sizeof(config_alpha));
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[]) {
    init_config();

    if (argc < 2) {
        printf("CDG-Bench v1.1\n");
        printf("Usage: %s <hex_message>\n", argv[0]);
        printf("Message format: TTTT IIII LLLL CCCC [payload...]\n");
        printf("  TTTT = msg_type (0001=alpha, 0002=beta, 0003=gamma)\n");
        printf("  IIII = config index (V1: patched, V2/V3: trigger if >= 0x0020)\n");
        printf("  LLLL = payload length (V4: trigger if > 0x0100)\n");
        printf("  CCCC = checksum\n");
        return 0;
    }

    const char *hex = argv[1];
    size_t hex_len = strlen(hex);
    size_t msg_len = hex_len / 2;
    uint8_t *msg = (uint8_t *)malloc(msg_len);

    for (size_t i = 0; i < msg_len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        msg[i] = (uint8_t)byte;
    }

    int result = dispatch_message(msg, msg_len);
    printf("Result: %d\n", result);

    msg_cleanup(msg, msg_len);
    free(msg);

    return 0;
}
