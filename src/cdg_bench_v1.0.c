/*
 * CDG-Bench v1.0 - Synthetic ARM64 Vulnerability Benchmark
 * 
 * Purpose: Controlled test target for Constraint Dependency Graph research.
 * Each vulnerability is documented with its CWE class and exact location.
 * 
 * Structure:
 *   - Three parallel message processing modules (alpha, beta, gamma)
 *   - Each contains CWE-125 (OOB Read) via unchecked index
 *   - Shared buffer_copy with CWE-787 (OOB Write) via unchecked length
 *   - calc_offset with CWE-190 (Integer Overflow) 
 *   - msg_cleanup with CWE-416 (Use-After-Free) [absent in v1.0, introduced v1.2]
 *
 * Compile for ARM64:
 *   aarch64-linux-gnu-gcc -O1 -g -fno-inline -o cdg_bench cdg_bench.c
 * 
 * Compile for x86_64 (testing):
 *   gcc -O1 -g -fno-inline -o cdg_bench cdg_bench.c
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 * CONFIGURATION TABLES
 * Each module has its own config table of fixed size.
 * The vulnerability: index into table is read from message
 * without bounds checking.
 * ============================================================ */

#define TABLE_SIZE_ALPHA 32
#define TABLE_SIZE_BETA  32
#define TABLE_SIZE_GAMMA 32
#define MAX_PAYLOAD_LEN  256
#define MSG_HEADER_SIZE  8

typedef struct {
    uint16_t msg_type;     /* bytes 0-1: message type */
    uint16_t index;        /* bytes 2-3: config table index -- THE CRITICAL FIELD */
    uint16_t payload_len;  /* bytes 4-5: payload length */
    uint16_t checksum;     /* bytes 6-7: simple checksum */
} msg_header_t;

typedef struct {
    uint32_t param_a;
    uint32_t param_b;
    uint16_t flags;
    uint16_t priority;
} config_entry_t;

/* Global config tables */
static config_entry_t config_alpha[TABLE_SIZE_ALPHA];
static config_entry_t config_beta[TABLE_SIZE_BETA];
static config_entry_t config_gamma[TABLE_SIZE_GAMMA];

/* Result buffer */
static uint8_t result_buffer[MAX_PAYLOAD_LEN];

/* ============================================================
 * VULNERABILITY V1: CWE-125 (Out-of-Bounds Read)
 * Location: msg_process_alpha
 * Trigger: msg_header.index >= TABLE_SIZE_ALPHA
 * Constraint: index >= 32
 * 
 * The index field from the message header is used directly
 * to access config_alpha[] without bounds checking.
 * ============================================================ */
int msg_process_alpha(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;
    
    msg_header_t hdr;
    memcpy(&hdr, raw_msg, sizeof(msg_header_t));
    
    /* V1: No bounds check on hdr.index before array access */
    /* VULNERABILITY: if hdr.index >= TABLE_SIZE_ALPHA, OOB read */
    config_entry_t *cfg = &config_alpha[hdr.index];  /* <-- V1 HERE */
    
    /* Use the config to process payload */
    uint32_t result = cfg->param_a + cfg->param_b;
    
    if (hdr.payload_len > 0 && hdr.payload_len <= MAX_PAYLOAD_LEN) {
        /* Process payload with config parameters */
        for (uint16_t i = 0; i < hdr.payload_len && (MSG_HEADER_SIZE + i) < msg_len; i++) {
            result_buffer[i] = raw_msg[MSG_HEADER_SIZE + i] ^ (uint8_t)(cfg->flags);
        }
    }
    
    return (int)result;
}

/* ============================================================
 * VULNERABILITY V2: CWE-125 (Out-of-Bounds Read)
 * Location: msg_process_beta
 * Trigger: msg_header.index >= TABLE_SIZE_BETA
 * Constraint: index >= 32 (SAME logical constraint as V1)
 * 
 * Structurally identical to V1 but:
 *   - Different config table (config_beta)
 *   - Different processing logic (multiplication vs addition)
 *   - Different register allocation at ARM64 level
 * ============================================================ */
int msg_process_beta(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;
    
    /* Parse header differently: read fields individually */
    uint16_t msg_type   = (raw_msg[0] << 8) | raw_msg[1];
    uint16_t index      = (raw_msg[2] << 8) | raw_msg[3];
    uint16_t payload_len = (raw_msg[4] << 8) | raw_msg[5];
    uint16_t checksum   = (raw_msg[6] << 8) | raw_msg[7];
    
    (void)msg_type; (void)checksum;
    
    /* V2: No bounds check on index before array access */
    /* VULNERABILITY: if index >= TABLE_SIZE_BETA, OOB read */
    config_entry_t entry = config_beta[index];  /* <-- V2 HERE */
    
    /* Different processing: multiplication instead of addition */
    uint32_t result = entry.param_a * entry.param_b;
    
    if (payload_len > 0 && payload_len <= MAX_PAYLOAD_LEN) {
        for (uint16_t i = 0; i < payload_len && (MSG_HEADER_SIZE + i) < msg_len; i++) {
            result_buffer[i] = raw_msg[MSG_HEADER_SIZE + i] + (uint8_t)(entry.priority);
        }
    }
    
    return (int)(result & 0xFFFF);
}

/* ============================================================
 * VULNERABILITY V3: CWE-125 (Out-of-Bounds Read)
 * Location: msg_process_gamma
 * Trigger: msg_header.index >= TABLE_SIZE_GAMMA
 * Constraint: index >= 32 (SAME logical constraint as V1, V2)
 * 
 * Third variant: uses pointer arithmetic instead of array syntax,
 * has additional (irrelevant) logic before the access.
 * At ARM64 level: completely different instruction sequence,
 * but produces the SAME Z3 constraint.
 * ============================================================ */
int msg_process_gamma(const uint8_t *raw_msg, size_t msg_len) {
    if (msg_len < MSG_HEADER_SIZE) return -1;
    
    msg_header_t hdr;
    hdr.msg_type    = *(uint16_t *)(raw_msg + 0);
    hdr.index       = *(uint16_t *)(raw_msg + 2);
    hdr.payload_len = *(uint16_t *)(raw_msg + 4);
    hdr.checksum    = *(uint16_t *)(raw_msg + 6);
    
    /* Some irrelevant computation before the vulnerable access */
    uint32_t temp = hdr.msg_type ^ hdr.checksum;
    temp = (temp << 3) | (temp >> 29);
    
    /* V3: No bounds check on hdr.index */
    /* VULNERABILITY: pointer arithmetic, same logical bug */
    config_entry_t *base = config_gamma;
    config_entry_t *cfg = base + hdr.index;  /* <-- V3 HERE */
    
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
 * VULNERABILITY V4: CWE-787 (Out-of-Bounds Write)
 * Location: buffer_copy (shared utility)
 * Trigger: length > sizeof(dest_buffer)
 * Constraint: len > MAX_PAYLOAD_LEN
 * 
 * Called by all three modules' post-processing.
 * The length field is taken from the message without adequate
 * validation against the destination buffer size.
 * ============================================================ */
int buffer_copy(uint8_t *dest, size_t dest_size,
                const uint8_t *src, uint16_t length) {
    /* V4: Insufficient bounds check -- uses length from message */
    /* VULNERABILITY: if length > dest_size, heap/stack overflow */
    if (length == 0) return 0;
    
    /* Bug: should check length <= dest_size, but doesn't */
    memcpy(dest, src, length);  /* <-- V4 HERE */
    
    return (int)length;
}

/* ============================================================
 * VULNERABILITY V5: CWE-416 (Use-After-Free)
 * Location: msg_cleanup
 * Status in v1.0: ABSENT (this function is safe in v1.0)
 * Introduced in v1.2 when refactoring adds a double-use pattern.
 * ============================================================ */
void msg_cleanup(uint8_t *buffer, size_t len) {
    if (buffer != NULL) {
        memset(buffer, 0, len);
        /* v1.0: NO free here -- safe */
        /* v1.2 will add: free(buffer); and then use buffer again */
    }
}

/* ============================================================
 * VULNERABILITY V6: CWE-190 (Integer Overflow)
 * Location: calc_offset
 * Status in v1.0: ABSENT
 * Introduced in v1.3 when adding offset calculation.
 * ============================================================ */
uint32_t calc_offset(uint16_t base, uint16_t multiplier, uint16_t count) {
    /* v1.0: Simple, safe calculation */
    return (uint32_t)base + (uint32_t)multiplier;
    /* v1.3 will change to: return base * multiplier * count; 
     * which overflows uint16_t intermediate results */
}

/* ============================================================
 * POST-PROCESSING: calls buffer_copy (potentially vulnerable)
 * ============================================================ */
int post_process(const uint8_t *raw_msg, size_t msg_len, int module_result) {
    if (msg_len < MSG_HEADER_SIZE) return -1;
    
    uint16_t payload_len = (raw_msg[4] << 8) | raw_msg[5];
    
    uint8_t output[MAX_PAYLOAD_LEN];
    
    /* V4 triggered here: payload_len comes from untrusted message */
    int copied = buffer_copy(output, sizeof(output), 
                             raw_msg + MSG_HEADER_SIZE, payload_len);
    
    return copied + module_result;
}

/* ============================================================
 * DISPATCH: route message to appropriate module
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
            return -2;  /* Unknown message type */
    }
    
    result = post_process(raw_msg, msg_len, result);
    return result;
}

/* ============================================================
 * INIT: populate config tables
 * ============================================================ */
void init_config(void) {
    for (int i = 0; i < TABLE_SIZE_ALPHA; i++) {
        config_alpha[i].param_a = (uint32_t)(i * 100 + 1);
        config_alpha[i].param_b = (uint32_t)(i * 50 + 2);
        config_alpha[i].flags = (uint16_t)(i & 0xFF);
        config_alpha[i].priority = (uint16_t)(i % 10);
    }
    /* Same pattern for beta and gamma */
    memcpy(config_beta, config_alpha, sizeof(config_alpha));
    memcpy(config_gamma, config_alpha, sizeof(config_alpha));
}

/* ============================================================
 * MAIN: simple test driver
 * ============================================================ */
int main(int argc, char *argv[]) {
    init_config();
    
    if (argc < 2) {
        printf("CDG-Bench v1.0\n");
        printf("Usage: %s <hex_message>\n", argv[0]);
        printf("Message format: TTTT IIII LLLL CCCC [payload...]\n");
        printf("  TTTT = msg_type (0001=alpha, 0002=beta, 0003=gamma)\n");
        printf("  IIII = config index (V1/V2/V3: trigger if >= 0x0020)\n");
        printf("  LLLL = payload length (V4: trigger if > 0x0100)\n");
        printf("  CCCC = checksum\n");
        return 0;
    }
    
    /* Parse hex input */
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
