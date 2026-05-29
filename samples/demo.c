// SPDX-License-Identifier: GPL-3.0-or-later
// A tiny, domain-neutral sample binary for deglyph demos and screenshots. It is
// written to exercise the detectors: a branchless CRC-16 bit loop, a frame
// encoder that writes immediate header/type bytes, and a command wrapper that
// passes an opcode immediate to a shared sender. The fake API key demonstrates
// the defensive use case (finding secrets baked into a shipped binary).
//
// Build (mingw):  gcc -O0 -fno-inline -o demo.exe demo.c

#include <stdint.h>
#include <stdio.h>

static const char API_KEY[] = "S3cr3t-demo-API-key-do-not-ship";

// Branchless reflected CRC-16 (polynomial 0x8408); the shr/xor bit loop is what
// the CRC detector recognizes.
__attribute__((noinline)) uint16_t crc16(const uint8_t *data, int len) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint16_t mask = (uint16_t)-(crc & 1);
            crc = (uint16_t)((crc >> 1) ^ (0x8408 & mask));
        }
    }
    return crc;
}

__attribute__((noinline)) void send_frame(int opcode, const uint8_t *payload,
                                           int len) {
    printf("send opcode=%#x len=%d\n", opcode, len);
}

__attribute__((noinline)) void encode_frame(uint8_t *buf, uint8_t value) {
    buf[0] = 0xAA;  // header magic
    buf[1] = 0x04;  // frame type
    buf[2] = value;
    uint16_t c = crc16(buf, 3);
    buf[3] = (uint8_t)(c >> 8);
    buf[4] = (uint8_t)c;
}

__attribute__((noinline)) void set_volume(uint8_t level) {
    uint8_t buf[8];
    encode_frame(buf, level);
    send_frame(0x2F, buf, 5);  // 0x2F passed as the opcode immediate
}

int main(void) {
    set_volume(12);
    printf("key tag: %c\n", API_KEY[0]);
    return 0;
}
