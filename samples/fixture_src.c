/* SPDX-License-Identifier: GPL-3.0-or-later
 * A libc-free, self-contained source for deglyph's stripped-binary regression
 * fixtures. It mirrors demo.c's recoverable shapes -- a reflected CRC-16 bit
 * loop, a frame encoder writing immediate header/type bytes, and a command
 * wrapper passing an opcode immediate to a shared sender -- but uses no printf
 * (and an _start entry), so it links freestanding without a libc / sysroot and
 * can be cross-compiled to PE / ELF / Mach-O for the function-recovery tests.
 *
 * Built by build_fixtures.sh; nothing here is committed. The functions are
 * noinline so each is a distinct recoverable start with its own unwind entry.
 */

#include <stdint.h>

/* Reflected CRC-16 (polynomial 0x8408): the shr/xor bit loop the CRC detector
 * recognizes. */
__attribute__((noinline)) static uint16_t crc16(const uint8_t *data, int len) {
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

/* Stand-in for a transport send; the opcode is passed as an immediate. */
__attribute__((noinline)) static void send_frame(int opcode) {
    volatile int sink = opcode;
    (void)sink;
}

/* Writes immediate header/type bytes into a buffer, then a CRC trailer. */
__attribute__((noinline)) static void encode_frame(uint8_t *buf, uint8_t value) {
    buf[0] = 0xAA;
    buf[1] = 0x04;
    buf[2] = value;
    uint16_t c = crc16(buf, 3);
    buf[3] = (uint8_t)(c >> 8);
    buf[4] = (uint8_t)c;
}

/* Command wrapper: builds a frame, then sends opcode 0x2F. */
__attribute__((noinline)) static void set_volume(uint8_t level) {
    uint8_t buf[8];
    encode_frame(buf, level);
    send_frame(0x2F);
}

/* Freestanding entry: no libc, no return-to-loader, so a stripped exe needs no
 * runtime. The infinite loop keeps the linker from demanding an exit path. */
void _start(void) {
    set_volume(12);
    for (;;) {
    }
}
