/* dm_probe.c — DIAG/DM surface canary for ZTE MF286D modem.
 * Opens a tty, sends one HDLC-framed DIAG_VERNO_F (cmd 0x00) query,
 * reads any response frame with timeout. Read-only protocol probe:
 * no flash access, no NV writes, no state change on the modem.
 * Static build: arm-linux-gnueabihf-gcc -O2 -static -o dm_probe dm_probe.c
 * Usage: dm_probe /dev/ttyUSB0 [baud, default 115200]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/select.h>

static unsigned short crc16(const unsigned char *d, int len) {
    unsigned long crc = 0xFFFFFFFFUL;
    for (int i = 0; i < len; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0x8408UL * (crc & 1));
    }
    return (unsigned short)(crc & 0xFFFF);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s /dev/ttyX [baud]\n", argv[0]); return 2; }
    int baud = argc > 2 ? atoi(argv[2]) : 115200;
    int fd = open(argv[1], O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { perror("open"); return 1; }
    struct termios t;
    if (tcgetattr(fd, &t) == 0) {
        cfmakeraw(&t);
        speed_t sp = baud == 921600 ? B921600 : baud == 460800 ? B460800 :
                     baud == 230400 ? B230400 : B115200;
        cfsetispeed(&t, sp); cfsetospeed(&t, sp);
        t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
        tcsetattr(fd, TCSANOW, &t);
        tcflush(fd, TCIOFLUSH);
    }
    unsigned char payload[] = { 0x00 };            /* DIAG_VERNO_F */
    unsigned short c = crc16(payload, 1);
    unsigned char frame[8] = { 0x7E, payload[0], c & 0xFF, (c >> 8) & 0xFF, 0x7E };
    printf("TX (%d bytes):", 5);
    for (int i = 0; i < 5; i++) printf(" %02X", frame[i]);
    printf("\n");
    ssize_t n = write(fd, frame, 5);
    if (n != 5) { perror("write"); close(fd); return 1; }
    tcdrain(fd);
    /* read up to 512 bytes for up to 3s */
    unsigned char buf[512]; int total = 0;
    for (int round = 0; round < 30 && total < (int)sizeof(buf); round++) {
        struct timeval tv = { 0, 100 * 1000 };
        fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
        if (select(fd + 1, &rf, NULL, NULL, &tv) > 0) {
            n = read(fd, buf + total, sizeof(buf) - total);
            if (n > 0) total += n;
            else if (n == 0) break;
        }
        if (total > 0) { /* got data; one more quiet 200ms then stop */
            struct timeval tv2 = { 0, 200 * 1000 };
            fd_set rf2; FD_ZERO(&rf2); FD_SET(fd, &rf2);
            if (select(fd + 1, &rf2, NULL, NULL, &tv2) > 0) {
                n = read(fd, buf + total, sizeof(buf) - total);
                if (n > 0) total += n;
            }
            if (total > 0) break;
        }
    }
    if (total == 0) { printf("RX: no response in 3s — port mute (or not DM)\n"); close(fd); return 1; }
    printf("RX (%d bytes):", total);
    for (int i = 0; i < total && i < 64; i++) printf(" %02X", buf[i]);
    printf("%s\n", total > 64 ? " …" : "");
    int has7e = 0;
    for (int i = 0; i < total; i++) if (buf[i] == 0x7E) has7e = 1;
    printf(has7e ? "VERDICT: DM surface ALIVE (0x7E framing seen)\n"
                 : "VERDICT: bytes returned but no HDLC framing — unknown protocol\n");
    close(fd);
    return has7e ? 0 : 1;
}
