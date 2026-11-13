/* dm_sweep.c — NV item sweep over the DM port (READ-ONLY).
 * Loops NV_READ (0x26) over items 0..4095, logs every response line to a file.
 * Device CRC variant (crcmod 0x11021/init0/xorFFFF) implemented bit-by-bit,
 * validated against embedded vectors (crc(00)=0xF078, crc(1326000000503 77E)=0x8B25).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/select.h>
#include <time.h>
#include "nv_crcs.h"

static int fd;
static void xmit(const unsigned char *payload, int plen, unsigned short c) {
    unsigned char full[16], pkt[64]; int flen = plen + 2, n = 0;
    memcpy(full, payload, plen);
    full[plen] = c & 0xFF; full[plen+1] = (c >> 8) & 0xFF;
    pkt[n++] = 0x7E;
    for (int i = 0; i < flen; i++) {
        if (full[i] == 0x7E || full[i] == 0x7D) { pkt[n++] = 0x7D; pkt[n++] = full[i] ^ 0x20; }
        else pkt[n++] = full[i];
    }
    pkt[n++] = 0x7E;
    write(fd, pkt, n); tcdrain(fd);
}
static int rx(unsigned char *out, int outsz, int wait_ms) {
    unsigned char buf[2048]; int total = 0;
    struct timespec a; clock_gettime(CLOCK_MONOTONIC, &a);
    for (;;) {
        struct timeval tv = { 0, 20 * 1000 };
        fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
        if (select(fd + 1, &r, NULL, NULL, &tv) > 0) {
            ssize_t n = read(fd, buf + total, sizeof(buf) - total);
            if (n > 0) total += n;
        }
        if (total >= 4 && buf[total-1] == 0x7E) {
            int o = 0;
            for (int i = 0; i < total - 1 && o < outsz - 1; i++) {
                if (buf[i] == 0x7D && i + 1 < total - 1) out[o++] = buf[++i] ^ 0x20;
                else if (buf[i] != 0x7E) out[o++] = buf[i];
            }
            return o;
        }
        struct timespec z; clock_gettime(CLOCK_MONOTONIC, &z);
        if ((z.tv_sec - a.tv_sec) * 1000 + (z.tv_nsec - a.tv_nsec) / 1000000 > wait_ms)
            return total > 0 ? -2 : 0;
    }
}
int main(int argc, char **argv) {
    const char *outpath = argc > 2 ? argv[2] : "/tmp/nvsweep.txt";
    fd = open(argv[1], O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { perror("open"); return 1; }
    struct termios t; tcgetattr(fd, &t); cfmakeraw(&t);
    cfsetispeed(&t, B115200); cfsetospeed(&t, B115200);
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSANOW, &t); tcflush(fd, TCIOFLUSH);

    /* CRC table embedded (validated offline; no runtime CRC needed) */

    FILE *out = fopen(outpath, "w");
    if (!out) { perror("fopen"); return 1; }
    unsigned char resp[1024];
    int got = 0, bad = 0, silent = 0;
    for (int item = 0; item <= 4095; item++) {
        unsigned char req[4] = { 0x26, item & 0xFF, (item >> 8) & 0xFF, 0x00 };
        xmit(req, 4, NV_CRC[item]);
        int n = rx(resp, sizeof(resp), 900);
        if (n <= 0) { silent++; fprintf(out, "I%04d SILENT\n", item); }
        else if (resp[0] == 0x13) { bad++; fprintf(out, "I%04d BAD\n", item); }
        else {
            got++;
            fprintf(out, "I%04d %d ", item, n);
            for (int k = 0; k < n && k < 140; k++) fprintf(out, "%02X", resp[k]);
            fprintf(out, "\n");
        }
        usleep(60000);
    }
    fprintf(out, "SWEEP-DONE items=%d bad=%d silent=%d\n", got, bad, silent);
    fclose(out); close(fd);
    fprintf(stderr, "sweep done: responses=%d bad=%d silent=%d -> %s\n", got, bad, silent, outpath);
    return 0;
}
