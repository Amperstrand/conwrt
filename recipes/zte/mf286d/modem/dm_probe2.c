/* dm_probe2.c — corrected-CRC DM probe matrix (device CRC variant validated
 * offline via crcmod 0x11021/init0/xorFFFF; CRCs precomputed and embedded).
 * Read-only: version/status/subsystem queries + NV_READ only. No writes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/select.h>
#include <time.h>

static int fd;
typedef struct { const char *name; unsigned char payload[8]; int plen; unsigned short crc; } probe_t;
static probe_t probes[] = {
    { "VERNO(devCRC)",      { 0x00 },                        1, 0xF078 },
    { "STATUS",             { 0x0C },                        1, 0x3A14 },
    { "DIAG_VER",           { 0x1C },                        1, 0x2A95 },
    { "EXT_BUILD",          { 0x7C },                        1, 0x4993 },
    { "SUBSYS_0F",          { 0x4B, 0x0F },                  2, 0x557E },
    { "SUBSYS_46",          { 0x4B, 0x46 },                  2, 0x8ABB },
    { "NV_READ_0(4b)",      { 0x26, 0x00, 0x00, 0x00 },      4, 0x3817 },
    { "NV_550_IMEI",        { 0x26, 0x26, 0x02, 0x00 },      4, 0xDE45 },
    { "NV_219",             { 0x26, 0xDB, 0x00, 0x00 },      4, 0x9EBE },
    { "NV_178",             { 0x26, 0xB2, 0x00, 0x00 },      4, 0x07ED },
    { "NV_298",             { 0x26, 0x2A, 0x01, 0x00 },      4, 0x518E },
};
static void xmit(probe_t *p) {
    unsigned char pkt[64]; int n = 0;
    unsigned char full[12]; memcpy(full, p->payload, p->plen);
    full[p->plen] = p->crc & 0xFF; full[p->plen+1] = (p->crc >> 8) & 0xFF;
    int flen = p->plen + 2;
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
        struct timeval tv = { 0, 50 * 1000 };
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
    fd = open(argv[1], O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { perror("open"); return 1; }
    struct termios t; tcgetattr(fd, &t); cfmakeraw(&t);
    cfsetispeed(&t, B115200); cfsetospeed(&t, B115200);
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSANOW, &t); tcflush(fd, TCIOFLUSH);
    unsigned char resp[1024];
    for (unsigned i = 0; i < sizeof(probes)/sizeof(probes[0]); i++) {
        probe_t *p = &probes[i];
        xmit(p);
        int n = rx(resp, sizeof(resp), 2500);
        if (n <= 0) { printf("%-18s -> %s (%d)\n", p->name, n==0?"SILENT":"partial", n); }
        else {
            printf("%-18s -> %d B cmd=0x%02X %s :", p->name, n, resp[0],
                   resp[0]==0x13 ? "BAD_CMD" : "RESPONSE");
            for (int k = 1; k < n && k < 40; k++) printf(" %02X", resp[k]);
            printf("\n");
        }
        usleep(200000);
    }
    close(fd);
    return 0;
}
