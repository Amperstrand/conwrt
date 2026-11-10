/* uim_bitmap — probe which QMI UIM (svc 0x0B) request messages the modem
 * exposes on the EXTERNAL interface (/dev/cdc-wdm0).
 * STRICTLY READ-ONLY: CTL GetClientID -> UIM GET_SUPPORTED_MESSAGES (0x001E,
 * empty request) -> CTL ReleaseClientID. No card/EFS/NV writes, no channel
 * opens, no profile ops.
 * Frame layer copied verbatim from the EXP-035 qmiuim.c (unit-tested against
 * qmicli golden frames). Build (armv7, static):
 *   arm-linux-gnueabi-gcc -static -O2 -o uim_bitmap uim_bitmap.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>

/* ---------------- pure QMUX/QMI frame layer (proven, EXP-035) ---------------- */
int qmi_build_frame(unsigned char *out, int max,
                    unsigned svc, unsigned cid, unsigned msg, unsigned txn,
                    const unsigned char *tlvs, int tlvlen) {
    int ctl = (svc == 0);
    int payload = 1 + 1 + 1 + 1 + (ctl ? 1 : 2) + 2 + 2 + tlvlen;
    int total = 3 + payload;
    if (total - 1 > 0xFFFF || total > max) return -1;
    int i = 0;
    out[i++] = 0x01;
    out[i++] = (total - 1) & 0xFF; out[i++] = ((total - 1) >> 8) & 0xFF;
    out[i++] = 0x00;
    out[i++] = svc & 0xFF;
    out[i++] = cid & 0xFF;
    out[i++] = 0x00;
    if (ctl) { out[i++] = txn & 0xFF; }
    else     { out[i++] = txn & 0xFF; out[i++] = 0x00; }
    out[i++] = msg & 0xFF; out[i++] = (msg >> 8) & 0xFF;
    out[i++] = tlvlen & 0xFF; out[i++] = (tlvlen >> 8) & 0xFF;
    if (tlvlen) memcpy(out + i, tlvs, tlvlen);
    return total;
}

int qmi_parse_frame(const unsigned char *f, int n,
                    unsigned *svc, unsigned *cid, unsigned *txn, unsigned *msg,
                    unsigned char *tlvs, int *tlvlen) {
    if (n < 14 || f[0] != 0x01 || (f[3] & 0x80) == 0) return -1;
    int want = 1 + (f[1] | (f[2] << 8));
    if (n < want) return -1;
    int ctl = (f[4] == 0);
    int txnoff = 7;
    int msgoff = ctl ? 8 : 9;
    *svc = f[4]; *cid = f[5];
    *txn = f[txnoff];
    *msg = f[msgoff] | (f[msgoff + 1] << 8);
    int tl = f[msgoff + 2] | (f[msgoff + 3] << 8);
    if (tl > *tlvlen) tl = *tlvlen;
    memcpy(tlvs, f + msgoff + 4, tl);
    *tlvlen = tl;
    return 0;
}

unsigned char *find_tlv(unsigned char *tlvs, int tlvlen, unsigned type, int *outlen) {
    int i = 0;
    while (i + 3 <= tlvlen) {
        unsigned t = tlvs[i]; int l = tlvs[i+1] | (tlvs[i+2] << 8);
        if (t == type) { *outlen = l; return tlvs + i + 3; }
        i += 3 + l;
    }
    return NULL;
}

/* ---------------- live I/O ---------------- */
static int fd;
static unsigned char rbuf[4096];
static unsigned txn;

static void qmi_xmit(unsigned svc, unsigned cid, unsigned msg,
                     const unsigned char *tlvs, int tlvlen) {
    unsigned char p[512];
    int n = qmi_build_frame(p, sizeof p, svc, cid, msg, ++txn, tlvs, tlvlen);
    if (n <= 0) { fprintf(stderr, "build failed\n"); exit(1); }
    if (write(fd, p, n) != n) { perror("write"); exit(1); }
}

static unsigned qmi_wait(unsigned svc, unsigned cid, unsigned want_txn,
                         unsigned char *tlvs, int *tlvlen) {
    int have = 0;
    for (;;) {
        while (have < 3 || have < 1 + (rbuf[1] | (rbuf[2] << 8))) {
            int n = read(fd, rbuf + have, sizeof(rbuf) - have);
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                fd_set z; struct timeval tv; FD_ZERO(&z); FD_SET(fd,&z); tv.tv_sec=15; tv.tv_usec=0;
                if (select(fd+1,&z,0,0,&tv) <= 0) { fprintf(stderr, "timeout svc=%u cid=%u txn=%u\n", svc,cid,want_txn); exit(3); }
                continue;
            }
            if (n <= 0) { fprintf(stderr, "read: %s\n", strerror(errno)); exit(1); }
            have += n;
        }
        unsigned s2,c2,t2,m2; unsigned char tv[1024]; int tl2 = sizeof tv;
        if (qmi_parse_frame(rbuf, have, &s2,&c2,&t2,&m2, tv, &tl2) == 0
            && s2 == svc && c2 == cid && t2 == want_txn) {
            memcpy(tlvs, tv, tl2); *tlvlen = tl2;
            have = 0;
            return m2;
        }
        have = 0;
    }
}

static const char *err_name(unsigned e) {
    switch (e) {
    case 0x0000: return "NONE";        case 0x0001: return "MALFORMED_MSG";
    case 0x0002: return "NO_MEMORY";    case 0x0003: return "INTERNAL";
    case 0x0011: return "MISSING_ARG";  case 0x0013: return "ARG_TOO_LONG";
    case 0x0030: return "INVALID_ARG";  case 0x0039: return "INVALID_MESSAGE_ID";
    case 0x0045: return "DISABLED";     case 0x0046: return "INVALID_OPERATION";
    case 0x0047: return "INVALID_QMI_CMD"; case 0x004A: return "INFO_UNAVAILABLE";
    case 0x0052: return "ACCESS_DENIED";   default:   return "?";
    }
}

/* send a deliberately-truncated TLV body (type 1, claims 16B, provides 0) so
 * framework decode ALWAYS fails before any handler runs -> side-effect-free
 * presence oracle: 0x47/0x39 = id absent from dispatch; anything else = id
 * present (decode/validation stage reached). */
static const unsigned char BAD_TLV[3] = {0x01, 0x10, 0x00};

static int ln2;
static int probe_id(unsigned cid, unsigned id) {
    qmi_xmit(0x0B, cid, id, BAD_TLV, 3);
    unsigned char tlvs[1024]; int tl = sizeof tlvs;
    qmi_wait(0x0B, cid, txn, tlvs, &tl);
    unsigned char *res = find_tlv(tlvs, tl, 0x02, &ln2);
    unsigned r = (res && ln2 >= 2) ? (res[0] | (res[1] << 8)) : 0xFFFF;
    unsigned e = (res && ln2 >= 4) ? (res[2] | (res[3] << 8)) : 0;
    if (r == 0xFFFF) { printf("  id 0x%02x: NO RESPONSE\n", id); return -1; }
    int present = (e != 0x0047 && e != 0x0039);
    printf("  id 0x%02x: result=%u err=0x%02x (%s) -> %s\n",
           id, r, e, err_name(e), present ? "PRESENT <<<" : "absent");
    return present;
}

/* ---------------- main ---------------- */
/* proprietary block extracted in EXP-040 (uim-msgids.json) */
static const unsigned PROP_IDS[] = {
 0x2b,0x2d,0x34,0x35,0x36,0x37,0x39,0x3c,0x3d,0x41,0x45,
 0x4b,0x4c,0x4d,0x4e,0x4f,0x51,0x52,0x53,0x54,
 0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,
 0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f};

int main(int argc, char **argv) {
    const char *dev = argc > 1 ? argv[1] : "/dev/cdc-wdm0";
    const char *mode = argc > 2 ? argv[2] : "bitmap";
    fd = open(dev, O_RDWR);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", dev, strerror(errno)); return 1; }

    if (!strcmp(mode, "ver")) {
        /* CTL GET_VERSION_LIST 0x0021 — no client needed */
        qmi_xmit(0, 0, 0x0021, NULL, 0);
        unsigned char tlvs[2048]; int tl = sizeof tlvs;
        qmi_wait(0, 0, txn, tlvs, &tl);
        int i = 0;
        while (i + 3 <= tl) {
            unsigned t = tlvs[i]; int l = tlvs[i+1] | (tlvs[i+2] << 8);
            printf("TLV %02x len %d:", t, l);
            for (int k = 0; k < l && k < 96; k++) printf(" %02X", tlvs[i+3+k]);
            printf("\n");
            i += 3 + l;
        }
        return 0;
    }

    /* allocate UIM client for probe/sweep/bitmap */
    unsigned char t_getcid[4] = {0x01, 0x01, 0x00, 0x0B};
    qmi_xmit(0, 0, 0x0022, t_getcid, 4);
    unsigned char tlvs[2048]; int tl = sizeof tlvs;
    qmi_wait(0, 0, txn, tlvs, &tl);
    unsigned char *r = find_tlv(tlvs, tl, 0x01, &ln2);
    int res_off = -1;
    { unsigned char *rr = find_tlv(tlvs, tl, 0x02, &ln2);
      if (rr && ln2 >= 2) res_off = (rr[0] | (rr[1] << 8)); }
    if (!r || ln2 < 2 || res_off) { fprintf(stderr, "GetClientID failed (res=%d)\n", res_off); return 2; }
    unsigned cid = r[1];
    printf("UIM client allocated: cid=%u\n", cid);

    if (!strcmp(mode, "call")) {
        /* empty (fully valid) request; dump every response TLV in hex */
        for (int a = 3; a < argc; a++) {
            unsigned id = strtoul(argv[a], NULL, 16);
            printf("--- call 0x%02x (empty request) ---\n", id);
            qmi_xmit(0x0B, cid, id, NULL, 0);
            unsigned char t2[2048]; int tl2 = sizeof t2;
            qmi_wait(0x0B, cid, txn, t2, &tl2);
            int i = 0;
            while (i + 3 <= tl2) {
                unsigned t = t2[i]; int l = t2[i+1] | (t2[i+2] << 8);
                printf("TLV %02x len %d:", t, l);
                for (int k = 0; k < l && k < 256; k++) printf(" %02X", t2[i+3+k]);
                printf("\n");
                i += 3 + l;
            }
            if (i == 0) printf("(no TLVs parsed, raw %d bytes)\n", tl2);
        }
    } else if (!strcmp(mode, "callslot")) {
        /* call with a single TLV{type 1, slot u8}: default slot 1 */
        for (int a = 3; a < argc; a++) {
            unsigned id = strtoul(argv[a], NULL, 16);
            unsigned slot = 1;
            if (a + 1 < argc && argv[a+1][0] >= '0' && argv[a+1][0] <= '9'
                && strstr(argv[a+1], "0x") == NULL) { slot = strtoul(argv[++a], NULL, 0); }
            unsigned char t[4] = {0x01, 0x01, 0x00, (unsigned char)slot};
            printf("--- callslot 0x%02x slot=%u ---\n", id, slot);
            qmi_xmit(0x0B, cid, id, t, 4);
            unsigned char t2[4096]; int tl2 = sizeof t2;
            qmi_wait(0x0B, cid, txn, t2, &tl2);
            int i = 0;
            while (i + 3 <= tl2) {
                unsigned t = t2[i]; int l = t2[i+1] | (t2[i+2] << 8);
                printf("TLV %02x len %d:", t, l);
                for (int k = 0; k < l && k < 512; k++) printf(" %02X", t2[i+3+k]);
                /* ascii render for string-ish payloads */
                printf("  |");
                for (int k = 0; k < l && k < 512; k++) printf("%c", (t2[i+3+k] >= 32 && t2[i+3+k] < 127) ? t2[i+3+k] : '.');
                printf("|\n");
                i += 3 + l;
            }
        }
    } else if (!strcmp(mode, "listen")) {
        /* print every incoming frame for N seconds (indications!) */
        int secs = argc > 3 ? atoi(argv[3]) : 10;
        printf("listening %ds...\n", secs);
        time_t t0 = time(NULL);
        while (time(NULL) - t0 < secs) {
            fd_set z; struct timeval tv; FD_ZERO(&z); FD_SET(fd,&z); tv.tv_sec=1; tv.tv_usec=0;
            if (select(fd+1,&z,0,0,&tv) <= 0) continue;
            int n = read(fd, rbuf, sizeof rbuf);
            if (n <= 0) continue;
            printf("FRAME %dB:", n);
            for (int k = 0; k < n && k < 96; k++) printf(" %02X", rbuf[k]);
            printf("\n"); fflush(stdout);
        }
    } else if (!strcmp(mode, "probe")) {
        for (int a = 3; a < argc; a++) probe_id(cid, strtoul(argv[a], NULL, 16));
    } else if (!strcmp(mode, "sweep")) {
        /* calibration sentinels then the 44 proprietary ids */
        static const unsigned SENT[] = {0x42, 0x3B, 0x1E};
        printf("--- calibration (expect PRESENT PRESENT absent) ---\n");
        for (unsigned k = 0; k < 3; k++) probe_id(cid, SENT[k]);
        printf("--- proprietary block ---\n");
        int hits = 0, n = 0;
        for (unsigned k = 0; k < sizeof PROP_IDS / sizeof *PROP_IDS; k++) {
            int p = probe_id(cid, PROP_IDS[k]); n++;
            if (p == 1) hits++;
        }
        printf("\nSWEEP VERDICT: %d/%d proprietary ids PRESENT externally -> %s\n",
               hits, n, hits ? "LPA FAMILY EXTERNALLY REACHABLE" : "internal-only (door closed)");
    } else {  /* bitmap — original probe, kept for the record */
        qmi_xmit(0x0B, cid, 0x001E, NULL, 0);
        qmi_wait(0x0B, cid, txn, tlvs, &tl);
        unsigned char *res = find_tlv(tlvs, tl, 0x02, &ln2);
        unsigned qmi_res = (res && ln2 >= 2) ? (res[0] | (res[1] << 8)) : 0xFFFF;
        unsigned qmi_err = (res && ln2 >= 4) ? (res[2] | (res[3] << 8)) : 0;
        printf("QMI result: 0x%04x err 0x%02x (%s)\n", qmi_res, qmi_err, err_name(qmi_err));
        int i = 0;
        while (i + 3 <= tl) {
            unsigned t = tlvs[i]; int l = tlvs[i+1] | (tlvs[i+2] << 8);
            printf("TLV %02x len %d:", t, l);
            for (int k = 0; k < l && k < 48; k++) printf(" %02X", tlvs[i+3+k]);
            printf("\n");
            i += 3 + l;
        }
    }

    unsigned char t_rel[4] = {0x01, 0x01, 0x00, cid};
    qmi_xmit(0, 0, 0x0023, t_rel, 4);
    qmi_wait(0, 0, txn, tlvs, &tl);
    printf("client released; done.\n");
    return 0;
}
