/* modemifd — pcscd IFD handler bridging PC/SC to a modem SIM slot over TCP.
 * Spike for Amperstrand/conwrt-bench#21. socat on the OpenWrt router exposes
 * the modem AT port; this driver speaks AT+CSIM (basic channel) and
 * AT+CPIN? (presence). Debug: MODEMIFD_DEBUG=1 -> /tmp/modemifd.log */
#define _GNU_SOURCE
#include <PCSC/ifdhandler.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_TARGET "192.168.13.124:7002"
/* genuine sysmo-class USIM ATR (T=0) so pcscd sees a well-formed card */
static const unsigned char FAKE_ATR[] = {
  0x3B,0x9F,0x96,0x80,0x1F,0x47,0x80,0x31,0xE0,0x73,0xF6,
  0x21,0x1B,0x66,0x04,0x20,0x40,0x90,0x00,0x73 };
#define FAKE_ATR_LEN ((DWORD)sizeof(FAKE_ATR))

typedef struct { int fd; char target[128]; pthread_mutex_t lock;
                 time_t p_ts; int present; } ctx_t;
static ctx_t G = { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER, .present = -1 };

static FILE *DF;
#define DLOG(...) do { if (!DF && getenv("MODEMIFD_DEBUG")) DF = fopen("/tmp/modemifd.log","a"); \
                       if (DF) { fprintf(DF, __VA_ARGS__); fflush(DF); } } while (0)

static int tcp_connect(const char *target) {
  char buf[128]; strncpy(buf, target, 127); buf[127] = 0;
  char *c = strchr(buf, ':'); if (!c) return -1; *c = 0;
  int port = atoi(c + 1); if (port <= 0) return -1;
  int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
  struct sockaddr_in a; memset(&a, 0, sizeof a);
  a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
  if (inet_pton(AF_INET, buf, &a.sin_addr) != 1) { close(fd); return -1; }
  int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  int r = connect(fd, (struct sockaddr *)&a, sizeof a);
  if (r < 0 && errno == EINPROGRESS) {
    fd_set w; FD_ZERO(&w); FD_SET(fd, &w);
    struct timeval tv = { .tv_sec = 3 };
    if (select(fd + 1, NULL, &w, NULL, &tv) <= 0) { close(fd); return -1; }
    int so = 0; socklen_t sl = sizeof so;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl) < 0 || so) { close(fd); return -1; }
  } else if (r < 0) { close(fd); return -1; }
  fcntl(fd, F_SETFL, fl);
  int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  return fd;
}

/* append up to cap-1 bytes; returns bytes appended this call, 0 timeout, -1 err */
static int read_more(int fd, char *out, size_t cap, size_t *used, int wait_ms) {
  if (*used >= cap - 1) return 0;
  fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
  struct timeval tv = { .tv_sec = wait_ms / 1000, .tv_usec = (wait_ms % 1000) * 1000 };
  if (select(fd + 1, &r, NULL, NULL, &tv) <= 0) return 0;
  ssize_t n = read(fd, out + *used, cap - 1 - *used);
  if (n <= 0) return -1;
  *used += (size_t)n; out[*used] = 0;
  return (int)n;
}

/* caller holds lock. 0=OK-ended, 1=ERROR-ended, -1=transport */
static int at_locked(ctx_t *c, const char *cmd, char *resp, size_t cap, int total_ms) {
  if (c->fd < 0 && (c->fd = tcp_connect(c->target)) < 0) { DLOG("connect fail %s\n", c->target); return -1; }
  { char t[2048]; size_t u = 0;
    while (read_more(c->fd, t, sizeof t, &u, 60) > 0) { u = 0; } }
  size_t used = 0; resp[0] = 0;
  char line[1400];
  int n = snprintf(line, sizeof line, "%s\r", cmd);
  if (write(c->fd, line, (size_t)n) != n) { close(c->fd); c->fd = -1; return -1; }
  int waited = 0;
  while (waited < total_ms) {
    int n2 = read_more(c->fd, resp, cap - 1, &used, 150);
    if (n2 < 0) { close(c->fd); c->fd = -1; DLOG("read err cmd=%s\n", cmd); return -1; }
    waited += 150;
    if (strstr(resp, "OK\r")) return 0;
    if (strstr(resp, "ERROR")) return 1;
  }
  return 0; /* soft timeout: hand back what we have */
}


/* v2: retry with forced reconnect on empty/failed responses (interleave hardening) */
static int at_retry(ctx_t *c, const char *cmd, char *resp, size_t cap, int total_ms) {
  int rc = at_locked(c, cmd, resp, cap, total_ms);
  if (rc < 0)
    rc = at_locked(c, cmd, resp, cap, total_ms);
  else if (resp[0] == 0) {
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    rc = at_locked(c, cmd, resp, cap, total_ms);
  }
  return rc;
}

static int h2b(int ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  return -1;
}
static void b2h(const unsigned char *b, size_t n, char *out) {
  static const char H[] = "0123456789ABCDEF";
  for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
  out[2*n] = 0;
}

RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel) {
  (void)Lun; (void)Channel;
  const char *t = getenv("MODEMIFD_TARGET"); if (!t) t = DEFAULT_TARGET;
  strncpy(G.target, t, 127); G.target[127] = 0;
  G.fd = tcp_connect(G.target);
  DLOG("CreateChannel %s fd=%d\n", G.target, G.fd);
  if (G.fd < 0) return IFD_COMMUNICATION_ERROR;
  char r[1024]; at_locked(&G, "ATE0", r, sizeof r, 1500);
  return IFD_SUCCESS;
}

RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName) {
  (void)Lun;
  strncpy(G.target, DeviceName ? DeviceName : DEFAULT_TARGET, 127); G.target[127] = 0;
  G.fd = tcp_connect(G.target);
  DLOG("CreateChannelByName %s fd=%d\n", G.target, G.fd);
  if (G.fd < 0) return IFD_COMMUNICATION_ERROR;
  char r[1024]; at_locked(&G, "ATE0", r, sizeof r, 1500);
  return IFD_SUCCESS;
}

RESPONSECODE IFDHCloseChannel(DWORD Lun) {
  (void)Lun; DLOG("CloseChannel fd=%d\n", G.fd);
  if (G.fd >= 0) { close(G.fd); }
  G.fd = -1;
  return IFD_SUCCESS;
}

static void fill_6f00(PUCHAR Rx, PDWORD RxLen) {
  if (*RxLen >= 2) { Rx[0] = 0x6F; Rx[1] = 0x00; *RxLen = 2; } else *RxLen = 0;
}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer,
    DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci) {
  (void)Lun; (void)SendPci; (void)RecvPci;
  if (TxLength > 512) { fill_6f00(RxBuffer, RxLength); return IFD_SUCCESS; }
  pthread_mutex_lock(&G.lock);
  char hex[1100], cmd[1250], resp[8192];
  b2h(TxBuffer, TxLength, hex);
  snprintf(cmd, sizeof cmd, "AT+CSIM=%u,\"%s\"", (unsigned)(TxLength * 2), hex);
  int rc = at_retry(&G, cmd, resp, sizeof resp - 1, 4000);
  DLOG("XMIT(%lu) %s\n  -> rc=%d resp=%.300s\n", (unsigned long)TxLength, hex, rc, resp);
  if (rc < 0) { pthread_mutex_unlock(&G.lock); *RxLength = 0; return IFD_COMMUNICATION_ERROR; }
  if (rc == 1) { fill_6f00(RxBuffer, RxLength); pthread_mutex_unlock(&G.lock); return IFD_SUCCESS; }
  char *p = strstr(resp, "+CSIM:");
  if (!p) { fill_6f00(RxBuffer, RxLength); pthread_mutex_unlock(&G.lock); return IFD_SUCCESS; }
  p = strchr(p, '"');
  if (!p) { fill_6f00(RxBuffer, RxLength); pthread_mutex_unlock(&G.lock); return IFD_SUCCESS; }
  p++;
  char *q = strchr(p, '"');
  if (!q) { fill_6f00(RxBuffer, RxLength); pthread_mutex_unlock(&G.lock); return IFD_SUCCESS; }
  DWORD n = 0;
  for (char *h = p; h + 1 < q && n < *RxLength; h += 2) {
    int hi = h2b((unsigned char)h[0]), lo = h2b((unsigned char)h[1]);
    if (hi < 0 || lo < 0) break;
    RxBuffer[n++] = (unsigned char)((hi << 4) | lo);
  }
  *RxLength = n;
  pthread_mutex_unlock(&G.lock);
  return IFD_SUCCESS;
}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength) {
  (void)Lun; (void)Action;
  DLOG("PowerICC action=%lu\n", (unsigned long)Action);
  if (*AtrLength < FAKE_ATR_LEN) { *AtrLength = FAKE_ATR_LEN; return IFD_ERROR_INSUFFICIENT_BUFFER; }
  memcpy(Atr, FAKE_ATR, FAKE_ATR_LEN); *AtrLength = FAKE_ATR_LEN;
  return IFD_SUCCESS;
}

RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags,
    UCHAR PTS1, UCHAR PTS2, UCHAR PTS3) {
  (void)Lun; (void)Protocol; (void)Flags; (void)PTS1; (void)PTS2; (void)PTS3;
  return IFD_SUCCESS;
}

RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength,
    PUCHAR RxBuffer, DWORD RxLength, PDWORD pdwBytesReturned) {
  (void)Lun; (void)dwControlCode; (void)TxBuffer; (void)TxLength; (void)RxBuffer; (void)RxLength;
  *pdwBytesReturned = 0;
  return IFD_SUCCESS;
}

static int probe_present(void) {
  time_t now = time(NULL);
  if (G.present >= 0 && now - G.p_ts < 3) return G.present;
  char resp[1024];
  pthread_mutex_lock(&G.lock);
  int rc = at_retry(&G, "AT+CPIN?", resp, sizeof resp, 2500);
  if (rc == 0 && !strstr(resp, "+CPIN:")) {
    if (G.fd >= 0) { close(G.fd); G.fd = -1; }
    rc = at_retry(&G, "AT+CPIN?", resp, sizeof resp, 2500);
  }
  pthread_mutex_unlock(&G.lock);
  G.p_ts = now;
  G.present = (rc == 0 && strstr(resp, "+CPIN:")) ? 1 : 0;
  DLOG("presence rc=%d -> %d (%.80s)\n", rc, G.present, resp);
  return G.present;
}

RESPONSECODE IFDHICCPresence(DWORD Lun) {
  (void)Lun;
  return probe_present() ? IFD_ICC_PRESENT : IFD_ICC_NOT_PRESENT;
}

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value) {
  (void)Lun;
  switch (Tag) {
  case TAG_IFD_ATR:
    if (*Length < FAKE_ATR_LEN) { *Length = FAKE_ATR_LEN; return IFD_ERROR_INSUFFICIENT_BUFFER; }
    memcpy(Value, FAKE_ATR, FAKE_ATR_LEN); *Length = FAKE_ATR_LEN;
    return IFD_SUCCESS;
  case TAG_IFD_SLOTS_NUMBER:
    if (*Length >= 1) { Value[0] = 1; *Length = 1; return IFD_SUCCESS; }
    return IFD_ERROR_INSUFFICIENT_BUFFER;
  default:
    *Length = 0;
    return IFD_ERROR_TAG;
  }
}

RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value) {
  (void)Lun; (void)Tag; (void)Length; (void)Value;
  return IFD_SUCCESS;
}
