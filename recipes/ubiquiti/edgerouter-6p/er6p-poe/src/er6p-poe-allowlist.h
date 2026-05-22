#ifndef ER6P_POE_ALLOWLIST_H
#define ER6P_POE_ALLOWLIST_H

#include <linux/build_bug.h>
#include <linux/types.h>

/*
 * HARD ALLOWLIST — enforced in BOTH kernel module AND userspace.
 * Port 0 (eth0/WAN) and port 2 (eth2/management) are NEVER allowed.
 * User constraint: "DO NOT enable PoE on eth0", "DO NOT toggle PoE on eth2"
 */
#define PORT_0 1  /* eth1 */
#define PORT_1 3  /* eth3 */
#define PORT_2 4  /* eth4 */
#define PORT_ALLOWLIST_LEN 3

static const int PORT_ALLOWLIST[] = {PORT_0, PORT_1, PORT_2};

/* Compile-time guard: port 0 (eth0) and port 2 (eth2) must NEVER appear */
#define _PORT_EQ_ZERO (PORT_0 == 0 || PORT_1 == 0 || PORT_2 == 0)
#define _PORT_EQ_TWO  (PORT_0 == 2 || PORT_1 == 2 || PORT_2 == 2)
static_assert(!_PORT_EQ_ZERO, "eth0 (port 0) must NEVER be in PoE allowlist");
static_assert(!_PORT_EQ_TWO, "eth2 (port 2) must NEVER be in PoE allowlist");

/* Runtime check */
static inline bool is_port_allowed(int port_idx)
{
    int i;
    for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
        if (PORT_ALLOWLIST[i] == port_idx)
            return true;
    }
    return false;
}

/*
 * Verified GPIO-to-port mapping (from A6/A7/A10):
 *
 * | Port | ethX | 24V power GPIO | 48V pair-mode GPIO |
 * |------|------|----------------|---------------------|
 * | 1    | eth1 | 4              | 3                   |
 * | 3    | eth3 | 10             | 7                   |
 * | 4    | eth4 | 16             | 9                   |
 */
struct poe_gpio_map {
    int port_idx;
    int gpio_24v;      /* power-enable GPIO */
    int gpio_48v;      /* pair-mode GPIO */
};

static const struct poe_gpio_map POE_GPIO_MAP[] = {
    { .port_idx = 1, .gpio_24v = 4,  .gpio_48v = 3  },  /* eth1 (lan1) */
    { .port_idx = 3, .gpio_24v = 10, .gpio_48v = 7  },  /* eth3 (lan3) */
    { .port_idx = 4, .gpio_24v = 16, .gpio_48v = 9  },  /* eth4 (lan4) */
};
#define POE_GPIO_MAP_LEN 3

#endif /* ER6P_POE_ALLOWLIST_H */
