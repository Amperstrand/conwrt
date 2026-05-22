#ifndef ER6P_POE_TYPES_H
#define ER6P_POE_TYPES_H

#include <linux/types.h>
#include "er6p-poe-allowlist.h"

/* PoE mode — matches EdgeOS poe_st value dispatch (A1 disassembly) */
enum poe_mode {
    POE_MODE_OFF = 0,
    POE_MODE_48V = 1,       /* 802.3af/at (not used on ER-6P) */
    POE_MODE_24V_2PAIR = 2, /* 24V passive, 2-pair */
    POE_MODE_BOTH = 5,      /* 4-pair (both 24V + 48V pins) */
};

/* GPIO pair roles for each PoE port */
enum poe_gpio_role {
    POE_GPIO_24V_POWER = 0,    /* power-enable (odd GPIO entries) */
    POE_GPIO_48V_PAIRMODE = 1, /* pair-mode (even GPIO entries) */
};

/* Per-port PoE state */
struct poe_port_state {
    int port_idx;              /* 1-based port index (1=eth1, 3=eth3, 4=eth4) */
    enum poe_mode mode;
    bool enabled;
};

/* Full driver state */
struct poe_driver_state {
    struct poe_port_state ports[PORT_ALLOWLIST_LEN];
    void __iomem *gpio_base;  /* ioremap'd GPIO controller base */
};

#endif /* ER6P_POE_TYPES_H */
