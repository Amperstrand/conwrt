#ifndef ER6P_POE_GPIO_H
#define ER6P_POE_GPIO_H

#include "er6p-poe-types.h"
#include "er6p-poe-allowlist.h"

#define GPIO_BASE_PHYS  0x1070000000800ULL
#define GPIO_TX_SET     0x88
#define GPIO_TX_CLEAR   0x90
#define GPIO_RX_DAT     0x80

int er6p_poe_gpio_init(void);
void er6p_poe_gpio_exit(void);

int er6p_poe_gpio_set(int port_idx, enum poe_gpio_role role, bool on);
void er6p_poe_gpio_all_off(void);

u64 er6p_poe_gpio_read(unsigned int offset);

#endif /* ER6P_POE_GPIO_H */
