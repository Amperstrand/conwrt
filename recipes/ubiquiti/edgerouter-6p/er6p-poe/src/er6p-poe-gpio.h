#ifndef ER6P_POE_GPIO_H
#define ER6P_POE_GPIO_H

#include "er6p-poe-types.h"
#include "er6p-poe-allowlist.h"

#define GPIO_BASE_PHYS  0x1070000000800ULL
#define GPIO_TX_SET     0x88
#define GPIO_TX_CLEAR   0x90
#define GPIO_RX_DAT     0x80
#define GPIO_BIT_CFG_BASE  0x00    /* BIT_CFG for GPIOs 0-15: GPIO_BASE + n*8 */
#define GPIO_XBIT_CFG_BASE 0x100  /* XBIT_CFG for GPIOs 16-31: GPIO_BASE + 0x100 + (n-16)*8 */

static inline unsigned int gpio_bit_cfg_offset(int gpio_num)
{
	if (gpio_num < 16)
		return GPIO_BIT_CFG_BASE + gpio_num * 8;
	else
		return GPIO_XBIT_CFG_BASE + (gpio_num - 16) * 8;
}

int er6p_poe_gpio_init(void);
void er6p_poe_gpio_exit(void);

int er6p_poe_gpio_set(int port_idx, enum poe_gpio_role role, bool on);
void er6p_poe_gpio_all_off(void);

u64 er6p_poe_gpio_read(unsigned int offset);

#endif /* ER6P_POE_GPIO_H */
