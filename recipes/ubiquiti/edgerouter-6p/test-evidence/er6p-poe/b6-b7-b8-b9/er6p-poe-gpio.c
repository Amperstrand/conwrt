#include <linux/io.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include "er6p-poe-gpio.h"

static void __iomem *gpio_base;

static const struct poe_gpio_map *find_gpio_map(int port_idx)
{
	int i;
	for (i = 0; i < POE_GPIO_MAP_LEN; i++) {
		if (POE_GPIO_MAP[i].port_idx == port_idx)
			return &POE_GPIO_MAP[i];
	}
	return NULL;
}

int er6p_poe_gpio_init(void)
{
	gpio_base = ioremap(GPIO_BASE_PHYS, 0x200);
	if (!gpio_base) {
		pr_err("er6p-poe: failed to ioremap GPIO base\n");
		return -ENOMEM;
	}
	pr_info("er6p-poe: GPIO base mapped at %p (phys 0x%llx)\n",
		gpio_base, GPIO_BASE_PHYS);
	return 0;
}

void er6p_poe_gpio_exit(void)
{
	if (gpio_base) {
		iounmap(gpio_base);
		gpio_base = NULL;
	}
}

int er6p_poe_gpio_set(int port_idx, enum poe_gpio_role role, bool on)
{
	const struct poe_gpio_map *map;
	int gpio_num;

	if (!is_port_allowed(port_idx))
		return -EPERM;

	map = find_gpio_map(port_idx);
	if (!map)
		return -EINVAL;

	gpio_num = (role == POE_GPIO_24V_POWER) ? map->gpio_24v : map->gpio_48v;

	if (on)
		writeq((1ULL << gpio_num), gpio_base + GPIO_TX_SET);
	else
		writeq((1ULL << gpio_num), gpio_base + GPIO_TX_CLEAR);

	pr_info("er6p-poe: port=%d role=%d gpio=%d %s\n",
		port_idx, role, gpio_num, on ? "ON" : "OFF");
	return 0;
}

void er6p_poe_gpio_all_off(void)
{
	int i;
	for (i = 0; i < POE_GPIO_MAP_LEN; i++) {
		er6p_poe_gpio_set(POE_GPIO_MAP[i].port_idx,
				  POE_GPIO_24V_POWER, false);
		er6p_poe_gpio_set(POE_GPIO_MAP[i].port_idx,
				  POE_GPIO_48V_PAIRMODE, false);
	}
}

u64 er6p_poe_gpio_read(unsigned int offset)
{
	if (!gpio_base)
		return 0;
	return readq(gpio_base + offset);
}
