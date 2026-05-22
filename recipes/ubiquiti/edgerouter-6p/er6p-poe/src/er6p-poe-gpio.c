#include <linux/io.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include "er6p-poe-gpio.h"

static void __iomem *gpio_base;
static u64 saved_bit_cfg_24v[POE_GPIO_MAP_LEN];
static u64 saved_bit_cfg_48v[POE_GPIO_MAP_LEN];

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
	int i;

	gpio_base = ioremap(GPIO_BASE_PHYS, 0x200);
	if (!gpio_base) {
		pr_err("er6p-poe: failed to ioremap GPIO base\n");
		return -ENOMEM;
	}
	pr_info("er6p-poe: GPIO base mapped at %p (phys 0x%llx)\n",
		gpio_base, GPIO_BASE_PHYS);

	for (i = 0; i < POE_GPIO_MAP_LEN; i++) {
		u64 cfg;
		void __iomem *cfg_reg;

		cfg_reg = gpio_base +
			  gpio_bit_cfg_offset(POE_GPIO_MAP[i].gpio_24v);
		saved_bit_cfg_24v[i] = readq(cfg_reg);
		cfg = saved_bit_cfg_24v[i];
		cfg |= (1ULL << 0);
		cfg &= ~(3ULL << 8);
		writeq(cfg, cfg_reg);
		pr_info("er6p-poe: GPIO_BIT_CFG[%d] = 0x%016llx (tx_oe=1, was 0x%016llx)\n",
			POE_GPIO_MAP[i].gpio_24v, readq(cfg_reg),
			saved_bit_cfg_24v[i]);

		cfg_reg = gpio_base +
			  gpio_bit_cfg_offset(POE_GPIO_MAP[i].gpio_48v);
		saved_bit_cfg_48v[i] = readq(cfg_reg);
		cfg = saved_bit_cfg_48v[i];
		cfg |= (1ULL << 0);
		cfg &= ~(3ULL << 8);
		writeq(cfg, cfg_reg);
		pr_info("er6p-poe: GPIO_BIT_CFG[%d] = 0x%016llx (tx_oe=1, was 0x%016llx)\n",
			POE_GPIO_MAP[i].gpio_48v, readq(cfg_reg),
			saved_bit_cfg_48v[i]);
	}

	return 0;
}

void er6p_poe_gpio_exit(void)
{
	int i;

	if (gpio_base) {
		for (i = 0; i < POE_GPIO_MAP_LEN; i++) {
			void __iomem *cfg_reg;

			cfg_reg = gpio_base +
				  gpio_bit_cfg_offset(POE_GPIO_MAP[i].gpio_24v);
			writeq(saved_bit_cfg_24v[i], cfg_reg);

			cfg_reg = gpio_base +
				  gpio_bit_cfg_offset(POE_GPIO_MAP[i].gpio_48v);
			writeq(saved_bit_cfg_48v[i], cfg_reg);
		}
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

	pr_debug("er6p-poe: port=%d role=%d gpio=%d %s\n",
		port_idx, role, gpio_num, on ? "ON" : "OFF");
	return 0;
}

void er6p_poe_gpio_all_off(void)
{
	int i;
	for (i = 0; i < POE_GPIO_MAP_LEN; i++) {
		if (er6p_poe_gpio_set(POE_GPIO_MAP[i].port_idx,
				      POE_GPIO_24V_POWER, false))
			pr_warn("er6p-poe: failed to clear 24V on port %d\n",
				POE_GPIO_MAP[i].port_idx);
		if (er6p_poe_gpio_set(POE_GPIO_MAP[i].port_idx,
				      POE_GPIO_48V_PAIRMODE, false))
			pr_warn("er6p-poe: failed to clear 48V on port %d\n",
				POE_GPIO_MAP[i].port_idx);
	}
}

u64 er6p_poe_gpio_read(unsigned int offset)
{
	if (!gpio_base)
		return 0;
	return readq(gpio_base + offset);
}
