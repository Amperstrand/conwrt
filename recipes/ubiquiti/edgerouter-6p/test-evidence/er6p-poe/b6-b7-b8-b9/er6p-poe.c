/*
 * er6p-poe.ko - EdgeRouter 6P PoE control driver
 *
 * Manages 24V passive PoE on allowed ports (eth1, eth3, eth4).
 * Port 0 (eth0/WAN) and port 2 (eth2/management) are NEVER touched.
 *
 * GPIO register layout (Cavium Octeon):
 *   GPIO_BASE_PHYS = 0x1070000000800
 *   TX_SET   = base + 0x88  (set GPIO output HIGH)
 *   TX_CLEAR = base + 0x90  (set GPIO output LOW)
 *   RX_DAT   = base + 0x80  (read GPIO pin state)
 *   BIT_CFGn = base + n*8   (pin config, n=0..19)
 *
 * Built for OpenWrt 25.12.4, kernel 6.12.87, octeon/generic (MIPS64 BE).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "er6p-poe-types.h"
#include "er6p-poe-allowlist.h"
#include "er6p-poe-gpio.h"
#include "er6p-poe-i2c.h"
#include "er6p-poe-engine.h"
#include "er6p-poe-sysfs.h"
#include "er6p-poe-debugfs.h"

MODULE_AUTHOR("conwrt research");
MODULE_DESCRIPTION("EdgeRouter 6P PoE control driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.3.0");

static int __init er6p_poe_init(void)
{
	int ret;

	pr_info("er6p-poe: loading driver (ports: %d allowed)\n",
		PORT_ALLOWLIST_LEN);

	ret = er6p_poe_gpio_init();
	if (ret)
		return ret;

	er6p_poe_state_init();
	er6p_poe_disable_all();

	ret = er6p_poe_sysfs_init();
	if (ret) {
		er6p_poe_gpio_exit();
		return ret;
	}

	er6p_poe_debugfs_init();
	er6p_poe_i2c_init();

	pr_info("er6p-poe: driver loaded successfully\n");
	return 0;
}

static void __exit er6p_poe_exit(void)
{
	er6p_poe_disable_all();
	er6p_poe_debugfs_exit();
	er6p_poe_sysfs_exit();
	er6p_poe_i2c_exit();
	er6p_poe_gpio_exit();
	pr_info("er6p-poe: unloading driver\n");
}

module_init(er6p_poe_init);
module_exit(er6p_poe_exit);
