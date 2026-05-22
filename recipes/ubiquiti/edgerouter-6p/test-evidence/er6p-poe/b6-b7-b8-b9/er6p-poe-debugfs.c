/*
 * er6p-poe debugfs interface
 *
 * /sys/kernel/debug/er6p_poe/registers  (raw register dump + per-port state)
 *
 * Gracefully skips if debugfs is unavailable.
 */
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include "er6p-poe-debugfs.h"
#include "er6p-poe-gpio.h"
#include "er6p-poe-engine.h"
#include "er6p-poe-allowlist.h"

static struct dentry *debugfs_dir;

static int registers_show(struct seq_file *m, void *v)
{
	int i;

	seq_puts(m, "GPIO registers:\n");
	seq_printf(m, "  RX_DAT:   0x%016llx\n",
		   er6p_poe_gpio_read(GPIO_RX_DAT));
	seq_printf(m, "  TX_SET:   0x%016llx\n",
		   er6p_poe_gpio_read(GPIO_TX_SET));
	seq_printf(m, "  TX_CLEAR: 0x%016llx\n",
		   er6p_poe_gpio_read(GPIO_TX_CLEAR));

	seq_puts(m, "\nPer-port state:\n");
	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		struct poe_port_state *s;
		const char *mode_str;

		s = er6p_poe_get_state(PORT_ALLOWLIST[i]);
		if (!s)
			continue;

		switch (s->mode) {
		case POE_MODE_OFF:       mode_str = "off";   break;
		case POE_MODE_48V:       mode_str = "48v";   break;
		case POE_MODE_24V_2PAIR: mode_str = "24v";   break;
		case POE_MODE_BOTH:      mode_str = "4pair"; break;
		default:                 mode_str = "???";   break;
		}

		seq_printf(m, "  port %d (eth%d): enabled=%d mode=%s\n",
			   s->port_idx, s->port_idx, s->enabled, mode_str);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(registers);

int er6p_poe_debugfs_init(void)
{
	debugfs_dir = debugfs_create_dir("er6p_poe", NULL);
	if (IS_ERR_OR_NULL(debugfs_dir)) {
		pr_info("er6p-poe: debugfs not available, skipping\n");
		debugfs_dir = NULL;
		return 0;
	}

	debugfs_create_file("registers", 0444, debugfs_dir, NULL,
			    &registers_fops);
	pr_info("er6p-poe: debugfs entries created\n");
	return 0;
}

void er6p_poe_debugfs_exit(void)
{
	debugfs_remove_recursive(debugfs_dir);
	debugfs_dir = NULL;
}
