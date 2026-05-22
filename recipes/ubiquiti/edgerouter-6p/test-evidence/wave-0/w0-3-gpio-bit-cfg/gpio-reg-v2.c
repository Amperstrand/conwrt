/*
 * gpio-reg.ko v2 - Read Cavium Octeon GPIO registers for debugging
 *
 * Provides:
 *   /proc/gpio-reg/summary   - Legacy summary (backward compatible)
 *   /proc/gpio-reg/bit_cfg/N - Per-pin BIT_CFG register (N=0..19), read-only
 *
 * GPIO_BIT_CFG layout (Cavium Octeon):
 *   BIT_CFGn = GPIO_BASE + 0x100 + (n * 8)
 *   Fields:
 *     [0]    tx_oe      - Output enable
 *     [1]    pin_xor    - XOR with pin value
 *     [2]    int_en     - Interrupt enable
 *     [3]    int_type   - Interrupt type (0=edge, 1=level)
 *     [4]    int_edge   - Edge direction (0=rising, 1=falling)
 *     [5]    int_xor    - XOR interrupt
 *     [9:8]  output_sel - Output select (0=GPIO, 1-3=other functions)
 *     [11:10] fil_sel   - Filter select
 *
 * Built for OpenWrt 25.12.4, kernel 6.12.87, octeon/generic (MIPS64 BE).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#define GPIO_BASE_PHYS	0x1070000000800ULL
#define GPIO_REG_SIZE	0x200

/* Global registers */
#define GPIO_RX_DAT	0x80
#define GPIO_TX_SET	0x88
#define GPIO_TX_CLEAR	0x90

/* BIT_CFG: n=0..19 -> offset = 0x100 + n*8 */
#define BIT_CFG_BASE	0x100
#define BIT_CFG(n)	(BIT_CFG_BASE + (n) * 8)
#define MAX_GPIO	19

static void __iomem *gpio_base;
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *bc_dir;

/* PoE-related GPIOs */
static const int poe_gpios[] = {1, 2, 3, 4, 5, 6, 7, 9, 10, 16, 18};
static const char *poe_labels[] = {
	"eth0 pair-mode", "eth0 power-en",
	"eth1 pair-mode", "eth1 power-en",
	"eth2 pair-mode", "eth2 power-en",
	"eth3 pair-mode", /* skip 8 - doesn't exist */
	"eth3 power-en",  "eth4 power-en",
	"misc-unknown"
};

/* Read BIT_CFG for GPIO n */
static u64 read_bit_cfg(int n)
{
	return __raw_readq(gpio_base + BIT_CFG(n));
}

/* Per-pin BIT_CFG show function */
static int bit_cfg_show(struct seq_file *m, void *v)
{
	int gpio = (int)(long)m->private;
	u64 cfg;

	if (!gpio_base)
		return -ENODEV;

	cfg = read_bit_cfg(gpio);

	seq_printf(m, "GPIO %d BIT_CFG: 0x%016llx\n", gpio, cfg);
	seq_printf(m, "  tx_oe      = %d (output enable)\n", (int)(cfg & 1));
	seq_printf(m, "  pin_xor    = %d\n", (int)((cfg >> 1) & 1));
	seq_printf(m, "  int_en     = %d\n", (int)((cfg >> 2) & 1));
	seq_printf(m, "  int_type   = %d (0=edge, 1=level)\n", (int)((cfg >> 3) & 1));
	seq_printf(m, "  int_edge   = %d (0=rising, 1=falling)\n", (int)((cfg >> 4) & 1));
	seq_printf(m, "  int_xor    = %d\n", (int)((cfg >> 5) & 1));
	seq_printf(m, "  output_sel = %d (0=GPIO, 1-3=alt)\n", (int)((cfg >> 8) & 0x3));
	seq_printf(m, "  fil_sel    = %d\n", (int)((cfg >> 10) & 0x3));
	seq_printf(m, "  offset     = 0x%x\n", BIT_CFG(gpio));

	return 0;
}

static int bit_cfg_open(struct inode *inode, struct file *file)
{
	/* kernel 5.10+ uses pde_data(), kernel 6.x same */
	return single_open(file, bit_cfg_show, pde_data(inode));
}

static const struct proc_ops bit_cfg_ops = {
	.proc_open	= bit_cfg_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* Legacy summary show */
static int gpio_reg_show(struct seq_file *m, void *v)
{
	u64 rx_dat, tx_set, tx_clr;
	int i;

	if (!gpio_base)
		return -ENODEV;

	rx_dat  = __raw_readq(gpio_base + GPIO_RX_DAT);
	tx_set  = __raw_readq(gpio_base + GPIO_TX_SET);
	tx_clr  = __raw_readq(gpio_base + GPIO_TX_CLEAR);

	seq_printf(m, "GPIO Controller Base: 0x%016llx (phys)\n", GPIO_BASE_PHYS);
	seq_printf(m, "RX_DAT:    0x%016llx\n", rx_dat);
	seq_printf(m, "TX_SET:    0x%016llx\n", tx_set);
	seq_printf(m, "TX_CLEAR:  0x%016llx\n", tx_clr);
	seq_puts(m, "\n");

	/* PoE-relevant GPIOs */
	seq_puts(m, "GPIO  BIT_CFG            tx_oe xor output_sel pin  LABEL\n");
	seq_puts(m, "----  ------------------  ----- --- ---------- ---  -----\n");

	for (i = 0; i < ARRAY_SIZE(poe_gpios); i++) {
		int gpio = poe_gpios[i];
		u64 cfg = read_bit_cfg(gpio);
		int tx_oe = cfg & 1;
		int output_sel = (cfg >> 8) & 0x3;
		int bit_val = !!(rx_dat & (1ULL << gpio));

		seq_printf(m, "%-5d 0x%016llx  %d     %d   %d          %d    %s\n",
			   gpio, cfg, tx_oe, (int)((cfg >> 1) & 1),
			   output_sel, bit_val,
			   (i < ARRAY_SIZE(poe_labels)) ? poe_labels[i] : "unknown");
	}

	/* ALL GPIOs BIT_CFG */
	seq_puts(m, "\n=== All GPIOs BIT_CFG (offset: 0x100 + n*8) ===\n");
	seq_puts(m, "GPIO  OFFSET   RAW                OE XOR OSEL PIN\n");
	for (i = 0; i <= MAX_GPIO; i++) {
		u64 cfg = read_bit_cfg(i);
		int tx_oe = cfg & 1;
		int pin_xor = (cfg >> 1) & 1;
		int output_sel = (cfg >> 8) & 0x3;
		int bit_val = !!(rx_dat & (1ULL << i));

		seq_printf(m, "%-5d 0x%03x    0x%016llx  %d  %d   %d    %d\n",
			   i, BIT_CFG(i), cfg, tx_oe, pin_xor, output_sel, bit_val);
	}

	/* Raw GPIO register space */
	seq_puts(m, "\n=== Raw GPIO register space (0x00-0xFF) ===\n");
	for (i = 0; i < 32; i++) {
		u64 val = __raw_readq(gpio_base + i * 8);
		seq_printf(m, "0x%03x: 0x%016llx\n", i * 8, val);
	}

	/* Raw BIT_CFG region */
	seq_puts(m, "\n=== Raw BIT_CFG region (0x100-0x1A0) ===\n");
	for (i = 0; i <= 20; i++) {
		u64 val = __raw_readq(gpio_base + BIT_CFG_BASE + i * 8);
		seq_printf(m, "0x%03x: 0x%016llx  (BIT_CFG_%d)\n",
			   BIT_CFG_BASE + i * 8, val, i);
	}

	return 0;
}

static int gpio_reg_open(struct inode *inode, struct file *file)
{
	return single_open(file, gpio_reg_show, NULL);
}

static ssize_t gpio_reg_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char kbuf[64];
	unsigned long offset;
	unsigned long long value;
	int n;

	if (count > sizeof(kbuf) - 1)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	n = sscanf(kbuf, "%lx %llx", &offset, &value);
	if (n != 2)
		return -EINVAL;

	if (offset >= GPIO_REG_SIZE)
		return -EINVAL;

	pr_info("gpio-reg: WRITE offset=0x%lx value=0x%llx\n", offset, value);
	__raw_writeq(value, gpio_base + offset);
	return count;
}

static const struct proc_ops gpio_reg_ops = {
	.proc_open	= gpio_reg_open,
	.proc_read	= seq_read,
	.proc_write	= gpio_reg_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init gpio_reg_init(void)
{
	int i;
	struct proc_dir_entry *entry;

	gpio_base = ioremap(GPIO_BASE_PHYS, GPIO_REG_SIZE);
	if (!gpio_base) {
		pr_err("gpio-reg: ioremap failed for 0x%llx\n", GPIO_BASE_PHYS);
		return -ENOMEM;
	}

	/* Create /proc/gpio-reg/ directory */
	proc_dir = proc_mkdir("gpio-reg", NULL);
	if (!proc_dir) {
		pr_err("gpio-reg: failed to create /proc/gpio-reg/\n");
		iounmap(gpio_base);
		return -ENOMEM;
	}

	/* /proc/gpio-reg/summary */
	entry = proc_create("summary", 0644, proc_dir, &gpio_reg_ops);
	if (!entry)
		pr_warn("gpio-reg: failed to create summary\n");

	/* /proc/gpio-reg/bit_cfg/ subdirectory */
	bc_dir = proc_mkdir("bit_cfg", proc_dir);
	if (!bc_dir) {
		pr_err("gpio-reg: failed to create bit_cfg dir\n");
	} else {
		char name[8];
		for (i = 0; i <= MAX_GPIO; i++) {
			snprintf(name, sizeof(name), "%d", i);
			entry = proc_create_data(name, 0444, bc_dir,
						 &bit_cfg_ops,
						 (void *)(long)i);
			if (!entry)
				pr_warn("gpio-reg: failed to create bit_cfg/%d\n", i);
		}
	}

	pr_info("gpio-reg: v2 - mapped GPIO at 0x%llx -> %p, BIT_CFG GPIOs 0-%d exposed\n",
		GPIO_BASE_PHYS, gpio_base, MAX_GPIO);
	return 0;
}

static void __exit gpio_reg_exit(void)
{
	int i;
	char name[8];

	if (bc_dir) {
		for (i = 0; i <= MAX_GPIO; i++) {
			snprintf(name, sizeof(name), "%d", i);
			remove_proc_entry(name, bc_dir);
		}
		remove_proc_entry("bit_cfg", proc_dir);
	}

	remove_proc_entry("summary", proc_dir);
	remove_proc_entry("gpio-reg", NULL);

	if (gpio_base)
		iounmap(gpio_base);
	pr_info("gpio-reg: v2 unloaded\n");
}

module_init(gpio_reg_init);
module_exit(gpio_reg_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cavium Octeon GPIO register debug access v2 - with BIT_CFG");
