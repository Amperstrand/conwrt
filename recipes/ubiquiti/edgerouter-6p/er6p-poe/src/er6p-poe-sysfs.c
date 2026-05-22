/*
 * er6p-poe sysfs interface
 *
 * /sys/kernel/er6p_poe/eth{1,3,4}/enable  (rw: 0=off, 1=on)
 * /sys/kernel/er6p_poe/eth{1,3,4}/mode    (ro: "off", "24v")
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/kstrtox.h>
#include "er6p-poe-sysfs.h"
#include "er6p-poe-engine.h"
#include "er6p-poe-allowlist.h"

/* Per-port sysfs attribute container */
struct port_attr_data {
	int port_idx;
	struct kobject *port_kobj;
	struct kobj_attribute enable_attr;
	struct kobj_attribute mode_attr;
};

static struct kobject *er6p_poe_kobj;
static struct kobj_attribute budget_attr;
static struct port_attr_data port_attrs[PORT_ALLOWLIST_LEN];

static const char *port_to_ethname(int port_idx)
{
	switch (port_idx) {
	case 1: return "eth1";
	case 3: return "eth3";
	case 4: return "eth4";
	default: return "unknown";
	}
}

static ssize_t enable_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buf)
{
	struct port_attr_data *pd;
	struct poe_port_state *state;

	pd = container_of(attr, struct port_attr_data, enable_attr);
	state = er6p_poe_get_state(pd->port_idx);
	if (!state)
		return -EINVAL;

	return sprintf(buf, "%d\n", state->enabled ? 1 : 0);
}

static ssize_t enable_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	struct port_attr_data *pd;
	long val;
	int ret;

	pd = container_of(attr, struct port_attr_data, enable_attr);

	if (kstrtol(buf, 10, &val))
		return -EINVAL;

	if (val == 1)
		ret = er6p_poe_enable(pd->port_idx);
	else if (val == 0)
		ret = er6p_poe_disable(pd->port_idx);
	else
		return -EINVAL;

	if (ret)
		return ret;

	pr_info("er6p-poe: %s PoE %s via sysfs\n",
		port_to_ethname(pd->port_idx),
		val ? "enabled" : "disabled");
	return count;
}

static ssize_t mode_show(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf)
{
	struct port_attr_data *pd;
	struct poe_port_state *state;

	pd = container_of(attr, struct port_attr_data, mode_attr);
	state = er6p_poe_get_state(pd->port_idx);
	if (!state)
		return -EINVAL;

	if (!state->enabled)
		return sprintf(buf, "off\n");

	switch (state->mode) {
	case POE_MODE_24V_2PAIR:
		return sprintf(buf, "24v\n");
	case POE_MODE_48V:
		return sprintf(buf, "48v\n");
	case POE_MODE_BOTH:
		return sprintf(buf, "4pair\n");
	default:
		return sprintf(buf, "off\n");
	}
}

static ssize_t budget_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "budget=%dW used=%dW\n",
		       er6p_poe_get_power_budget(),
		       er6p_poe_get_power_used());
}

int er6p_poe_sysfs_init(void)
{
	int i;

	er6p_poe_kobj = kobject_create_and_add("er6p_poe", kernel_kobj);
	if (!er6p_poe_kobj) {
		pr_err("er6p-poe: failed to create sysfs directory\n");
		return -ENOMEM;
	}

	budget_attr.attr.name = "power_budget";
	budget_attr.attr.mode = 0444;
	budget_attr.show = budget_show;
	budget_attr.store = NULL;

	if (sysfs_create_file(er6p_poe_kobj, &budget_attr.attr)) {
		pr_err("er6p-poe: failed to create power_budget sysfs entry\n");
		kobject_put(er6p_poe_kobj);
		er6p_poe_kobj = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		const char *name = port_to_ethname(PORT_ALLOWLIST[i]);

		port_attrs[i].port_idx = PORT_ALLOWLIST[i];

		/* enable attribute (rw) */
		port_attrs[i].enable_attr.attr.name = "enable";
		port_attrs[i].enable_attr.attr.mode = 0644;
		port_attrs[i].enable_attr.show = enable_show;
		port_attrs[i].enable_attr.store = enable_store;

		/* mode attribute (ro) */
		port_attrs[i].mode_attr.attr.name = "mode";
		port_attrs[i].mode_attr.attr.mode = 0444;
		port_attrs[i].mode_attr.show = mode_show;
		port_attrs[i].mode_attr.store = NULL;

		port_attrs[i].port_kobj = kobject_create_and_add(name,
								  er6p_poe_kobj);
		if (!port_attrs[i].port_kobj) {
			pr_err("er6p-poe: failed to create sysfs dir for %s\n",
			       name);
			goto err_cleanup;
		}

		if (sysfs_create_file(port_attrs[i].port_kobj,
				      &port_attrs[i].enable_attr.attr)) {
			pr_err("er6p-poe: failed to create enable for %s\n",
			       name);
			kobject_put(port_attrs[i].port_kobj);
			port_attrs[i].port_kobj = NULL;
			goto err_cleanup;
		}

		if (sysfs_create_file(port_attrs[i].port_kobj,
				      &port_attrs[i].mode_attr.attr)) {
			pr_err("er6p-poe: failed to create mode for %s\n",
			       name);
			sysfs_remove_file(port_attrs[i].port_kobj,
					  &port_attrs[i].enable_attr.attr);
			kobject_put(port_attrs[i].port_kobj);
			port_attrs[i].port_kobj = NULL;
			goto err_cleanup;
		}

		pr_info("er6p-poe: created sysfs entries for %s\n", name);
	}

	return 0;

err_cleanup:
	while (--i >= 0) {
		if (port_attrs[i].port_kobj) {
			sysfs_remove_file(port_attrs[i].port_kobj,
					  &port_attrs[i].enable_attr.attr);
			sysfs_remove_file(port_attrs[i].port_kobj,
					  &port_attrs[i].mode_attr.attr);
			kobject_put(port_attrs[i].port_kobj);
			port_attrs[i].port_kobj = NULL;
		}
	}
	kobject_put(er6p_poe_kobj);
	er6p_poe_kobj = NULL;
	return -ENOMEM;
}

void er6p_poe_sysfs_exit(void)
{
	int i;

	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		if (port_attrs[i].port_kobj) {
			sysfs_remove_file(port_attrs[i].port_kobj,
					  &port_attrs[i].enable_attr.attr);
			sysfs_remove_file(port_attrs[i].port_kobj,
					  &port_attrs[i].mode_attr.attr);
			kobject_put(port_attrs[i].port_kobj);
			port_attrs[i].port_kobj = NULL;
		}
	}

	if (er6p_poe_kobj) {
		sysfs_remove_file(er6p_poe_kobj, &budget_attr.attr);
		kobject_put(er6p_poe_kobj);
		er6p_poe_kobj = NULL;
	}
}
