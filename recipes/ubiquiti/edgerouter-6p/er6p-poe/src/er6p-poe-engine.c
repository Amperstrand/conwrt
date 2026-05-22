#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include "er6p-poe-engine.h"
#include "er6p-poe-gpio.h"
#include "er6p-poe-allowlist.h"

/* Per-mode wattage estimates (conservative) */
#define WATT_24V_2PAIR  12
#define WATT_24V_4PAIR  25

static int power_budget_w = 50;
module_param(power_budget_w, int, 0644);
MODULE_PARM_DESC(power_budget_w, "Total PoE power budget in watts (default: 50)");

static int power_used_w;
static struct poe_port_state port_states[PORT_ALLOWLIST_LEN];

/* Protects power_used_w and port_states from concurrent sysfs writes */
static DEFINE_MUTEX(poe_state_lock);

static int poe_mode_watts(enum poe_mode mode)
{
	switch (mode) {
	case POE_MODE_24V_2PAIR:
		return WATT_24V_2PAIR;
	case POE_MODE_BOTH:
		return WATT_24V_4PAIR;
	default:
		return 0;
	}
}

void er6p_poe_state_init(void)
{
	int i;

	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		port_states[i].port_idx = PORT_ALLOWLIST[i];
		port_states[i].mode = POE_MODE_OFF;
		port_states[i].enabled = false;
	}
	power_used_w = 0;
}

struct poe_port_state *er6p_poe_get_state(int port_idx)
{
	int i;

	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		if (port_states[i].port_idx == port_idx)
			return &port_states[i];
	}
	return NULL;
}

int er6p_poe_enable(int port_idx)
{
	int ret;
	struct poe_port_state *state;
	int projected_w, mode_w;

	state = er6p_poe_get_state(port_idx);
	if (!state)
		return -EINVAL;

	mutex_lock(&poe_state_lock);

	if (state->enabled) {
		mutex_unlock(&poe_state_lock);
		return 0;
	}

	mode_w = poe_mode_watts(POE_MODE_24V_2PAIR);
	projected_w = power_used_w + mode_w;

	if (projected_w > power_budget_w) {
		pr_warn("er6p-poe: would exceed power budget: %dW > %dW (port %d)\n",
			projected_w, power_budget_w, port_idx);
		mutex_unlock(&poe_state_lock);
		return -EDQUOT;
	}

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_48V_PAIRMODE, false);
	if (ret)
		goto unlock;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, false);
	if (ret)
		goto rollback_pairmode;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, true);
	if (ret)
		goto rollback_pairmode;

	state->enabled = true;
	state->mode = POE_MODE_24V_2PAIR;
	power_used_w += mode_w;
	mutex_unlock(&poe_state_lock);
	return 0;

rollback_pairmode:
	er6p_poe_gpio_set(port_idx, POE_GPIO_48V_PAIRMODE, false);
unlock:
	mutex_unlock(&poe_state_lock);
	return ret;
}

int er6p_poe_disable(int port_idx)
{
	int ret;
	struct poe_port_state *state;

	state = er6p_poe_get_state(port_idx);
	if (!state)
		return -EINVAL;

	mutex_lock(&poe_state_lock);

	if (!state->enabled) {
		mutex_unlock(&poe_state_lock);
		return 0;
	}

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, false);
	if (ret) {
		mutex_unlock(&poe_state_lock);
		return ret;
	}

	er6p_poe_gpio_set(port_idx, POE_GPIO_48V_PAIRMODE, false);

	power_used_w -= poe_mode_watts(state->mode);
	if (WARN_ON(power_used_w < 0))
		power_used_w = 0;
	state->enabled = false;
	state->mode = POE_MODE_OFF;
	mutex_unlock(&poe_state_lock);
	return 0;
}

void er6p_poe_disable_all(void)
{
	int i;

	for (i = 0; i < POE_GPIO_MAP_LEN; i++)
		er6p_poe_disable(POE_GPIO_MAP[i].port_idx);
}

int er6p_poe_get_power_budget(void)
{
	return power_budget_w;
}

int er6p_poe_get_power_used(void)
{
	return power_used_w;
}
