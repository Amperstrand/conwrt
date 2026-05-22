#include <linux/kernel.h>
#include <linux/errno.h>
#include "er6p-poe-engine.h"
#include "er6p-poe-gpio.h"
#include "er6p-poe-allowlist.h"

static struct poe_port_state port_states[PORT_ALLOWLIST_LEN];

void er6p_poe_state_init(void)
{
	int i;

	for (i = 0; i < PORT_ALLOWLIST_LEN; i++) {
		port_states[i].port_idx = PORT_ALLOWLIST[i];
		port_states[i].mode = POE_MODE_OFF;
		port_states[i].enabled = false;
	}
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

	state = er6p_poe_get_state(port_idx);
	if (!state)
		return -EINVAL;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_48V_PAIRMODE, false);
	if (ret)
		return ret;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, false);
	if (ret)
		return ret;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, true);
	if (ret)
		return ret;

	state->enabled = true;
	state->mode = POE_MODE_24V_2PAIR;
	return 0;
}

int er6p_poe_disable(int port_idx)
{
	int ret;
	struct poe_port_state *state;

	state = er6p_poe_get_state(port_idx);
	if (!state)
		return -EINVAL;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_24V_POWER, false);
	if (ret)
		return ret;

	ret = er6p_poe_gpio_set(port_idx, POE_GPIO_48V_PAIRMODE, false);
	if (ret)
		return ret;

	state->enabled = false;
	state->mode = POE_MODE_OFF;
	return 0;
}

void er6p_poe_disable_all(void)
{
	int i;

	for (i = 0; i < POE_GPIO_MAP_LEN; i++)
		er6p_poe_disable(POE_GPIO_MAP[i].port_idx);
}
