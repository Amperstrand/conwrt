#ifndef ER6P_POE_ENGINE_H
#define ER6P_POE_ENGINE_H

#include "er6p-poe-types.h"

void er6p_poe_state_init(void);
int er6p_poe_enable(int port_idx);
int er6p_poe_disable(int port_idx);
void er6p_poe_disable_all(void);
struct poe_port_state *er6p_poe_get_state(int port_idx);

#endif
