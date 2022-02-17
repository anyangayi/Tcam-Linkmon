#ifndef RAW_NIC_TX_H
#define RAW_NIC_TX_H
#include <stdint.h>
LW_SYMBOL_EXPORT void abscom_hooked_nic_tx(uint8_t *buf,size_t length);
#endif
