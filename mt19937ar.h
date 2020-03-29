#ifndef MT19937AR_H_
#define MT19937AR_H_

#include <stdint.h>

void init_by_array(uint32_t init_key[], int key_length);
uint32_t genrand_int32();

#endif