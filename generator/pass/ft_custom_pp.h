#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef FT_GENERATOR
extern uint8_t __ft_get_byte();

inline void __ft_get_bytes(uint8_t* buffer, size_t nbytes) {
    for (size_t i = 0; i < nbytes; i++) {
        buffer[i] ^= __ft_get_byte();
    }
}
inline bool __ft_bool_default_true() {
    uint8_t val = 0;
    __ft_get_bytes(&val, 1);
    return val == 0;
}
#else
#define __ft_bool_default_true() true
#define __ft_get_bytes(buffer, nbytes)
#endif


#define __ft_mutate_const_size(val) __ft_get_bytes((uint8_t*)&val, sizeof(val))