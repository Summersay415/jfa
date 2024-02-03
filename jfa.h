#ifndef JFA_H
#define JFA_H
#include "aes.h"

class JFA : protected AES {
    inline bool has(const int& p_what, const int* p_array, const int& p_size) const;

public:
    uint8_t* encrypt_block(uint8_t* p_block);
    uint8_t* decrypt_block(uint8_t* p_block);
    void set_key(uint8_t* p_key);
};

#endif
