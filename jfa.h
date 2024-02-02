#ifndef JFA_H
#define JFA_H
#include "aes.h"

class JFA : protected AES {
    inline bool has(const int& p_what, const int* p_array, const int& p_size) const;

public:
    unsigned char* encrypt_block(unsigned char* p_block);
    unsigned char* decrypt_block(unsigned char* p_block);
    void set_key(unsigned char* p_key);
};

#endif
