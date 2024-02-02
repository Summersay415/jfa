#ifndef JFA_H
#define JFA_H
#include "aes.h"

class JFA : protected AES {
    inline bool has(const int&, const int*, const int&) const;

public:
    unsigned char* encrypt_block(unsigned char*);
    unsigned char* decrypt_block(unsigned char*);
    void set_key(unsigned char*);
};

#endif
