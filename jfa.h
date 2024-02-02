#ifndef JFA_H
#define JFA_H
#include "aes.h"
#include <string>

class JFA {
    AES aes;
    unsigned char* key;

    inline bool has(const int&, const int*, const int&) const;

public:
    enum Result {
        OK = 0,
        CANT_OPEN_INPUT_FILE = 1,
        CANT_OPEN_KEY_FILE = 2,
        CANT_WRITE_TO_OUTPUT_FILE = 3
    };

    unsigned char* encrypt_block(unsigned char*);
    unsigned char* decrypt_block(unsigned char*);
    void set_key(unsigned char*);
    Result encrypt_file(std::string, std::string, std::string);
    Result decrypt_file(std::string, std::string, std::string);
};

#endif
