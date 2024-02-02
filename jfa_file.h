#ifndef JFA_FILE_H
#define JFA_FILE_H
#include <string>
#include "jfa.h"

class JFAFile : protected JFA {
public:
    enum Result {
        OK = 0,
        CANT_OPEN_INPUT_FILE = 1,
        CANT_OPEN_KEY_FILE = 2,
        CANT_WRITE_TO_OUTPUT_FILE = 3
    };

    Result encrypt_file(std::string, std::string, std::string);
    Result decrypt_file(std::string, std::string, std::string);
    Result generate_key(std::string) const;
};

#endif
