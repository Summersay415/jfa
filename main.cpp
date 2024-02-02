#include <cstring>
#include <iostream>
#include "jfa.h"

using namespace std;


void print_help(char* launch_command) {
    cout << "Usage: " << launch_command << " <mode> <input file path> <key path> <output file path>, where:" << endl;
    cout << "mode - encrypt/decrypt;" << endl;
    cout << "input file path - path to file to be encrypted/decrypted;" << endl;
    cout << "input file path - path to file to be encrypted/decrypted;" << endl;
    cout << "output file path - path to file in which result of encryption/decryption will be written (if file already exists, it will be overwritten)." << endl;
}


int main(int argc, char** argv) {
    if (argc == 2) {
        if (strcmp(argv[1], "help") == 0) {
            print_help(argv[0]);
            return 0;
        }
    }

    if (argc != 5) {
        cout << "Incorrect arguments count." << endl;
        cout << "Run \"" << argv[0] << " help\" to see the usage." << endl;
        return 0;
    }

    bool is_encrypting = strcmp(argv[1], "encrypt") == 0;
    bool is_decrypting = strcmp(argv[1], "decrypt") == 0;
    if (not is_decrypting and not is_encrypting) {
        cout << "Incorrect mode specified. Possible values: encrypt, decrypt." << endl;
        cout << "Run \"" << argv[0] << " help\" to see the usage." << endl;
        return 0;
    }

    JFA::Result result;
    JFA jfa;
    string input_file_path(argv[2]);
    string key_file_path(argv[3]);
    string output_file_path(argv[4]);

    if (is_encrypting) {
        cout << "Encrypting..." << endl;
        result = jfa.encrypt_file(input_file_path, key_file_path, output_file_path);
    }
    if (is_decrypting) {
        cout << "Decrypting..." << endl;
        result = jfa.decrypt_file(input_file_path, key_file_path, output_file_path);
    }

    switch (result) {
        case JFA::Result::CANT_OPEN_INPUT_FILE:
            cout << "Input file doesn't exists or permission denied!" << endl;
            return -result;
        case JFA::Result::CANT_OPEN_KEY_FILE:
            cout << "Key file doesn't exists or permission denied!" << endl;
            return -result;
        case JFA::Result::CANT_WRITE_TO_OUTPUT_FILE:
            cout << "Permission to write in output file is denied!" << endl;
            return -result;
        default:
            cout << "Success!" << endl;
            break;
    }
    return 0;
}


/*unsigned char* string_to_hex(string& from, int size) {
    unsigned char* result = new unsigned char[size];

    for (int i = 0; i < size; i++) {
        if (i * 2 >= from.size())
            break;

        if (from[i * 2] >= '0' and from[i * 2] <= '9')
            result[i] = 16 * (from[i * 2] - '0');
        else if (from[i * 2] >= 'a' and from[i * 2] <= 'f')
            result[i] = 16 * (from[i * 2] - 'a' + 10);

        if (from[i * 2 + 1] >= '0' and from[i * 2 + 1] <= '9')
            result[i] += from[i * 2 + 1] - '0';
        else if (from[i * 2 + 1] >= 'a' and from[i * 2 + 1] <= 'f')
            result[i] += from[i * 2 + 1] - 'a' + 10;
    }

    return result;
}

string hex_to_string(unsigned char* from, int size) {
    stringstream ss;
    for (int i = 0; i < size; i++)
        ss << hex << setfill('0') << setw(2) << right << (unsigned int)from[i];
    return ss.str();
}*/
