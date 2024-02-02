#include <cstring>
#include <iostream>
#include "jfa_file.h"

using namespace std;


const char VERSION[10] = "0.1";


void print_help(char* p_launch_command) {
    cout << "Junk Fill Algorithm (based on AES) - version " << VERSION << '.' << endl;
    cout << endl;
    cout << "Usage: " << p_launch_command << " <mode> [arguments]" << endl;
    cout << "Supports 3 modes:" << endl;
    cout << "Encrypt/decrypt - arguments: <input file path> <key file path> [output file path]" << endl;
    cout << " input file path - path to file to be encrypted/decrypted;" << endl;
    cout << " key file path - path to key file;" << endl;
    cout << " output file path (optional) - path to file in which result of encryption/decryption will be written." << endl;
    cout << "Description: encrypts or decrypts given file with given key, writing result to given file. Key file must be at least 16 byte size, you can generate one with \"generate\" mode." << endl;
    cout << "Notes: if output file already exists, it will be overwritten; if output file path is not given, defaults to \"<input file path>.jfaenc\" or \"<input file path>.jfadec\"" << endl;
    cout << endl;
    cout << "Generate - arguments: [output file path]" << endl;
    cout << " output file path (optional) - path to file in which generated key will be written." << endl;
    cout << "Description: generates random key with standard C++ library, and writes result to given path." << endl;
    cout << "Notes: if output file already exists, it will be overwritten; if output file path is not given, defaults to \"key.jfa\"" << endl;
    cout << endl;
    cout << "Author: Summersay415 (https://github.com/Summersay415)" << endl;
    cout << "License: none" << endl;
}


int main(int p_argc, char** p_argv) {
    if (p_argc == 2) {
        if (strcmp(p_argv[1], "help") == 0) {
            print_help(p_argv[0]);
            return 0;
        }
    }

    if (p_argc < 2) {
        cout << "No arguments specified." << endl;
        cout << "Run \"" << p_argv[0] << " help\" to see the usage." << endl;
        return 0;
    }

    bool is_encrypting = strcmp(p_argv[1], "encrypt") == 0;
    bool is_decrypting = strcmp(p_argv[1], "decrypt") == 0;
    bool is_generating = strcmp(p_argv[1], "generate") == 0;
    if (not is_decrypting and not is_encrypting and not is_generating) {
        cout << "Incorrect mode specified. Possible values: encrypt, decrypt, generate." << endl;
        cout << "Run \"" << p_argv[0] << " help\" to learn more." << endl;
        return 0;
    }

    JFAFile::Result result;
    JFAFile jfa;
    if (is_encrypting or is_decrypting) {
        if (p_argc < 4 or p_argc > 5) {
            cout << "Incorrect arguments count." << endl;
            cout << "Run \"" << p_argv[0] << " help\" to see the usage." << endl;
            return 0;
        }
        string input_file_path = p_argv[2];
        string key_file_path = p_argv[3];
        string output_file_path;

        if (p_argc == 4) {
            if (is_encrypting)
                output_file_path = input_file_path + ".jfaenc";
            else
                output_file_path = input_file_path + ".jfadec";
        }
        else
            output_file_path = p_argv[4];

        if (is_encrypting) {
            cout << "Encrypting..." << endl;
            result = jfa.encrypt_file(input_file_path, key_file_path, output_file_path);
        }
        else if (is_decrypting) {
            cout << "Decrypting..." << endl;
            result = jfa.decrypt_file(input_file_path, key_file_path, output_file_path);
        }
    }
    else if (is_generating) {
        if (p_argc > 3) {
            cout << "Incorrect arguments count." << endl;
            cout << "Run \"" << p_argv[0] << " help\" to see the usage." << endl;
            return 0;
        }
        string output_file_path;

        if (p_argc == 2)
            output_file_path = "key.jfa";
        else
            output_file_path = p_argv[2];

        result = jfa.generate_key(output_file_path);
    }

    switch (result) {
        case JFAFile::Result::CANT_OPEN_INPUT_FILE:
            cout << "Input file doesn't exists or permission denied!" << endl;
            return -result;
        case JFAFile::Result::CANT_OPEN_KEY_FILE:
            cout << "Key file doesn't exists or permission denied!" << endl;
            return -result;
        case JFAFile::Result::CANT_WRITE_TO_OUTPUT_FILE:
            cout << "Permission to write in output file is denied!" << endl;
            return -result;
        default:
            cout << "Success!" << endl;
            break;
    }
    return 0;
}
