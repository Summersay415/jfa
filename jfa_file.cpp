#include <fstream>
#include <cstdlib>
#include <ctime>
#include "jfa_file.h"

using namespace std;


JFAFile::Result JFAFile::encrypt_file(string p_input_path, string p_key_path, string p_output_path) {
    ifstream finput(p_input_path, ios_base::binary);
    ifstream fkey(p_key_path, ios_base::binary);
    ofstream foutput(p_output_path, ios_base::binary);

    if (not finput.is_open())
        return Result::CANT_OPEN_INPUT_FILE;
    if (not fkey.is_open())
        return Result::CANT_OPEN_KEY_FILE;
    if (not foutput.is_open())
        return Result::CANT_WRITE_TO_OUTPUT_FILE;

    uint8_t key_data[4 * NB];
    for (int i = 0; i < 4 * NB; i++)
        key_data[i] = fkey.get();
    set_key(key_data);

    uint8_t block[4 * NB];
    int idx = 0;
    while (true) {
        int byte = finput.get();
        if (byte < 0)
            break;
        block[idx] = byte;
        idx++;
        if (idx == 4 * NB) {
            idx = 0;
            uint8_t* enc_block = encrypt_block(block);
            foutput.write(reinterpret_cast<char*>(enc_block), 6 * NB);
            delete[] enc_block;
        }
    }

    if (idx != 0) {
        bool writed_one = false;
        for (int i = idx; i < 4 * NB; i++) {
            if (not writed_one) {
                block[i] = 1;
                writed_one = true;
                continue;
            }
            block[i] = 0;
        }
        uint8_t* enc_block = encrypt_block(block);
        foutput.write(reinterpret_cast<char*>(enc_block), 6 * NB);
        delete[] enc_block;
    }

    finput.close();
    fkey.close();
    foutput.close();
    return Result::OK;
}


JFAFile::Result JFAFile::decrypt_file(string p_input_path, string p_key_path, string p_output_path) {
    ifstream finput(p_input_path, ios_base::binary);
    ifstream fkey(p_key_path, ios_base::binary);
    ofstream foutput(p_output_path, ios_base::binary);

    if (not finput.is_open())
        return Result::CANT_OPEN_INPUT_FILE;
    if (not fkey.is_open())
        return Result::CANT_OPEN_KEY_FILE;
    if (not foutput.is_open())
        return Result::CANT_WRITE_TO_OUTPUT_FILE;

    uint8_t key_data[4 * NB];
    for (int i = 0; i < 4 * NB; i++)
        key_data[i] = fkey.get();
    set_key(key_data);

    uint8_t block[6 * NB];
    int idx = 0;
    while (true) {
        int byte = finput.get();
        if (byte < 0)
            break;
        block[idx] = byte;
        idx++;
        if (idx == 6 * NB) {
            idx = 0;
            uint8_t* decrypted_data = decrypt_block(block);
            if ((decrypted_data[4 * NB - 1] == 0 or decrypted_data[4 * NB - 1] == 1) and finput.eof()) {
                int stop_idx;
                for (int i = 4 * NB - 1; i > 0; i--) {
                    if (decrypted_data[i] == 1) {
                        stop_idx = i;
                        break;
                    }
                }
                for (int i = 0; i < stop_idx; i++)
                    foutput.write(reinterpret_cast<char*>(&(decrypted_data[i])), 1);
            }
            else
                foutput.write(reinterpret_cast<char*>(decrypted_data), 16);
            delete[] decrypted_data;
        }
    }

    finput.close();
    fkey.close();
    foutput.close();
    return Result::OK;
}


JFAFile::Result JFAFile::generate_key(string p_output_path) const {
    ofstream foutput(p_output_path, ios_base::binary);

    if (not foutput.is_open())
        return Result::CANT_WRITE_TO_OUTPUT_FILE;

    srand(time(nullptr));
    for (int i = 0; i < 16; i++) {
        int num = rand();
        foutput.write(reinterpret_cast<char*>(&num), 1);
    }

    foutput.close();
    return Result::OK;
}
