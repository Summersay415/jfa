#include <fstream>
#include <string>
#include <iostream>
#include "jfa.h"

using namespace std;

unsigned char* JFA::encrypt_block(unsigned char* data) {
    unsigned char* enc_data = aes.encrypt(data);
    unsigned char* result = new unsigned char[6 * aes.NB];
    for (int i = 0; i < 6 * aes.NB; i++)
        result[i] = 0;

    int sum_data = 0, sum_key = 0;
    for (int i = 0; i < 4 * aes.NB; i++)
        sum_data += enc_data[i];
    for (int i = 0; i < 4 * aes.NK; i++)
        sum_key += key[i];
    int need_modulo = (sum_data + sum_key + 15) % 24;
    const int magic_nums[8] = {27, 33, 9, 11, 63, 77, 55, 43};
    int idxs[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    idxs[0] = need_modulo;
    for (int i = 0; i < 7; i++) {
        int next_idx = (magic_nums[i] * sum_data) % 24;
        while (has(next_idx, idxs, 8))
            next_idx = (next_idx + 1) % 24;
        idxs[i + 1] = next_idx;
        result[idxs[i]] = ((magic_nums[i] * sum_key + sum_data) % 10) * 24 + next_idx + sum_key % 16;
    }

    int enc_data_idx = 0;
    for (int i = 0; i < 6 * aes.NB; i++) {
        if (not has(i, idxs, 8)) {
            result[i] = enc_data[enc_data_idx];
            enc_data_idx++;
        }
    }
    int new_modulo = 0;
    for (int i = 0; i < 6 * aes.NB; i++)
        new_modulo += result[i];
    new_modulo %= 24;
    int add = 0;
    if (new_modulo < need_modulo)
        add = need_modulo - new_modulo;
    else if (new_modulo > need_modulo)
        add = 24 - new_modulo + need_modulo;
    result[idxs[7]] = ((magic_nums[7] * sum_key + sum_data) % 10) * 24 + add;

    delete[] enc_data;
    return result;
}


unsigned char* JFA::decrypt_block(unsigned char* data) {
    unsigned char clean_data[4 * aes.NB];

    int sum_data = 0, sum_key = 0;
    for (int i = 0; i < 6 * aes.NB; i++)
        sum_data += data[i];
    for (int i = 0; i < 4 * aes.NK; i++)
        sum_key += key[i];
    int idxs[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    idxs[0] = sum_data % 24;
    for (int i = 0; i < 7; i++)
        idxs[i + 1] = (data[idxs[i]] - sum_key % 16) % 24;

    int clean_data_idx = 0;
    for (int i = 0; i < 6 * aes.NB; i++) {
        if (not has(i, idxs, 8)) {
            clean_data[clean_data_idx] = data[i];
            clean_data_idx++;
        }
    }

    unsigned char* result = aes.decrypt(clean_data);
    return result;
}


JFA::Result JFA::encrypt_file(string input_path, string key_path, string output_path) {
    ifstream finput(input_path, ios_base::binary);
    ifstream fkey(key_path, ios_base::binary);
    ofstream foutput(output_path, ios_base::binary);

    if (not finput.is_open())
        return Result::CANT_OPEN_INPUT_FILE;
    if (not fkey.is_open())
        return Result::CANT_OPEN_KEY_FILE;
    if (not foutput.is_open())
        return Result::CANT_WRITE_TO_OUTPUT_FILE;

    unsigned char key_data[4 * aes.NB];
    for (int i = 0; i < 4 * aes.NB; i++)
        key_data[i] = fkey.get();
    set_key(key_data);

    unsigned char block[4 * aes.NB];
    int idx = 0;
    while (true) {
        int byte = finput.get();
        if (byte < 0)
            break;
        block[idx] = byte;
        idx++;
        if (idx == 4 * aes.NB) {
            idx = 0;
            unsigned char* enc_block = encrypt_block(block);
            foutput.write(reinterpret_cast<char*>(enc_block), 6 * aes.NB);
            delete[] enc_block;
        }
    }

    if (idx != 0) {
        bool writed_one = false;
        for (int i = idx; i < 4 * aes.NB; i++) {
            if (not writed_one) {
                block[i] = 1;
                writed_one = true;
                continue;
            }
            block[i] = 0;
        }
        unsigned char* enc_block = encrypt_block(block);
        foutput.write(reinterpret_cast<char*>(enc_block), 6 * aes.NB);
        delete[] enc_block;
    }

    finput.close();
    fkey.close();
    foutput.close();
    return Result::OK;
}


JFA::Result JFA::decrypt_file(string input_path, string key_path, string output_path) {
    ifstream finput(input_path, ios_base::binary);
    ifstream fkey(key_path, ios_base::binary);
    ofstream foutput(output_path, ios_base::binary);

    if (not finput.is_open())
        return Result::CANT_OPEN_INPUT_FILE;
    if (not fkey.is_open())
        return Result::CANT_OPEN_KEY_FILE;
    if (not foutput.is_open())
        return Result::CANT_WRITE_TO_OUTPUT_FILE;

    unsigned char key_data[4 * aes.NB];
    for (int i = 0; i < 4 * aes.NB; i++)
        key_data[i] = fkey.get();
    set_key(key_data);

    unsigned char block[6 * aes.NB];
    int idx = 0;
    while (true) {
        int byte = finput.get();
        if (byte < 0)
            break;
        block[idx] = byte;
        idx++;
        if (idx == 6 * aes.NB) {
            idx = 0;
            unsigned char* decrypted_data = decrypt_block(block);
            if ((decrypted_data[4 * aes.NB - 1] == 0 or decrypted_data[4 * aes.NB - 1] == 1) and finput.eof()) {
                int stop_idx;
                for (int i = 4 * aes.NB - 1; i > 0; i--) {
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


void JFA::set_key(unsigned char* key) {
    aes.set_key(key);
    this->key = key;
}


inline bool JFA::has(const int& what, const int* array, const int& size) const {
    for (int i = 0; i < size; i++)
        if (array[i] == what)
            return true;
    return false;
}
