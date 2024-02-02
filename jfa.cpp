#include <fstream>
#include <string>
#include <iostream>
#include "jfa.h"

using namespace std;

unsigned char* JFA::encrypt_block(unsigned char* p_data) {
    unsigned char* enc_data = encrypt(p_data);
    unsigned char* result = new unsigned char[6 * NB];
    for (int i = 0; i < 6 * NB; i++)
        result[i] = 0;

    int sum_data = 0, sum_key = 0;
    for (int i = 0; i < 4 * NB; i++)
        sum_data += enc_data[i];
    for (int i = 0; i < 4 * NK; i++)
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
    for (int i = 0; i < 6 * NB; i++) {
        if (not has(i, idxs, 8)) {
            result[i] = enc_data[enc_data_idx];
            enc_data_idx++;
        }
    }
    int new_modulo = 0;
    for (int i = 0; i < 6 * NB; i++)
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


unsigned char* JFA::decrypt_block(unsigned char* p_data) {
    unsigned char clean_data[4 * NB];

    int sum_data = 0, sum_key = 0;
    for (int i = 0; i < 6 * NB; i++)
        sum_data += p_data[i];
    for (int i = 0; i < 4 * NK; i++)
        sum_key += key[i];
    int idxs[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    idxs[0] = sum_data % 24;
    for (int i = 0; i < 7; i++)
        idxs[i + 1] = (p_data[idxs[i]] - sum_key % 16) % 24;

    int clean_data_idx = 0;
    for (int i = 0; i < 6 * NB; i++) {
        if (not has(i, idxs, 8)) {
            clean_data[clean_data_idx] = p_data[i];
            clean_data_idx++;
        }
    }

    unsigned char* result = decrypt(clean_data);
    return result;
}


void JFA::set_key(unsigned char* p_key) {
    AES::set_key(p_key);
}


inline bool JFA::has(const int& p_what, const int* p_array, const int& p_size) const {
    for (int i = 0; i < p_size; i++)
        if (p_array[i] == p_what)
            return true;
    return false;
}
