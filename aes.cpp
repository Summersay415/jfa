#include "aes.h"


void AES::key_expansion() {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB * (NR + 1); j++)
            key_expanded[i][j] = 0;

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NK; j++)
            key_expanded[i][j] = key[i + j * 4];

    int s_idxs[4] = {4, 4, 4, 4};
    for (int c = NK; c < NB * (NR + 1); c++) {
        if (c % NK == 0) {
            unsigned char tmp[4];
            for (int i = 1; i < 4; i++)
                tmp[i - 1] = key_expanded[i][c - 1];
            tmp[4 - 1] = key_expanded[0][c - 1];

            for (int i = 0; i < 4; i++)
                tmp[i] = sbox[tmp[i]];

            for (int r = 0; r < 4; r++) {
                unsigned char s;
                if (r == 0)
                    s = key_expanded[r][c - 4] ^ tmp[r] ^ rcon[c / NK];
                else
                    s = key_expanded[r][c - 4] ^ tmp[r] ^ 0;
                key_expanded[r][s_idxs[r]] = s;
                s_idxs[r]++;
            }
        }
        else {
            for (int r = 0; r < 4; r++) {
                unsigned char s = key_expanded[r][c - 4] ^ key_expanded[r][c - 1];
                key_expanded[r][s_idxs[r]] = s;
                s_idxs[r]++;
            }
        }
    }
}


void AES::sub_bytes(bool p_inverted) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB; j++)
            state[i][j] = p_inverted ? inv_sbox[state[i][j]] : sbox[state[i][j]];
}


void AES::shift_rows(bool p_inverted) {
    unsigned char temp;
    if (p_inverted) {
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        temp = state[2][3];
        state[2][3] = state[2][1];
        state[2][1] = temp;
        temp = state[2][2];
        state[2][2] = state[2][0];
        state[2][0] = temp;

        temp = state[3][3];
        state[3][3] = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = temp;
    }
    else {
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
    }
}


void AES::mix_columns(bool p_inverted) {
    for (int i = 0; i < NB; i++) {
        unsigned char s0, s1, s2, s3;
        if (p_inverted) {
            s0 = mul_by_0e(state[0][i]) ^ mul_by_0b(state[1][i]) ^ mul_by_0d(state[2][i]) ^ mul_by_09(state[3][i]);
            s1 = mul_by_09(state[0][i]) ^ mul_by_0e(state[1][i]) ^ mul_by_0b(state[2][i]) ^ mul_by_0d(state[3][i]);
            s2 = mul_by_0d(state[0][i]) ^ mul_by_09(state[1][i]) ^ mul_by_0e(state[2][i]) ^ mul_by_0b(state[3][i]);
            s3 = mul_by_0b(state[0][i]) ^ mul_by_0d(state[1][i]) ^ mul_by_09(state[2][i]) ^ mul_by_0e(state[3][i]);
        }
        else {
            s0 = mul_by_02(state[0][i]) ^ mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i];
            s1 = state[0][i] ^ mul_by_02(state[1][i]) ^ mul_by_03(state[2][i]) ^ state[3][i];
            s2 = state[0][i] ^ state[1][i] ^ mul_by_02(state[2][i]) ^ mul_by_03(state[3][i]);
            s3 = mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul_by_02(state[3][i]);
        }
        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}


void AES::add_round_key(int p_round) {
    for (int c = 0; c < NK; c++)
        for (int j = 0; j < 4; j++)
            state[j][c] = state[j][c] ^ key_expanded[j][NB * p_round + c];
}


unsigned char* AES::encrypt(unsigned char* p_data) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB; j++)
            state[i][j] = p_data[i + 4 * j];
    add_round_key(0);

    for (int i = 1; i < NR; i++) {
        sub_bytes(false);
        shift_rows(false);
        add_round_key(i);
        mix_columns(false);
    }

    sub_bytes(false);
    shift_rows(false);
    add_round_key(NR);

    unsigned char* result = new unsigned char[4 * NB];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB; j++)
            result[i + 4 * j] = state[i][j];

    return result;
}


unsigned char* AES::decrypt(unsigned char* p_data) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB; j++)
            state[i][j] = p_data[i + 4 * j];
    add_round_key(NR);

    for (int i = NR - 1; i > 0; i--) {
        sub_bytes(true);
        shift_rows(true);
        mix_columns(true);
        add_round_key(i);
    }

    sub_bytes(true);
    shift_rows(true);
    add_round_key(0);

    unsigned char* result = new unsigned char[4 * NB];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < NB; j++)
            result[i + 4 * j] = state[i][j];

    return result;
}


void AES::set_key(unsigned char* p_key) {
    for (int i = 0; i < 4 * NK; i++)
        this->key[i] = p_key[i];
    key_expansion();
}


void AES::init_sbox() {
    // generate sbox
    unsigned char p = 1, q = 1;
    do {
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        unsigned char xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
    // generate inv sbox
    for (unsigned int i = 0; i < 256; i++)
        inv_sbox[sbox[i]] = i;
}


AES::AES() {
    init_sbox();
}

// helper functions
inline unsigned char AES::rotl8(const unsigned char& p_x, const unsigned char& p_shift) const {
    return (p_x << p_shift) | (p_x >> (8 - p_shift));
}

inline unsigned char AES::mul_by_02(const unsigned char p_num) const {
    if (p_num < 0x80)
        return p_num << 1;
    else
        return (p_num << 1) ^ 0x1b;
}

inline unsigned char AES::mul_by_03(const unsigned char p_num) const {
    return mul_by_02(p_num) ^ p_num;
}

inline unsigned char AES::mul_by_09(const unsigned char p_num) const {
    return mul_by_02(mul_by_02(mul_by_02(p_num))) ^ p_num;
}

inline unsigned char AES::mul_by_0b(const unsigned char p_num) const {
    return mul_by_02(mul_by_02(mul_by_02(p_num))) ^ mul_by_02(p_num) ^ p_num;
}

inline unsigned char AES::mul_by_0d(const unsigned char p_num) const {
    return mul_by_02(mul_by_02(mul_by_02(p_num))) ^ mul_by_02(mul_by_02(p_num)) ^ p_num;
}

inline unsigned char AES::mul_by_0e(const unsigned char p_num) const {
    return mul_by_02(mul_by_02(mul_by_02(p_num))) ^ mul_by_02(mul_by_02(p_num)) ^ mul_by_02(p_num);
}
