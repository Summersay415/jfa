#ifndef AES_H
#define AES_H
#include <cstdint>

class AES {
public:
    // hardcoded most times, don't change
    static const int NB = 4;
    static const int NK = 4;
    static const int NR = 10;

protected:
    uint8_t key[16];

private:
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
    uint8_t rcon[11] = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    uint8_t key_expanded[4][NB * (NR + 1)];
    uint8_t state[4][NB];
    void init_sbox();

    void key_expansion();
    void sub_bytes(bool p_inverted);
    void shift_rows(bool p_inverted);
    void mix_columns(bool p_inverted);
    void add_round_key(int p_round);

    // helper functions
    uint8_t rotl8(const uint8_t p_x, const uint8_t p_shift) const;
    uint8_t mul_by_02(const uint8_t p_num) const;
    uint8_t mul_by_03(const uint8_t p_num) const;
    uint8_t mul_by_09(const uint8_t p_num) const;
    uint8_t mul_by_0b(const uint8_t p_num) const;
    uint8_t mul_by_0d(const uint8_t p_num) const;
    uint8_t mul_by_0e(const uint8_t p_num) const;

public:
    uint8_t* decrypt_block(uint8_t* p_block);
    uint8_t* encrypt_block(uint8_t* p_block);
    void set_key(uint8_t* p_key);

    AES();
};
#endif
