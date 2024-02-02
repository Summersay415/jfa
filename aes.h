#ifndef AES_H
#define AES_H

class AES {
public:
    // hardcoded most times, don't change
    static const int NB = 4;
    static const int NK = 4;
    static const int NR = 10;

protected:
    unsigned char key[16];

private:
    unsigned char sbox[256];
    unsigned char inv_sbox[256];
    unsigned char rcon[11] = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    unsigned char key_expanded[4][NB * (NR + 1)];
    unsigned char state[4][NB];
    void init_sbox();

    void key_expansion();
    void sub_bytes(bool p_inverted);
    void shift_rows(bool p_inverted);
    void mix_columns(bool p_inverted);
    void add_round_key(int p_round);

    // helper functions
    unsigned char rotl8(const unsigned char p_x, const unsigned char p_shift) const;
    unsigned char mul_by_02(const unsigned char p_num) const;
    unsigned char mul_by_03(const unsigned char p_num) const;
    unsigned char mul_by_09(const unsigned char p_num) const;
    unsigned char mul_by_0b(const unsigned char p_num) const;
    unsigned char mul_by_0d(const unsigned char p_num) const;
    unsigned char mul_by_0e(const unsigned char p_num) const;

public:
    unsigned char* decrypt_block(unsigned char* p_block);
    unsigned char* encrypt_block(unsigned char* p_block);
    void set_key(unsigned char* p_key);

    AES();
};
#endif
