#ifndef AES_H
#define AES_H

class AES {
public:
    // hardcoded most times, don't change
    static const int NB = 4;
    static const int NK = 4;
    static const int NR = 10;

private:
    unsigned char sbox[256];
    unsigned char inv_sbox[256];
    unsigned char rcon[11] = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    unsigned char key_expanded[4][NB * (NR + 1)];
    unsigned char state[4][NB];
    void init_sbox();

    void key_expansion(unsigned char*);
    void sub_bytes(bool);
    void shift_rows(bool);
    void mix_columns(bool);
    void add_round_key(int);
    void print_state() const;

    // helper functions
    unsigned char rotl8(const unsigned char&, const unsigned char&) const;
    unsigned char mul_by_02(const unsigned char) const;
    unsigned char mul_by_03(const unsigned char) const;
    unsigned char mul_by_09(const unsigned char) const;
    unsigned char mul_by_0b(unsigned char) const;
    unsigned char mul_by_0d(unsigned char) const;
    unsigned char mul_by_0e(unsigned char) const;

public:
    unsigned char* decrypt(unsigned char*);
    unsigned char* encrypt(unsigned char*);
    void set_key(unsigned char*);

    AES();
};
#endif
