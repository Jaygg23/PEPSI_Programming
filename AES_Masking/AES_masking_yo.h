//#define xtimes(input) (((input)<<1)^(((input)>>7)*0x1b)) // 함수
#define xtimes(f) ((((f) >> 7 & 0x01) == 1) ? ((f) << 1) ^ 0x1b : (f) << 1) // 분기문

typedef uint8_t AES_STATE_t[16]; // 128-bit block
typedef uint8_t AES128_KEY_t[16]; // 128-bit masterkey

extern unsigned char M_Sbox[256];

void AddRoundKey(unsigned char string[], unsigned char key[]);
void SubBytes(unsigned char string[]);
void ShiftRows(unsigned char string[]);
void MixColumns(unsigned char string[]);
void KeySchedule128(unsigned char key[][16]);

/***********  마스킹 값 생성  **********/
void Masked_Plaintext(unsigned char state[], unsigned char m1p, unsigned char m2p, unsigned char m3p, unsigned char m4p);
void make_masking_value(unsigned char* m, unsigned char* mp, unsigned char* m1, unsigned char* m2, unsigned char* m3, unsigned char* m4);
void calculate_mp_value(unsigned char m1, unsigned char m2, unsigned char m3, unsigned char m4, unsigned char* m1p, unsigned char* m2p, unsigned char* m3p, unsigned char* m4p);
void build_msbox(uint8_t M_SBox[256], uint8_t m, uint8_t mp);

/***********  마스킹 적용 함수  **********/
void Masked_KeySchedule128(unsigned char key[][16], unsigned char m, unsigned char mp, unsigned char m1, unsigned char m2, unsigned char m3, unsigned char m4, 
    unsigned char m1p, unsigned char m2p, unsigned char m3p, unsigned char m4p);
void Masked_SubBytes(unsigned char string[]);
void Masked_ShiftRows(unsigned char state[], unsigned char mp, unsigned char m1, unsigned char m2, unsigned char m3, unsigned char m4);
