#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include "AES_masking_yo.h"

unsigned char KEY[16] = { 0, };
/*
void Encrypt(AES_STATE_t PT, AES128_KEY_t KEY, AES_STATE_t CT)
{
    unsigned char RoundKey[11][16];
    for (int i = 0; i < 16; i++)
    {
        RoundKey[0][i] = KEY[i];
        CT[i] = PT[i];
    }

    KeySchedule128(RoundKey);

    AddRoundKey(CT, RoundKey[0]);

    //1~9 라운드
    for (int cnt_i = 0; cnt_i < 9; cnt_i++)
    {
        if (cnt_i == 0)
            trigger_high();
        SubBytes(CT);
        ShiftRows(CT);
        MixColumns(CT);
        AddRoundKey(CT, RoundKey[cnt_i + 1]);
        if (cnt_i == 0)
            trigger_low();
    }

    //마지막 10 라운드
    SubBytes(CT);
    ShiftRows(CT);
    AddRoundKey(CT, RoundKey[10]);
}
*/
void Encrypt(AES_STATE_t PT, AES128_KEY_t KEY, AES_STATE_t CT)
{
    unsigned char m, mp, m1, m2, m3, m4, m1p, m2p, m3p, m4p;

    unsigned char RoundKey[11][16];

    // 평문 기반으로 시드 생성
    uint8_t seed = 0;
    for (int i = 0; i < 16; i++) {
        seed = (seed * 131) + PT[i]; // 평문 바이트들을 차례대로 곱하고 더하면서 하나의 32비트 숫자로 섞어냄
        // 131, 33, 5381, 65599 같은 수는 이런 폴리노미얼 해시(polynomial rolling hash)에서 자주 쓰는 적당히 큰 홀수
        // 1. 첫 seed = 0에 PT[0]을 더함
        // 2. 다음 바이트부터는 seed를 131배 해준 다음 그 바이트를 더함
    }
    srand(seed);  // 평문 기반 난수 시드 설정

    for (int i = 0; i < 16; i++)
    {
        RoundKey[0][i] = KEY[i];
        CT[i] = PT[i];
    }

    make_masking_value(&m, &mp, &m1, &m2, &m3, &m4);
    calculate_mp_value(m1, m2, m3, m4, &m1p, &m2p, &m3p, &m4p);
    build_msbox(M_Sbox, m, mp); // M_Sbox 생성

    Masked_KeySchedule128(RoundKey, m, mp, m1, m2, m3, m4, m1p, m2p, m3p, m4p);
    Masked_Plaintext(CT, m1p, m2p, m3p, m4p);

    AddRoundKey(CT, RoundKey[0]);
    //1~9 라운드
    for (int round = 0; round < 9; round++)
    {
        if (round == 0)
            trigger_high();
        Masked_SubBytes(CT);
        Masked_ShiftRows(CT, mp, m1, m2, m3, m4);
        MixColumns(CT); // masking 적용 없이 기존 MixColumns 그대로 사용
        AddRoundKey(CT, RoundKey[round + 1]);
        if (round == 0)
            trigger_low();
    }

    //마지막 10 라운드
    Masked_SubBytes(CT);
    ShiftRows(CT);
    AddRoundKey(CT, RoundKey[10]);
}

uint8_t get_key(uint8_t* k, uint8_t len)
{
    unsigned char i = 0;
    for (i = 0; i < len; i++)
        KEY[i] = k[i];
    return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    unsigned char i = 0;
    unsigned char PT[16] = { 0, };
    unsigned char CT[16] = { 0, };
    for (i = 0; i < len; i++)
        PT[i] = pt[i];

    Encrypt(PT, KEY, CT); 

    simpleserial_put('r', 16, CT);
    return 0x00;
}


uint8_t reset(uint8_t* x, uint8_t len)
{
    unsigned char i = 0;
    for (i = 0; i < 16; i++)
        KEY[i] = 0;
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();
    simpleserial_addcmd('p', 16, get_pt);
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('x', 0, reset);
    while (1)
        simpleserial_get();
} 
