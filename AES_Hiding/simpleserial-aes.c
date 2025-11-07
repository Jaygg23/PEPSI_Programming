#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include "aes_hiding.h"
#define dummy_num 4 // 추가할 더미 개수

unsigned char KEY[16] = { 0, };


void Encrypt(AES_STATE_t PT, AES128_KEY_t KEY, AES_STATE_t CT)
{
    //srand(12345);
    int shuff_idxs[18];
    for (int i = 0; i < 18; i++) shuff_idxs[i] = i;

    unsigned char RoundKey[11][16];
    for (int i = 0; i < 16; i++)
    {
        RoundKey[0][i] = KEY[i];
        CT[i] = PT[i];
    }

    KeySchedule128(RoundKey);
    AddRoundKey(CT, RoundKey[0]);

    //1~9 라운드
    for (int round = 0; round < 9; round++)
    {
        Fisher_Yates_shuffle(shuff_idxs, 18);
        if (round == 0)
            trigger_high();
        SubBytes_Hiding(CT, dummy_num, round, shuff_idxs);
        if (round == 0)
            trigger_low();
        ShiftRows_Hiding(CT, dummy_num, round);
        MixColumns_Hiding(CT, dummy_num, round);
        AddRoundKey_Hiding(CT, RoundKey[round + 1], dummy_num, round);

    }
    SubBytes_Hiding(CT, dummy_num, 9, shuff_idxs);
    ShiftRows_Hiding(CT, dummy_num, 9);
    AddRoundKey_Hiding(CT, RoundKey[10], dummy_num, 9);
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
