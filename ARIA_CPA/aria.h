#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

typedef uint8_t ARIA_STATE_t[16]; // 128-bit block
typedef uint8_t ARIA128_KEY_t[16]; // 128-bit masterkey

void AddRoundKey(unsigned char state[], unsigned char key[]);
void word_XOR(unsigned char a[], const unsigned char b[]);
int32_t StatetoWord(uint32_t x);
uint32_t StatetoWord_1(uint32_t x);
void LT_layer(unsigned char state[16]);
void LT_1_layer(unsigned char state[16]);
void DiffLayer(unsigned char state[]);
void Fo(unsigned char state[], unsigned char key[]);
void Fe(unsigned char state[], unsigned char key[]);
void Ff(unsigned char state[], unsigned char key_11[], unsigned char key_12[]);
void  RoR_128bit(const uint8_t in[16], uint8_t out[16], int n);
void RoL_128bit(const uint8_t in[16], uint8_t out[16], int n);
void KeySchedule128(unsigned char key[][16]);
void ARIA128_enc(ARIA_STATE_t P, ARIA_STATE_t C, ARIA128_KEY_t K128);