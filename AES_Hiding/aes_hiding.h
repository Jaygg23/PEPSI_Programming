#pragma once
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#ifndef AES_HIDING_H
#define AES_HIDING_H

/* ---------------- 매크로 ---------------- */
#define xtimes(f) ((((f) >> 7 & 0x01) == 1) ? ((f) << 1) ^ 0x1b : (f) << 1)
#define dummy_num 4
#define PATTERN_COUNT 20

extern const int precomputed_indices[PATTERN_COUNT][20];
extern const int precomputed_Shiftrows[PATTERN_COUNT][7];
extern const int precomputed_MixColumns[PATTERN_COUNT][8];

/* ---------------- 타입 정의 ---------------- */
typedef uint8_t AES_STATE_t[18];
typedef uint8_t AES128_KEY_t[16];

/* ---------------- AES Hiding 함수 ---------------- */
void SubBytes_Hiding(unsigned char state[], int dummy_count, int round, int shuff_idxs[18]);
void ShiftRows_Hiding(unsigned char state[], int dummy_count, int round);
void AddRoundKey_Hiding(unsigned char state[], unsigned char key[], int dummy_count, int round);
void MixColumns_Hiding(unsigned char state[], int dummy_count, int round);

/* ---------------- 더미 함수 / 함수 포인터 ---------------- */
void Shiftrows_dummy(unsigned char state[]);
void rotate_row1(unsigned char state[]);
void rotate_row2(unsigned char state[]);
void rotate_row3(unsigned char state[]);

/* ---------------- 외부 상수 배열 ---------------- */
extern const unsigned char s_box[256];
extern const unsigned char RC[10];
extern const int precomputed_indices[PATTERN_COUNT][20];
extern const int precomputed_Shiftrows[PATTERN_COUNT][7];
extern const int precomputed_MixColumns[PATTERN_COUNT][8];

#endif // AES_HIDING_H
