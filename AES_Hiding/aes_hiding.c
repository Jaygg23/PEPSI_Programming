#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "hal.h"
#include "aes_hiding.h"

//#define xtimes(input) (((input)<<1) ^ (((input)>>7) * 0x1b)) // 함수
#define xtimes(f) ((((f) >> 7 & 0x01) == 1) ? ((f) << 1) ^ 0x1b : (f) << 1) // 분기문

#define dummy_num 4 // 추가할 더미 개수
#define PATTERN_COUNT 20 // 미리 설정한 인덱스 셔플 패턴 개수

typedef uint8_t AES_STATE_t[18]; // 128-bit block
typedef uint8_t AES128_KEY_t[16]; // 128-bit masterkey

const int precomputed_indices[PATTERN_COUNT][20] = { // 셔플 패턴 20개 미리 생성 (Dummy 4개) 
    {  3,  7, 12, 16,  0,  9,  5, 17,  8, 14,  6, 10, 18, 15,  1, 13, 19, 11,  2,  4 },
    {  8, 16,  5,  3, 15,  7, 17,  2, 14,  0, 18,  6,  1,  9, 12, 13, 11, 19,  4, 10 },
    { 13,  1,  9, 16,  7,  6,  4, 17,  0, 15, 18,  8, 11, 10,  3, 19, 14, 12,  5,  2 },
    { 16, 10,  6,  2, 12, 17,  9,  1, 14,  3,  7,  8, 18,  0, 15,  4,  5, 19, 11, 13 },
    {  2,  8, 16, 11,  0, 14,  6, 17,  3,  7,  1, 15,  9, 18, 10, 12,  5, 13,  4, 19 },
    { 15,  4,  7, 16,  9,  1, 10,  6, 17,  3,  2,  5, 14, 18, 11,  0, 12, 19, 13,  8 },
    {  6, 13,  5,  0, 16, 12,  3, 17, 10,  1,  7, 14, 18,  9,  8, 15,  2, 19,  4, 11 },
    { 11,  2, 16, 13,  8,  7,  0,  5, 17, 15,  1, 18,  3, 14, 12,  9, 19,  4, 10,  6 },
    { 14, 16,  0,  6,  2, 12, 17,  8, 11,  9,  5,  3, 18, 10, 15,  7,  4, 19, 13,  1 },
    {  7,  3,  1, 15, 16,  6,  8, 17,  5, 12,  0, 13, 18, 10,  2,  4, 11, 19, 14,  9 },
    {  5, 14, 16,  1, 12,  7, 17,  3, 10,  6, 18, 15,  2,  0,  8, 19, 11,  9, 13,  4 },
    {  0, 16,  6, 11,  8, 17,  9,  2, 15,  5,  3, 18, 14,  1, 19,  7, 10, 12,  4, 13 },
    { 12,  9,  2, 16,  4,  6, 17, 14, 11, 18,  0, 15,  3,  7, 10, 19,  8,  1,  5, 13 },
    {  8,  3, 16,  7, 14, 12, 17,  1,  6, 10,  5, 18, 13,  4, 11,  0, 19,  9, 15,  2 },
    { 16,  2, 10,  5,  9, 17, 14,  0,  3, 18,  6, 15,  7, 12, 19, 11, 13,  1,  4,  8 },
    {  7, 13,  0, 16,  2,  8,  5, 17, 10,  4, 18,  6, 14,  1, 19,  9, 15,  3, 11, 12 },
    {  4, 15, 16,  9,  7,  0,  3, 17, 11, 13, 18,  1,  6,  8, 19, 14,  2,  5, 10, 12 },
    { 16,  5, 11,  2,  7, 17,  8, 15, 18,  6,  0, 10, 14,  1, 19, 13,  9,  3, 12,  4 },
    { 10, 16,  7,  1, 12, 17,  0,  9,  3, 18,  5, 15,  6,  8,  2, 19, 13, 11, 14,  4 },
    {  9,  6,  3, 16,  1,  0, 17, 12,  4, 11, 18, 15,  8, 13,  2,  7, 19,  5, 10, 14 }
};

const int sub_shuff_indices[PATTERN_COUNT][32] = {
{ 23, 10, 22, 12, 6, 2, 3, 24, 31, 20, 15, 7, 29, 17, 19, 25, 9, 0, 28, 1, 27, 11, 14, 18, 4, 13, 26, 8, 30, 21, 5, 16, },
{ 30, 17, 8, 20, 15, 6, 0, 16, 13, 24, 23, 1, 7, 4, 3, 10, 2, 21, 9, 12, 14, 28, 22, 11, 25, 26, 5, 19, 31, 18, 29, 27, },
{ 11, 25, 3, 12, 21, 28, 6, 19, 13, 30, 26, 20, 17, 5, 18, 4, 9, 31, 10, 7, 2, 29, 24, 14, 15, 27, 16, 23, 8, 1, 0, 22, },
{ 26, 31, 11, 24, 2, 25, 12, 14, 16, 3, 19, 13, 23, 22, 9, 21, 6, 29, 1, 0, 28, 17, 7, 30, 18, 15, 20, 8, 10, 5, 4, 27, },
{ 27, 31, 17, 11, 30, 14, 12, 20, 22, 25, 26, 13, 7, 8, 29, 3, 18, 6, 1, 5, 10, 0, 19, 28, 16, 15, 9, 23, 4, 24, 2, 21, },
{ 27, 9, 31, 21, 7, 22, 19, 15, 28, 26, 18, 24, 2, 11, 23, 4, 30, 1, 12, 0, 10, 5, 20, 6, 8, 16, 29, 17, 13, 3, 25, 14, },
{ 23, 11, 8, 29, 9, 13, 16, 20, 4, 21, 2, 27, 18, 7, 15, 22, 6, 1, 19, 12, 17, 5, 14, 3, 28, 30, 31, 10, 26, 25, 0, 24, },
{ 8, 5, 23, 25, 30, 18, 2, 28, 20, 1, 0, 7, 17, 13, 4, 29, 12, 14, 22, 3, 31, 6, 11, 19, 10, 26, 27, 15, 9, 21, 16, 24, },
{ 23, 29, 26, 9, 19, 6, 16, 30, 13, 20, 8, 10, 3, 22, 2, 14, 25, 1, 7, 15, 0, 4, 17, 11, 24, 27, 18, 5, 21, 12, 28, 31, },
{ 30, 19, 29, 21, 1, 13, 7, 11, 9, 25, 22, 24, 27, 26, 17, 18, 20, 0, 6, 31, 2, 28, 23, 4, 16, 15, 10, 12, 5, 14, 8, 3, },
{ 10, 26, 1, 18, 3, 0, 31, 13, 20, 27, 8, 14, 5, 25, 12, 17, 24, 2, 30, 15, 4, 16, 22, 19, 6, 11, 23, 7, 29, 9, 21, 28, },
{ 7, 10, 15, 0, 22, 1, 13, 31, 3, 12, 2, 20, 23, 9, 26, 8, 21, 18, 19, 16, 27, 25, 14, 6, 11, 28, 30, 24, 4, 5, 29, 17, },
{ 4, 8, 9, 7, 11, 29, 13, 23, 2, 22, 20, 3, 16, 21, 30, 15, 6, 18, 26, 0, 1, 25, 28, 5, 10, 14, 27, 24, 12, 19, 31, 17, },
{ 12, 27, 13, 24, 2, 14, 15, 26, 0, 23, 20, 9, 19, 11, 8, 3, 29, 7, 28, 10, 18, 30, 21, 16, 25, 17, 31, 22, 1, 6, 4, 5, },
{ 14, 0, 7, 20, 15, 16, 10, 5, 22, 24, 30, 25, 4, 1, 26, 12, 8, 21, 19, 6, 29, 9, 23, 18, 28, 27, 11, 31, 13, 3, 2, 17, },
{ 12, 22, 13, 31, 4, 5, 18, 21, 8, 7, 17, 2, 15, 28, 10, 14, 29, 20, 6, 16, 24, 25, 3, 30, 26, 9, 19, 11, 1, 23, 27, 0, },
{ 9, 31, 26, 5, 25, 18, 19, 0, 17, 22, 28, 6, 20, 4, 24, 10, 1, 27, 8, 15, 3, 7, 14, 2, 16, 13, 29, 11, 12, 23, 30, 21, },
{ 21, 10, 20, 15, 29, 4, 1, 2, 17, 23, 31, 8, 11, 27, 5, 24, 13, 26, 16, 7, 12, 14, 18, 30, 19, 22, 6, 25, 28, 9, 3, 0, },
{ 7, 15, 9, 23, 5, 13, 16, 21, 8, 30, 14, 22, 31, 6, 28, 27, 18, 2, 11, 24, 19, 12, 4, 29, 1, 0, 17, 3, 20, 26, 25, 10, },
{ 17, 6, 5, 15, 22, 31, 18, 19, 28, 27, 12, 23, 7, 26, 14, 21, 10, 0, 9, 8, 13, 29, 4, 20, 25, 1, 30, 11, 3, 2, 16, 24, }
};


const int shuff_idxs[PATTERN_COUNT][16] = { // 셔플 패턴 16개 미리 생성
    {  3,  7, 12,  0,  9,  5,  8, 14,  6, 10, 15,  1, 13, 11,  2,  4 },
    {  8,  5,  3, 15,  7,  2, 14,  0,  6,  1,  9, 12, 13, 11,  4, 10 },
    { 13,  1,  9,  7,  6,  4,  0, 15,  8, 11, 10,  3, 14, 12,  5,  2 },
    { 10,  6,  2, 12,  9,  1, 14,  3,  7,  8,  0, 15,  4,  5, 11, 13 },
    {  2,  8, 11,  0, 14,  6,  3,  7,  1, 15,  9, 10, 12,  5, 13,  4 },
    { 15,  4,  7,  9,  1, 10,  6,  3,  2,  5, 14, 11,  0, 12, 13,  8 },
    { 6, 13,  5,  0, 12,  3,  10,  1,  7, 14,  9,  8, 15,  2,  4, 11 },
    { 11,  2, 13,  8,  7,  0,  5, 15,  1,  3, 14, 12,  9,  4, 10,  6 },
    { 14,  0,  6,  2, 12,  8, 11,  9,  5,  3, 10, 15,  7,  4, 13,  1 },
    {  7,  3,  1, 15,  6,  8,  5, 12,  0, 13, 10,  2,  4, 11, 14,  9 },
    {  5, 14,  1, 12,  7,  3, 10,  6, 15,  2,  0,  8, 11,  9, 13,  4 },
    {  0,  6, 11,  8,  9,  2, 15,  5,  3, 14,  1,  7, 10, 12,  4, 13 },
    { 12,  9,  2,  4,  6, 14, 11,  0, 15,  3,  7, 10,  8,  1,  5, 13 },
    {  8,  3,  7, 14, 12,  1,  6, 10,  5, 13,  4, 11,  0,  9, 15,  2 },
    {  2, 10,  5,  9, 14,  0,  3,  6, 15,  7, 12, 11, 13,  1,  4,  8 },
    {  7, 13,  0,  2,  8,  5, 10,  4,  6, 14,  1,  9, 15,  3, 11, 12 },
    {  4, 15,  9,  7,  0,  3, 11, 13,  1,  6,  8, 14,  2,  5, 10, 12 },
    {  5, 11,  2,  7,  8, 15,  6,  0, 10, 14,  1, 13,  9,  3, 12,  4 },
    { 10,  7,  1, 12,  0,  9,  3,  5, 15,  6,  8,  2, 13, 11, 14,  4 },
    {  9,  6,  3,  1,  0, 12,  4, 11, 15,  8, 13,  2,  7,  5, 10, 14 }
};
const int precomputed_Shiftrows[PATTERN_COUNT][7] = {
    {0, 2, 4, 1, 6, 5, 3},
    {1, 0, 3, 2, 4, 5, 6},
    {2, 3, 0, 1, 4, 5, 6},
    {3, 2, 1, 0, 4, 5, 6},
    {0, 2, 1, 3, 4, 6, 5},
    {1, 3, 2, 0, 5, 4, 6},
    {2, 0, 3, 1, 6, 4, 5},
    {3, 1, 0, 2, 5, 6, 4},
    {0, 3, 1, 2, 6, 5, 4},
    {1, 2, 0, 3, 5, 6, 4},
    {2, 1, 3, 0, 4, 6, 5},
    {3, 0, 2, 1, 6, 5, 4},
    {0, 1, 3, 2, 5, 4, 6},
    {1, 0, 2, 3, 6, 4, 5},
    {2, 3, 1, 0, 5, 6, 4},
    {3, 2, 0, 1, 4, 5, 6},
    {0, 2, 3, 1, 6, 5, 4},
    {1, 3, 0, 2, 4, 6, 5},
    {2, 0, 1, 3, 5, 4, 6},
    {3, 1, 2, 0, 6, 4, 5} };
const int precomputed_MixColumns[PATTERN_COUNT][8] = {
    {7, 1, 4, 5, 3, 2, 6, 0},
    {1, 5, 3, 2, 0, 4, 7, 6},
    {2, 3, 6, 7, 1, 0, 4, 5},
    {3, 2, 4, 0, 7, 6, 5, 1},
    {0, 6, 1, 7, 4, 2, 5, 3},
    {1, 3, 4, 2, 5, 7, 0, 6},
    {2, 6, 3, 7, 0, 4, 1, 5},
    {4, 1, 2, 5, 7, 0, 6, 3},
    {0, 3, 1, 2, 4, 7, 5, 6},
    {6, 5, 4, 0, 1, 2, 3, 7}
};

const unsigned char s_box[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char RC[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void AddRoundKey(unsigned char string[], unsigned char key[])
{
    string[0] ^= key[0];
    string[1] ^= key[1];
    string[2] ^= key[2];
    string[3] ^= key[3];
    string[4] ^= key[4];
    string[5] ^= key[5];
    string[6] ^= key[6];
    string[7] ^= key[7];
    string[8] ^= key[8];
    string[9] ^= key[9];
    string[10] ^= key[10];
    string[11] ^= key[11];
    string[12] ^= key[12];
    string[13] ^= key[13];
    string[14] ^= key[14];
    string[15] ^= key[15];
}

void SubBytes(unsigned char string[])
{
    string[0] = s_box[string[0]];
    string[1] = s_box[string[1]];
    string[2] = s_box[string[2]];
    string[3] = s_box[string[3]];
    string[4] = s_box[string[4]];
    string[5] = s_box[string[5]];
    string[6] = s_box[string[6]];
    string[7] = s_box[string[7]];
    string[8] = s_box[string[8]];
    string[9] = s_box[string[9]];
    string[10] = s_box[string[10]];
    string[11] = s_box[string[11]];
    string[12] = s_box[string[12]];
    string[13] = s_box[string[13]];
    string[14] = s_box[string[14]];
    string[15] = s_box[string[15]];
}

void ShiftRows(unsigned char string[])
{
    unsigned char buf;

    buf = string[1];
    string[1] = string[5];
    string[5] = string[9];
    string[9] = string[13];
    string[13] = buf;

    buf = string[2];
    string[2] = string[10];
    string[10] = buf;
    buf = string[6];
    string[6] = string[14];
    string[14] = buf;

    buf = string[15];
    string[15] = string[11];
    string[11] = string[7];
    string[7] = string[3];
    string[3] = buf;
}

void MixColumns(unsigned char string[])
{
    unsigned char buf[4] = { 0x00, };

    buf[0] = string[0];
    buf[1] = string[1];
    buf[2] = string[2];
    buf[3] = string[3];
    string[0] = xtimes((buf[0] ^ buf[1])) ^ buf[1] ^ buf[2] ^ buf[3];
    string[1] = buf[0] ^ xtimes((buf[1] ^ buf[2])) ^ buf[2] ^ buf[3];
    string[2] = buf[0] ^ buf[1] ^ xtimes((buf[2] ^ buf[3])) ^ buf[3];
    string[3] = xtimes((buf[0] ^ buf[3])) ^ buf[0] ^ buf[1] ^ buf[2];

    buf[0] = string[4];
    buf[1] = string[5];
    buf[2] = string[6];
    buf[3] = string[7];
    string[4] = xtimes((buf[0] ^ buf[1])) ^ buf[1] ^ buf[2] ^ buf[3];
    string[5] = buf[0] ^ xtimes((buf[1] ^ buf[2])) ^ buf[2] ^ buf[3];
    string[6] = buf[0] ^ buf[1] ^ xtimes((buf[2] ^ buf[3])) ^ buf[3];
    string[7] = xtimes((buf[0] ^ buf[3])) ^ buf[0] ^ buf[1] ^ buf[2];

    buf[0] = string[8];
    buf[1] = string[9];
    buf[2] = string[10];
    buf[3] = string[11];
    string[8] = xtimes((buf[0] ^ buf[1])) ^ buf[1] ^ buf[2] ^ buf[3];
    string[9] = buf[0] ^ xtimes((buf[1] ^ buf[2])) ^ buf[2] ^ buf[3];
    string[10] = buf[0] ^ buf[1] ^ xtimes((buf[2] ^ buf[3])) ^ buf[3];
    string[11] = xtimes((buf[0] ^ buf[3])) ^ buf[0] ^ buf[1] ^ buf[2];

    buf[0] = string[12];
    buf[1] = string[13];
    buf[2] = string[14];
    buf[3] = string[15];
    string[12] = xtimes((buf[0] ^ buf[1])) ^ buf[1] ^ buf[2] ^ buf[3];
    string[13] = buf[0] ^ xtimes((buf[1] ^ buf[2])) ^ buf[2] ^ buf[3];
    string[14] = buf[0] ^ buf[1] ^ xtimes((buf[2] ^ buf[3])) ^ buf[3];
    string[15] = xtimes((buf[0] ^ buf[3])) ^ buf[0] ^ buf[1] ^ buf[2];
}

void KeySchedule128(unsigned char key[][16])
{
    int cnt_i;

    for (cnt_i = 0; cnt_i < 10; cnt_i++)
    {
        key[cnt_i + 1][0] = key[cnt_i][0] ^ s_box[key[cnt_i][13]] ^ RC[cnt_i];
        key[cnt_i + 1][1] = key[cnt_i][1] ^ s_box[key[cnt_i][14]];
        key[cnt_i + 1][2] = key[cnt_i][2] ^ s_box[key[cnt_i][15]];
        key[cnt_i + 1][3] = key[cnt_i][3] ^ s_box[key[cnt_i][12]];

        key[cnt_i + 1][4] = key[cnt_i + 1][0] ^ key[cnt_i][4];
        key[cnt_i + 1][5] = key[cnt_i + 1][1] ^ key[cnt_i][5];
        key[cnt_i + 1][6] = key[cnt_i + 1][2] ^ key[cnt_i][6];
        key[cnt_i + 1][7] = key[cnt_i + 1][3] ^ key[cnt_i][7];

        key[cnt_i + 1][8] = key[cnt_i + 1][4] ^ key[cnt_i][8];
        key[cnt_i + 1][9] = key[cnt_i + 1][5] ^ key[cnt_i][9];
        key[cnt_i + 1][10] = key[cnt_i + 1][6] ^ key[cnt_i][10];
        key[cnt_i + 1][11] = key[cnt_i + 1][7] ^ key[cnt_i][11];

        key[cnt_i + 1][12] = key[cnt_i + 1][8] ^ key[cnt_i][12];
        key[cnt_i + 1][13] = key[cnt_i + 1][9] ^ key[cnt_i][13];
        key[cnt_i + 1][14] = key[cnt_i + 1][10] ^ key[cnt_i][14];
        key[cnt_i + 1][15] = key[cnt_i + 1][11] ^ key[cnt_i][15];
    }
}

/* ---------------- Hiding ---------------- */
void Fisher_Yates_shuffle(int* arr, int size) { // Fisher–Yates 방식 셔플
    for (int i = size - 1; i > 0; i--) {
        int j = rand() % (i + 1); // 0 ~ i 사이 랜덤 인덱스 선택
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}
void SubBytes_Hiding(unsigned char state[], int dummy_count, int round, int shuff_idxs[18]) {
    int total = 18;   // 실제 16바이트 + 더미 바이트
    //unsigned char dummy_plus_state[18];

    //for (int i = 0; i < 16; i++) {
    //    state[i] = state[i]; // state[0~15] 실제 데이터 복사
    //}
    for (int i = 16; i < total; i++) {
        state[i] = (unsigned char)(0x78 ^ i); // state[16~15 + dummy_count] 더미 채우기
    }
    //for (int i = 0; i < total; i++) {
    //    order[i] = indices[i]; // order 배열을 미리 정의된 패턴으로 섞기
    //}
    /*
    printf("[Round %d | SubBytes Hiding]: ", round + 1);
    printf(" Order: ");
    for (int i = 0; i < total; i++) {
        if (shuff_idxs[i] < 16) printf("%d ", shuff_idxs[i]);
        else printf("D ");
    }
    printf("\n");
    */
    // SubBytes 수행
    for (int i = 0; i < total; i++) {
        //int idx = shuff_idxs[i];
        //unsigned char before = dummy_plus_state[shuff_idxs[i]];
        state[shuff_idxs[i]] = s_box[state[shuff_idxs[i]]];

        //if (idx < 16) { // 실제 데이터
        //    printf("SubBytes[%d]: 0x%02X -> 0x%02X\n", idx, before, dummy_plus_state[idx]);
        //}
        //else {        // 더미 데이터
        //    printf("   Dummy[SubBytes]: 0x%02X -> 0x%02X\n", before, dummy_plus_state[idx]);
        //}
    }

    // 6. 변환된 실제 state[0~15]만 복사해둔다 (더미는 버림)
    //for (int i = 0; i < 16; i++) {
    //    state[state_indices[i]] = dummy_plus_state[state_indices[i]];
    //}

    // printf("\n");
}

void Shiftrows_dummy(unsigned char* state) {
    //printf("  DummyShift: row rotation\n");
}
void rotate_row1(unsigned char s[]) {
    unsigned char buf = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = buf;
    //printf("ShiftRow: row1 (1,5,9,13)\n");
}
void rotate_row2(unsigned char s[]) {
    unsigned char buf = s[2];
    s[2] = s[10];
    s[10] = buf;
    buf = s[6];
    s[6] = s[14];
    s[14] = buf;
    //printf("ShiftRow: row2 (2,6,10,14)\n");
}
void rotate_row3(unsigned char s[]) {
    unsigned char buf = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = buf;
    //printf("ShiftRow: row3 (3,7,11,15)\n");
}
typedef void (*Shiftrows_Func)(unsigned char state[]); // 함수 포인터 배열
Shiftrows_Func shiftrows[7] = {
    rotate_row1,
    rotate_row2,
    rotate_row3,
    Shiftrows_dummy,
    Shiftrows_dummy,
    Shiftrows_dummy,
    Shiftrows_dummy
};
void ShiftRows_Hiding(unsigned char state[], int dummy_count, int round) { // 바이트 별로 계산 -> x5 후에 %16 -> % 대신 &(2^n - 1)
    int total = 3 + dummy_count;
    int temp = round & ((int)pow(2, PATTERN_COUNT) - 1);
    const int* indices = precomputed_Shiftrows[temp];

    /*
    printf("[Round %d | ShiftRows Hiding]\n", round + 1);
    printf(" Order: ");
    for (int i = 0; i < total; i++) {
        if (indices[i] < 3) printf("%d ", indices[i]);
        else printf("D ");
    }
    printf("\n");
    */

    // 함수 포인터로 실행
    for (int i = 0; i < total; i++) {
        shiftrows[indices[i]](state);
    }

    //printf("\n");
}

void AddRoundKey_Hiding(unsigned char state[], unsigned char key[], int dummy_count, int round) {
    int total = 16 + dummy_count;
    int temp = round & ((int)pow(2, PATTERN_COUNT) - 1);
    const int* indices = precomputed_indices[temp]; // 라운드 번호에 따라 미리 준비된 패턴 선택
    unsigned char dummy_plus_state[20]; // 실제 + 더미
    unsigned char dummy_plus_key[20]; // 실제 + 더미 키
    unsigned char order[20];

    for (int i = 0; i < 16; i++) {
        dummy_plus_state[i] = state[i]; // 실제 데이터 복사
        dummy_plus_key[i] = key[i];
    }
    for (int i = 16; i < total; i++) { // dummy 값 채우기
        dummy_plus_state[i] = (unsigned char)(0x78 ^ i); // 더미 state
        dummy_plus_key[i] = (unsigned char)(0x23 ^ i); // 더미 key
    }
    for (int i = 0; i < total; i++) {
        order[i] = indices[i]; // order 배열을 미리 정의된 패턴으로 섞기
    }
    /*
    printf("[Round %d | AddRoundKey Hiding]: ", round + 1);
    printf(" Order: ");
    for (int i = 0; i < total; i++) {
        if (order[i] < 16) printf("%d ", order[i]);
        else printf("D ");
    }
    printf("\n");
    */
    // 수행
    for (int i = 0; i < total; i++) {
        //unsigned char before = dummy_plus_state[order[i]];
        dummy_plus_state[order[i]] ^= dummy_plus_key[order[i]];
        /*
        if (idx < 16) { // 실제 데이터
            printf("AddRoundKey[%d]: 0x%02X ^ 0x%02X = 0x%02X\n", idx, before, dummy_plus_key[order[i]], dummy_plus_state[idx]);
        }
        else { // 더미
            printf("   Dummy[AddRoundKey]: 0x%02X ^ 0x%02X = 0x%02X\n", before, dummy_plus_key[order[i]], dummy_plus_state[idx]);
        }
        */
    }

    for (int i = 0; i < 16; i++) {
        state[i] = dummy_plus_state[i]; // 실제 state[0~15]만 복사
    }

    //printf("\n");
}

void MixColumns_Hiding(unsigned char state[], int dummy_count, int round) {
    unsigned char tmp[16];       // 입력 복사
    unsigned char out[16];       // 실제 MixColumns 결과
    unsigned char dummy[4];      // 더미 값
    unsigned char combined[20];  // 실제 + 더미
    const int* order;               // 셔플된 순서

    // 0. 입력 복사
    memcpy(tmp, state, 16);

    // 1. 바이트 단위 MixColumns 결과 미리 계산
    out[0] = xtimes(tmp[0]) ^ xtimes(tmp[1]) ^ tmp[1] ^ tmp[2] ^ tmp[3];
    out[1] = xtimes(tmp[1]) ^ xtimes(tmp[2]) ^ tmp[2] ^ tmp[3] ^ tmp[0];
    out[2] = xtimes(tmp[2]) ^ xtimes(tmp[3]) ^ tmp[3] ^ tmp[0] ^ tmp[1];
    out[3] = xtimes(tmp[3]) ^ xtimes(tmp[0]) ^ tmp[0] ^ tmp[1] ^ tmp[2];

    out[4] = xtimes(tmp[4]) ^ xtimes(tmp[5]) ^ tmp[5] ^ tmp[6] ^ tmp[7];
    out[5] = xtimes(tmp[5]) ^ xtimes(tmp[6]) ^ tmp[6] ^ tmp[7] ^ tmp[4];
    out[6] = xtimes(tmp[6]) ^ xtimes(tmp[7]) ^ tmp[7] ^ tmp[4] ^ tmp[5];
    out[7] = xtimes(tmp[7]) ^ xtimes(tmp[4]) ^ tmp[4] ^ tmp[5] ^ tmp[6];

    out[8] = xtimes(tmp[8]) ^ xtimes(tmp[9]) ^ tmp[9] ^ tmp[10] ^ tmp[11];
    out[9] = xtimes(tmp[9]) ^ xtimes(tmp[10]) ^ tmp[10] ^ tmp[11] ^ tmp[8];
    out[10] = xtimes(tmp[10]) ^ xtimes(tmp[11]) ^ tmp[11] ^ tmp[8] ^ tmp[9];
    out[11] = xtimes(tmp[11]) ^ xtimes(tmp[8]) ^ tmp[8] ^ tmp[9] ^ tmp[10];

    out[12] = xtimes(tmp[12]) ^ xtimes(tmp[13]) ^ tmp[13] ^ tmp[14] ^ tmp[15];
    out[13] = xtimes(tmp[13]) ^ xtimes(tmp[14]) ^ tmp[14] ^ tmp[15] ^ tmp[12];
    out[14] = xtimes(tmp[14]) ^ xtimes(tmp[15]) ^ tmp[15] ^ tmp[12] ^ tmp[13];
    out[15] = xtimes(tmp[15]) ^ xtimes(tmp[12]) ^ tmp[12] ^ tmp[13] ^ tmp[14];

    // 2. 더미 값 4개 생성
    for (int i = 0; i < dummy_count; i++) {
        unsigned char a = (unsigned char)(0x23 ^ i);
        unsigned char b = (unsigned char)(0x78 ^ i);
        dummy[i] = a ^ b;
    }

    // 3. 실제 + 더미 합치기
    for (int i = 0; i < 16; i++) combined[i] = out[i];
    for (int i = 0; i < 4; i++)  combined[16 + i] = dummy[i];

    // 4. 인덱스 배열 [0..19] 
    int temp = round & ((int)pow(2, PATTERN_COUNT) - 1);
    order = precomputed_indices[temp];

    // 5. 셔플된 순서대로 처리
    /*
    printf("[Round %d | MixColumns Hiding]\n", round + 1);
    printf(" Order: ");
    for (int i = 0; i < 20; i++) {
        if (order[i] < 16) printf("%d ", order[i]);
        else printf("D ");
    }
    printf("\n");
    */
    for (int i = 0; i < 20; i++) {
        int idx = order[i];
        unsigned char v = combined[idx];

        if (idx < 16) {
            // 실제 state 반영
            //printf("MixColumns[%d]: 0x%02X -> 0x%02X\n", idx, tmp[idx], v);
            state[idx] = v;
        }
        else {
            // 더미 출력만
            //printf("   Dummy[MixColumns]: 0x%02X\n", v);
        }
    }
    //printf("\n");
}


/* ------------------------------------------------- */

// 주석 처리 이유 : simpleserial-aes.c에 enc랑 main 있음
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
        //SubBytes(CT);
        SubBytes_Hiding(CT, dummy_num);
        ShiftRows(CT);
        MixColumns(CT);
        AddRoundKey(CT, RoundKey[cnt_i + 1]);
        if (cnt_i == 0)
            trigger_low();
    }

    //마지막 10 라운드
    //SubBytes(CT);
    SubBytes_Hiding(CT, dummy_num);
    ShiftRows(CT);
    AddRoundKey(CT, RoundKey[10]);
}

int main() {
    srand(12345);
    unsigned char plaintext[16] = { // 랜덤 -> 수정!
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a
    };

    unsigned char key[16] = { // 고정
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char ciphertext[16];

    Encrypt(plaintext, key, ciphertext);

    printf("Ciphertext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
*/
