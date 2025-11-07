#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define TRACE_FILE "CW_Lite_powerConsumption.trace"
#define PLAIN_FILE "CW_Lite_plain.bin"

#define WAVEFORM 1000 // 파형 1000개 (행)
#define POINT 14864 // 포인트 14864개 (열)
#define GUESSKEY_NUM 256 // guesskey 00~ff 256개
#define POINT_START 500 // SubByte를 시작하는 point 지점
#define POINT_END 2300 // SubByte가 끝나는 point 지점

typedef unsigned char BYTE;

// 전역변수 선언
float** trace; // trace 정보 저장 이차원 배열
BYTE** plain; // plain 정보 저장 이차원 배열
BYTE HW[GUESSKEY_NUM][WAVEFORM]; // interm 값에 HW를 적용한 값 저장 (256*1000)


/*static const BYTE AES_SBOX[16][16] = {{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
									{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
									{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
									{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
									{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
									{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
									{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
									{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
									{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
									{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
									{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
									{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
									{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
									{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
									{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
									{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16} };*/


// Sbox 값을 HW모델에 적용한 값을 저장하는 배열 (256)
static const int Sbox_HW[256] = {4, 5, 6, 6, 5, 5, 6, 4, 2, 1, 5, 4, 7, 6, 5, 5,
									 4, 2, 4, 6, 6, 4, 4, 4, 5, 4, 3, 6, 4, 3, 4, 2 ,
									 6, 7, 4, 3, 4, 6, 7, 4, 3, 4, 5, 5, 4, 4, 3, 3 ,
									 1, 5, 3, 4, 2, 4, 2, 4, 3, 2, 1, 4, 6, 4, 4, 5 ,
									 2, 3, 3, 3, 4, 5, 4, 2, 3, 5, 5, 5, 3, 5, 5, 2 ,
									 4, 4, 0, 6, 1 ,6 ,4 ,5 ,4 ,5 ,6 ,4 ,3 ,3 ,3 ,6 ,
									 3, 7, 4, 7, 3 ,4 ,4 ,3 ,3 ,6 ,1 ,7 ,2, 4, 6, 3 ,
									 3, 4, 1, 5, 3, 5, 3, 6, 5, 5, 5, 2 ,1 ,8 ,6 ,4 ,
									 5, 2, 3, 5, 6 ,5, 2, 4, 3, 5, 6, 5, 3, 5, 3, 5 ,
									 2, 2, 5, 5, 2, 3, 2, 2, 3, 6, 4, 2, 6, 5, 3, 6 ,
									 3, 3, 4, 2, 3, 2, 2, 4, 3, 5, 4, 3, 3, 4, 4, 5 ,
									 6, 3, 5, 5, 4, 5, 4, 4, 4, 4, 5, 5, 4, 5, 5, 1 ,
									 5, 4, 3, 4, 3, 4, 4, 4, 4, 6, 4, 5, 4, 6 ,4 ,3 ,
									 3, 5, 5, 4, 2, 2, 6, 3, 3, 4, 5, 5, 3, 3, 4, 5 ,
									 4, 5, 3, 2, 4, 5, 4, 3, 5, 4, 4, 5, 5, 4, 2, 7 ,
									 3, 3, 3, 3, 7, 5, 2, 3, 2, 4, 4, 4, 3, 3, 6, 3  };

void headerinfo() {
	// 파일 오픈
	FILE* fp = fopen(TRACE_FILE, "rb");
	if (fp == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	// 파일 읽기
	// 1. 파일 설명(string) - 20bytes
	char description[21] = { 0, };
	fread(description, sizeof(char), 20, fp);
	description[20] = '\0';
	printf("파일 설명 : %s\n", description);

	// 2. 파형 수(int) - 4bytes (1000 행)
	int waveform2;
	fread(&waveform2, sizeof(int), 1, fp);
	printf("파형 수 : %d\n", waveform2);

	// 3. 포인트 수(int) - 4bytes (14864 열)
	int point2;
	fread(&point2, sizeof(int), 1, fp);
	printf("포인트 수 : %d\n", point2);

	// 4. END!(string) - 4bytes
	char end[5] = { 0, };
	fread(end, sizeof(char), 4, fp);
	end[4] = '\0';
	printf("END : %s\n", end);

	return;
}

void tracefile() {
	// 파일 오픈
	FILE* fp = fopen(TRACE_FILE, "rb");
	if (fp == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	// 소비 전력 - 파형의 각 포인트
	trace = (float**)calloc(WAVEFORM, sizeof(float*));
	if (trace == NULL) {
		puts("메모리 할당 실패 (파형의 각 포인트)");
		fclose(fp);
		return;
	}

	fseek(fp, 32, SEEK_SET); // fp 위치를 시작으로부터 32번째로 옮김

	for (int i = 0;i < WAVEFORM;i++) {
		trace[i] = (float*)calloc(POINT, sizeof(float));
		if (trace[i] == NULL) {
			puts("메모리 할당 실패");
			for (int j = 0;j < i;j++) {
				free(trace[j]);
			}
			free(trace);
			fclose(fp);
			return;
		}
		fread(trace[i], sizeof(float), POINT, fp); // 소비전력 읽기
	}
	fclose(fp);
	return;
	
	/*
	//출력
	for (int i = 0;i < 10;i++) {
		printf("Tracefile [%d] : ", i + 1);
		for (int j = 0;j < 10;j++) {
			printf("%f ", trace[i][j]);
		}
		printf("\n");
	}
	
	fclose(fp);
	*/
}

void plaintext() {
	// 파일 오픈
	FILE* fp2 = fopen(PLAIN_FILE, "rb");
	if (fp2 == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	// 이차원 배열 동적할당
	plain = (BYTE**)calloc(WAVEFORM, sizeof(BYTE*));
	// plain은 이중포인터로 선언됨
	// calloc(num * sizeof(BYTE*))으로 num(1000)개의 BYTE 포인터를 저장할 공간 할당
	// -> 각 행을 가리킬 포인터 배열 우선 만듦
	//    plain은 1000 크기의 포인터 배열이 됨

	if (plain == NULL) {
		puts("메모리 할당 실패(num)");
		fclose(fp2);
		return;
	}

	for (int i = 0;i < WAVEFORM;i++) {
		plain[i] = (BYTE*)calloc(16, sizeof(BYTE));
		// plain[i]은 각 행을 가리키는 포인터
		//calloc(16 * sizeof(BYTE))를 사용해 각 행에 대해 16바이트 크기의 메모리 할당
		// -> 각 행(plain[i])은 16바이트 크기의 BYTE 배열을 저장하는 메모리 블록을 가짐
		// 반복문을 통해 1000개의 행을 순차적으로 할당
		// => plain은 [1000][16] 크기의 동적 2차원 배열
		if (plain[i] == NULL) {
			puts("메모리 할당 실패"); // 할당 실패 시, 이미 할당된 메모리를 해제해야 메모리 누수 방지
			for (int j = 0; j < i; j++) { // 이전까지 할당된 행의 메모리 해제
				free(plain[j]);
			}
			free(plain); // 행 포인터 배열 자체도 해제
			fclose(fp2);
			return;
		}
	}

	// 파일에서 1바이트씩 읽어서 저장
	// 1바이트씩 16개를 읽어서 한 행에 저장
	// 총 16열씩 1000행
	for (int i = 0;i < WAVEFORM;i++) {
		fread(plain[i], sizeof(BYTE), 16, fp2);
	}
	fclose(fp2);
	return;
	/*
	//츨력
	for (int i = 0;i < waveform;i++) {
		printf("Plaintext [%d] : ", i + 1);
		for (int j = 0;j < 16;j++) {
			printf("%02x ", plain[i][j]);
		}
		printf("\n");
	}
	*/

	//fclose(fp2);
}


/*int hamming_weight(BYTE value) { // HW 모델을 적용하는 함수
	int num_of_1 = 0; // 1의 개수를 저장할 변수
	while (value) {
		num_of_1 += value & 1; // 가장 오른쪽 비트가 1인지 확인 -> 1일 경우 num_of_1 변수를 1 증가시킴
		value >>= 1; // 값을 오른쪽으로 1비트 이동
	}
	return num_of_1; // 1의 개수 반환
}*/



/*void sbox_lookup() { // AES_SBOX의 값을 미리 HW에 적용해 배열에 저장 -> 결과값을 Sbox_HW[16][16]로 저장함
	for (int i = 0;i < 16;i++) {
		for (int j = 0;j < 16;j++) {
			BYTE value = AES_SBOX[i][j]; // sbox의 값 value에 저장
			Sbox_HW[i][j] = hamming_weight(value);
		}
	}
}*/


void intermediate_values(int byte_index) { // 중간값 계산 : 256*1000 (guesskey 256개 * plain 한 바이트의 1000열)
	for (int guesskey = 0; guesskey < GUESSKEY_NUM; guesskey++) { // guesskey: 00~ff (0~255) 하나씩 대입해서 구하기
		for (int plaintext_row = 0; plaintext_row < WAVEFORM; plaintext_row++) { // plaintext 1000 행까지
			BYTE xor = plain[plaintext_row][byte_index] ^ guesskey; // XOR 연산
			HW[guesskey][plaintext_row] = Sbox_HW[xor]; // HW된 S-box 값을 HW배열에 저장 
			// xor >> 4 : xor 값을 4비트 이동 (0x7d를 0x07로 변경 -> AES_SBOX의 첫 번째 인덱스)
			// xor & 0x0F : xor 값에서 하위 4비트만 추출 (0x7d와 0x0f(1111) 연산 시, 하위 4비트만 남김 -> AES_SBOX의 두 번째 인덱스)
		}
	}	
}

void cpa() {
	float max_pearson_val, second_pearson_val; // 피어슨 상관계수의 첫째, 둘째값 저장 변수
	int best_guesskey, second_guesskey; // 그 때의 guesskey 저장 변수

	// X : 가상 소비전력 값 (interm), Y : 실제 소비전력 값 (trace), n : 실제 소비전력의 개수(waveform)
	float sum_X2, sum_Y2, sum_X, sum_Y, sum_XY, pearson_value;
	for (int byte_index = 0; byte_index < 16; byte_index++) { // 0~15바이트 각각 계산
		intermediate_values(byte_index); // 중간값 계산
		max_pearson_val = second_pearson_val = 0.0; // 초기화
		best_guesskey = second_guesskey = 0;

		for (int guesskey = 0;guesskey < GUESSKEY_NUM;guesskey++) { // guesskey 00~ff
			sum_X2 = sum_X = 0.0;
			for (int interm_col = 0;interm_col < WAVEFORM;interm_col++) { // 연산 시 point와 상관없는 값들을 미리 저장해서 중복되는 연산 줄임
				sum_X2 += HW[guesskey][interm_col] * HW[guesskey][interm_col];
				sum_X += HW[guesskey][interm_col];
			}

			for (int point = POINT_START;point < POINT_END;point++) { // point 0~14863 -> SubByte를 하는 부분만 잘라서 point 돌리기(start 500 ~ end 2300)->시간 단축
				sum_Y2 = sum_Y = sum_XY = pearson_value = 0.0; // 피어슨 상관계수 계산 시 필요한 변수 초기화
				for (int interm_col = 0;interm_col < WAVEFORM;interm_col++) { // 피어슨 상관계수 값 계산
					sum_Y2 += trace[interm_col][point] * trace[interm_col][point];
					sum_Y += trace[interm_col][point];
					sum_XY += HW[guesskey][interm_col] * trace[interm_col][point];
				}
				pearson_value = fabsf((WAVEFORM * sum_XY - sum_X * sum_Y) / sqrtf((WAVEFORM * sum_X2 - sum_X * sum_X) * (WAVEFORM * sum_Y2 - sum_Y * sum_Y))); // 계산 후 절댓값 함수 fabs

				// 피어슨 상관계수 1, 2번째 값과 ratio, 그때의 guesskey 구하기
				if (pearson_value > max_pearson_val) { // 현재 pearson_value 값이 기존의 max_pearson_val보다 클 경우,
					// 최댓값 갱신
					if (guesskey != best_guesskey) { // 기존의 best_guesskey가 현재 guesskey와 다를 경우에만
						second_pearson_val = max_pearson_val; // 현재 max 값을 second에 저장
						second_guesskey = best_guesskey; // 현재 best_guesskey를 second에 저장
					}
					max_pearson_val = pearson_value; // max_pearson_val를 현재 pearson_value로 갱신
					best_guesskey = guesskey; // 그 때의 guesskey를 best_guesskey로 저장
				}
				else if (pearson_value > second_pearson_val) { // 현재 pearson_value 값이 max보다 작지만, second보다 클 경우,
					if (guesskey != best_guesskey) {  // 최댓값과 다른 경우만 갱신
						second_pearson_val = pearson_value;
						second_guesskey = guesskey;
					}
				}
			}
		}
		float ratio = max_pearson_val / second_pearson_val; // 가장 큰 값/두 번째로 큰 값의 비율 계산
		printf("Byte %d: Max Correlation = %f, Second Max Correlation = %f, Ratio = %f, Best Guesskey = %c\n", byte_index, max_pearson_val, second_pearson_val, ratio, best_guesskey);

	}
}

int main() {
	clock_t start_time = clock(); // 실행 시작 시간

	// 1. 전력소비 측정 - tracefile, plain 정보 불러오기
	//headerinfo();
	tracefile();
	plaintext();

	// 2. CPA
	cpa();

	// 메모리 해제
	for (int i = 0;i < WAVEFORM;i++) {
		free(trace[i]);
		free(plain[i]);
	}
	free(trace);
	free(plain);

	clock_t end_time = clock(); // 실행 종료 시간
	float total_time = (float)(end_time - start_time) / CLOCKS_PER_SEC;
	printf("총 실행 시간 : %.3f초\n", total_time);

	return 0;
}