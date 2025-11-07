#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define  waveform 1000 // 파형 1000개 (행)
#define point 14864 // 포인트 14864개 (열)
#define guesskey_num 256 // guesskey 00~ff 256개
#define point_start 500 // SubByte를 시작하는 point 지점
#define point_end 2300 // SubByte가 끝나는 point 지점

typedef unsigned char BYTE;

// 전역변수 선언
float** trace; // trace 정보 저장 이차원 배열
BYTE** plain; // plain 정보 저장 이차원 배열
BYTE interm[guesskey_num][waveform]; // 중간값 저장 (256*1000)


static const BYTE AES_SBOX[16][16] = { {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
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
									{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16} };

void headerinfo() {
	// 파일 오픈
	FILE* fp = fopen("CW_Lite_powerConsumption.trace", "rb");
	if (fp == NULL) {
		puts("파일 오픈 실패");
		return -1;
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

}

void tracefile() {
	// 파일 오픈
	FILE* fp = fopen("CW_Lite_powerConsumption.trace", "rb");
	if (fp == NULL) {
		puts("파일 오픈 실패");
		return -1;
	}

	// 소비 전력 - 파형의 각 포인트
	trace = (float**)malloc(waveform * sizeof(float*));
	if (trace == NULL) {
		puts("메모리 할당 실패 (파형의 각 포인트)");
		fclose(fp);
		return -1;
	}

	fseek(fp, 32, SEEK_SET); // fp 위치를 시작으로부터 32번째로 옮김

	for (int i = 0;i < waveform;i++) {
		trace[i] = (float*)malloc(point * sizeof(float));
		if (trace[i] == NULL) {
			puts("메모리 할당 실패");
			for (int j = 0;j < i;j++) {
				free(trace[j]);
			}
			free(trace);
			fclose(fp);
			return -1;
		}
		fread(trace[i], sizeof(float), point, fp); // 소비전력 읽기
	}
	
	//출력
	for (int i = 0;i < 10;i++) {
		printf("Tracefile [%d] : ", i + 1);
		for (int j = 0;j < 10;j++) {
			printf("%f ", trace[i][j]);
		}
		printf("\n");
	}
	
	fclose(fp);
}

void plaintext() {
	// 파일 오픈
	FILE* fp2 = fopen("CW_Lite_plain.bin", "rb");
	if (fp2 == NULL) {
		puts("파일 오픈 실패");
		return -1;
	}

	// 이차원 배열 동적할당
	plain = (BYTE**)malloc(waveform * sizeof(BYTE*));
	// plain은 이중포인터로 선언됨
	// malloc(num * sizeof(BYTE*))으로 num(1000)개의 BYTE 포인터를 저장할 공간 할당
	// -> 각 행을 가리킬 포인터 배열 우선 만듦
	//    plain은 1000 크기의 포인터 배열이 됨

	if (plain == NULL) {
		puts("메모리 할당 실패(num)");
		fclose(fp2);
		return -1;
	}

	for (int i = 0;i < waveform;i++) {
		plain[i] = (BYTE*)malloc(16 * sizeof(BYTE));
		// plain[i]은 각 행을 가리키는 포인터
		//malloc(16 * sizeof(BYTE))를 사용해 각 행에 대해 16바이트 크기의 메모리 할당
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
			return -1;
		}
	}

	// 파일에서 1바이트씩 읽어서 저장
	// 1바이트씩 16개를 읽어서 한 행에 저장
	// 총 16열씩 1000행
	for (int i = 0;i < waveform;i++) {
		fread(plain[i], sizeof(BYTE), 16, fp2);
	}

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

	fclose(fp2);
	return 0;
}

void intermediate_values(int byte_index) { // 중간값 계산 : 256*1000 (guesskey 256개 * plain 한 바이트의 1000열)
	for (int i = 0; i < guesskey_num; i++) { // guesskey: 00~ff (0~255)
		for (int j = 0; j < waveform; j++) { // plain 1000 행까지
			BYTE xor = plain[j][byte_index] ^ i; // XOR 연산
			BYTE sbox = AES_SBOX[xor >> 4][xor &0x0F]; // S-box 적용
			// xor >> 4 : xor 값을 4비트 이동 (0x7d를 0x07로 변경 -> AES_SBOX의 첫 번째 인덱스)
			// xor & 0x0F : xor 값에서 하위 4비트만 추출 (0x7d와 0x0f(1111) 연산 시, 하위 4비트만 남김 -> AES_SBOX의 두 번째 인덱스)
			interm[i][j] = sbox; // sbox의 결과 저장
		}
	}
}

void dpa() {
	for (int byte_index = 0; byte_index < 16; byte_index++) { // 0~15바이트 각각 계산
		intermediate_values(byte_index); // 중간값 계산

		float max_value = 0.0; // 평균의 차 중 가장 큰 값 초기화
		int best_guesskey = 0; // 그 때의 guesskey
		float second_max_value = 0.0;
		int second_best_guesskey = 0;


		for (int i = 0;i < guesskey_num;i++) { // guesskey 00~ff
			for (int j = point_start;j < point_end;j++) { // point 0~14863 -> SPA : SubByte를 하는 부분만 잘라서 point 돌리기(start 500 ~ end 2300)->시간 단축
				float sum_0 = 0.0, sum_1 = 0.0; // 0set과 1set의 합
				int count_0 = 0, count_1 = 0; // set의 원소의 개수

				for (int k = 0;k < waveform;k++) { // 파형 0~999
					if ((interm[i][k] >> 7) & 1) { // msb가 1일 경우 
						sum_1 += trace[k][j];
						count_1++;
					}
					else { // msb가 0일 경우
						sum_0 += trace[k][j];
						count_0++;
					}
				}
				float avg_0 = (count_0 > 0) ? sum_0 / count_0 : 0.0; // 0set 원소의 개수가 0 초과일 경우, sum/count로 평균 계산
				float avg_1 = (count_1 > 0) ? sum_1 / count_1 : 0.0;
				float diff = fabs(avg_1 - avg_0); // fabs 함수로 두 set의 평균의 차 계산

				//평균의 차 중 최댓값, 두 번째로 큰 값 구하기
				if (diff > max_value) { // 현재 pearson_value 값이 기존의 max_pearson_val보다 클 경우,
					// 최댓값 갱신
					max_value = diff; // max_pearson_val를 현재 pearson_value로 갱신
					best_guesskey = i; // 그 때의 guesskey를 best_guesskey로 저장
				}
				else if (diff > second_max_value) { // 현재 pearson_value 값이 max_val보다 작지만, second_max_val보다 클 경우,
					if (i != best_guesskey) {  // 반드시 최댓값과 다른 경우만 갱신
						second_max_value = diff;
						second_best_guesskey = i;
					}
				}
			}
		}
		float ratio = max_value / second_max_value; // 가장 큰 값/두 번째로 큰 값의 비율 계산
		printf("Byte %d: Max Difference = %f, Second Max Difference = %f, Ratio = %f, Best GuessKey = %c\n", byte_index, max_value, second_max_value, ratio, best_guesskey);
		// guesskey 아스키코드로 출력
	}
}



int main() {
	// 1. 전력소비 측정 - tracefile, plain 정보 불러오기
	//headerinfo();
	tracefile();
	plaintext();

	// 2. DPA
	dpa();

	// 메모리 해제
	for (int i = 0;i < waveform;i++) {
		free(trace[i]);
		free(plain[i]);
	}
	free(trace);
	free(plain);

}