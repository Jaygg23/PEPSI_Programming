#include <time.h>
#include "aria.h"

#define TRACE_FILE "CTF-4-ARIA-trace.bin"
#define PLAIN_FILE "CTF-4-ARIA-plain.bin"

#define WAVEFORM 1000 // 파형 1000 (행)
#define POINT 5830 // 포인트 5830 (열)
#define GUESSKEY_NUM 256 // guesskey 00~ff 256개

#define POINT_START 0 
#define POINT_END 5830

typedef unsigned char BYTE;
float HW[GUESSKEY_NUM][WAVEFORM];

typedef uint8_t ARIA_STATE_t[16]; // 128-bit block
typedef uint8_t ARIA128_KEY_t[16]; // 128-bit masterkey

// Sbox를 HW모델에 적용한 값을 저장하는 배열 (256)
static const uint8_t HW_S1[256] = {
	4,5,6,6,5,5,6,4,2,1,5,4,7,6,5,5,
	4,2,4,6,6,4,4,4,5,4,3,6,4,3,4,2,
	6,7,4,3,4,6,7,4,3,4,5,5,4,4,3,3,
	1,5,3,4,2,4,2,4,3,2,1,4,6,4,4,5,
	2,3,3,3,4,5,4,2,3,5,5,5,3,5,5,2,
	4,4,0,6,1,6,4,5,4,5,6,4,3,3,3,6,
	3,7,4,7,3,4,4,3,3,6,1,7,2,4,6,3,
	3,4,1,5,3,5,3,6,5,5,5,2,1,8,6,4,
	5,2,3,5,6,5,2,4,3,5,6,5,3,5,3,5,
	2,2,5,5,2,3,2,2,3,6,4,2,6,5,3,6,
	3,3,4,2,3,2,2,4,3,5,4,3,3,4,4,5,
	6,3,5,5,4,5,4,4,4,4,5,5,4,5,5,1,
	5,4,3,4,3,4,4,4,4,6,4,5,4,6,4,3,
	3,5,5,4,2,2,6,3,3,4,5,5,3,3,4,5,
	4,5,3,2,4,5,4,3,5,4,4,5,5,4,2,7,
	3,3,3,3,7,5,2,3,2,4,4,4,3,3,6,3
};
static const uint8_t HW_S1_1[256] = {
	3,2,4,5,2,4,4,3,7,1,4,5,2,6,6,7,
	5,5,4,2,5,5,8,4,3,4,3,2,3,6,5,5,
	3,6,3,3,4,3,3,5,6,3,4,3,2,6,4,4,
	1,4,3,4,2,5,2,4,5,5,3,3,5,4,4,3,
	4,5,6,3,3,3,3,3,4,3,4,4,5,4,5,3,
	4,3,2,2,7,6,5,5,5,3,3,5,5,4,5,2,
	2,4,5,0,3,5,5,2,7,4,3,2,4,5,3,2,
	3,3,4,5,4,6,4,1,3,6,6,2,1,3,3,5,
	4,3,2,2,5,5,5,5,5,5,6,5,4,4,5,5,
	4,4,4,2,6,5,4,3,4,6,5,4,3,5,7,5,
	4,5,3,4,4,3,4,3,6,6,3,3,4,2,6,4,
	6,4,5,4,4,4,5,1,4,6,2,7,4,5,4,5,
	5,6,3,4,2,3,5,3,4,2,1,4,4,1,5,6,
	2,3,7,4,3,5,3,3,4,5,5,6,4,4,4,7,
	2,3,5,4,5,3,6,3,3,6,6,4,3,4,4,3,
	4,4,1,6,5,6,5,3,4,4,2,4,4,2,2,6
};
static const uint8_t HW_S2[256] = {
	4,4,3,6,3,3,3,4,3,3,4,3,4,4,4,4,
	5,6,3,5,4,5,6,4,5,6,4,2,5,3,4,3,
	4,2,2,5,4,4,4,4,5,4,2,5,4,7,6,6,
	0,5,4,7,4,3,3,4,4,2,3,4,4,6,1,6,
	4,7,5,3,4,6,5,3,4,4,3,4,6,5,5,5,
	1,5,2,3,4,3,3,2,4,6,4,5,4,3,2,4,
	8,4,3,3,4,2,3,2,1,4,5,4,3,4,5,4,
	6,5,2,6,3,4,2,3,3,3,2,5,5,5,2,1,
	5,1,3,6,2,4,2,1,3,3,5,5,2,5,3,5,
	4,2,5,5,5,4,6,4,5,1,5,5,4,3,3,5,
	3,6,7,4,4,7,4,4,6,4,4,5,7,5,5,3,
	5,4,3,6,3,5,4,3,3,2,4,3,5,5,3,3,
	2,4,3,4,4,4,4,6,4,4,5,2,3,2,6,5,
	5,5,3,7,3,4,3,6,5,6,1,2,4,2,5,4,
	2,3,5,4,6,4,3,6,3,3,7,3,5,6,5,5,
	6,2,3,4,5,2,5,5,3,6,4,3,6,5,5,2
};
static const uint8_t HW_S2_1[256] = {
	2,3,4,4,4,5,2,4,2,4,6,4,4,2,3,4,
	5,6,5,4,5,2,4,4,3,4,7,5,5,1,3,4,
	2,4,6,3,5,5,6,4,5,3,4,4,4,1,3,4,
	2,4,4,5,6,3,3,4,4,4,3,3,2,5,5,6,
	7,2,5,6,6,4,3,3,5,2,2,4,4,3,1,4,
	3,3,5,6,1,2,5,4,4,4,5,4,3,4,1,5,
	5,4,1,3,2,5,3,5,4,4,2,3,7,7,4,5,
	4,6,5,3,5,4,5,3,3,6,3,4,6,4,3,2,
	5,8,5,4,3,4,6,3,3,5,6,3,2,2,4,4,
	3,4,5,4,1,4,3,3,5,3,5,6,3,5,3,6,
	2,5,4,5,5,6,4,3,7,3,5,4,2,3,4,6,
	6,6,5,6,2,7,5,3,4,6,7,5,2,3,3,4,
	3,5,2,4,4,4,3,5,3,3,5,3,3,5,4,3,
	4,4,4,3,4,5,5,5,2,6,6,4,5,3,6,4,
	5,4,0,3,5,6,3,4,4,5,2,6,1,4,5,5,
	3,3,5,6,2,5,5,5,7,3,2,4,2,3,4,2
};

float** tracefile() {
	// trace 정보 배열에 저장
	FILE* fp = fopen(TRACE_FILE, "rb");
	if (fp == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	// 소비 전력 - 파형의 각 포인트
	float** trace = (float**)calloc(WAVEFORM, sizeof(float*));
	if (trace == NULL) {
		puts("메모리 할당 실패 (파형의 각 포인트)");
		fclose(fp);
		return;
	}

	fseek(fp, 16, SEEK_SET); // fp 위치를 시작으로부터 16번째로 옮김

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
	return trace;

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
	return trace;
	*/
}
BYTE** plaintext() {
	// plain 정보 배열에 저장
	FILE* fp_plain = fopen(PLAIN_FILE, "rb");
	if (fp_plain == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	BYTE** plain = (BYTE**)calloc(WAVEFORM, sizeof(BYTE*)); // plain은 1000 크기의 포인터 배열

	if (plain == NULL) {
		puts("메모리 할당 실패(num)");
		fclose(fp_plain);
		return;
	}

	fseek(fp_plain, 16, SEEK_SET); // fp 위치를 시작으로부터 16번째로 옮김

	for (int i = 0;i < WAVEFORM;i++) {
		plain[i] = (BYTE*)calloc(16, sizeof(BYTE)); // 각 행을 가리키는 포인터 (16바이트 크기의 메모리 할당)
		// 반복문을 통해 500개의 행을 순차적으로 할당 -> [500][16] 크기의 동적 2차원 배열
		if (plain[i] == NULL) {
			puts("메모리 할당 실패"); // 할당 실패 시, 이미 할당된 메모리를 해제해야 메모리 누수 방지
			for (int j = 0; j < i; j++) { // 이전까지 할당된 행의 메모리 해제
				free(plain[j]);
			}
			free(plain); // 행 포인터 배열 자체도 해제
			fclose(fp_plain);
			return;
		}
	}

	// 총 16열씩 1000행
	for (int i = 0;i < WAVEFORM;i++) { // 파일에서 1바이트씩 읽어서 저장 (1바이트씩 16개를 읽어서 한 행에 저장)
		fread(plain[i], sizeof(BYTE), 16, fp_plain);
	}

	fclose(fp_plain);
	return plain;

	/*
	//츨력
	for (int i = 0;i < 10;i++) {
		printf("Plaintext [%d] : ", i + 1);
		for (int j = 0;j < 16;j++) {
			printf("%02x ", plain[i][j]);
		}
		printf("\n");
	}
	fclose(fp_plain);
	return plain;
	*/
}

// 1라운드 키 복구
void interm_rk1_byte(BYTE** plain, BYTE guesskey2, const BYTE known_key[16], int target_byte) {
	for (int guesskey1 = 0; guesskey1 < GUESSKEY_NUM; guesskey1++) {
		for (int plaintext_row = 0; plaintext_row < WAVEFORM; plaintext_row++) {
			BYTE state[16];

			// 1. 평문 복사 및 AddRoundKey 수행
			for (int i = 0; i < 16; i++) {
				if (i == target_byte) state[i] = plain[plaintext_row][i] ^ guesskey1; // CPA 대상: 1바이트만 guesskey 사용
				else state[i] = plain[plaintext_row][i] ^ known_key[i];    // 나머지는 known_key 사용
			}

			// 2. Substitution + LT_layer 수행
			LT_layer(state); // 내부에서 StatetoWord 호출해서 S-box 치환까지 수행

			// 3. y[5] 계산 (DiffLayer 결과의 5번째 바이트에 해당)
			// 4. rk2[5] = gk2와 XOR → S2^-1 → HW
			BYTE y5, y10, y14, y11, sbox_out;
			switch (target_byte) {
			case 1:
				y5 = state[1] ^ state[3] ^ state[4] ^ state[9] ^ state[10] ^ state[14] ^ state[15];
				sbox_out = HW_S2_1[y5 ^ guesskey2];
				HW[guesskey1][plaintext_row] = sbox_out;
				break;
			case 6:
				y10 = state[2] ^ state[3] ^ state[5] ^ state[6] ^ state[8] ^ state[13] ^ state[15];
				BYTE sbox_out = HW_S1[y10 ^ guesskey2];
				HW[guesskey1][plaintext_row] = sbox_out;
				break;
			case 11:
				y14 = state[0] ^ state[3] ^ state[4] ^ state[5] ^ state[9] ^ state[11] ^ state[14];
				sbox_out = HW_S1[y14 ^ guesskey2];
				HW[guesskey1][plaintext_row] = sbox_out;
				break;
			case 12:
				y11 = state[2] ^ state[3] ^ state[4] ^ state[7] ^ state[9] ^ state[12] ^ state[14];
				sbox_out = HW_S2[y11 ^ guesskey2];
				HW[guesskey1][plaintext_row] = sbox_out;
			}
		}
	}
}
void cpa_rk1_byte(float** trace, BYTE** plain, const BYTE known_key[16], int target_byte) {
	float best_corr_overall = 0.0f;
	BYTE best_rk1_byte = 0, best_rk2_byte5 = 0;

	for (int guesskey2 = 0; guesskey2 < GUESSKEY_NUM; guesskey2++) {  // rk2[5] 후보 전수 탐색
		interm_rk1_byte(plain, guesskey2, known_key,target_byte);  // gk2 고정 상태로 중간값 계산

		float max_corr = 0.0f;
		BYTE best_guesskey = 0;

		// rk1[1] 후보 탐색
		for (int guesskey = 0; guesskey < GUESSKEY_NUM; guesskey++) {
			float sum_X = 0.0f, sum_X2 = 0.0f;
			for (int i = 0; i < WAVEFORM; i++) {
				sum_X += HW[guesskey][i];
				sum_X2 += HW[guesskey][i] * HW[guesskey][i];
			}

			for (int point = 0; point < 2000; point++) { // 1라운드 키를 구하기 위한 포인트 : 0 ~ 2000
				float sum_Y = 0.0f, sum_Y2 = 0.0f, sum_XY = 0.0f;
				for (int i = 0; i < WAVEFORM; i++) {
					float y = trace[i][point];
					float x = HW[guesskey][i];
					sum_Y += y;
					sum_Y2 += y * y;
					sum_XY += x * y;
				}

				float numerator = WAVEFORM * sum_XY - sum_X * sum_Y;
				float denominator = sqrtf((WAVEFORM * sum_X2 - sum_X * sum_X) * (WAVEFORM * sum_Y2 - sum_Y * sum_Y));
				if (denominator == 0.0f) continue;

				float corr = fabsf(numerator / denominator);

				if (corr > max_corr) {
					max_corr = corr;
					best_guesskey = guesskey;
				}
			}
		}

		// 전체 최고 상관계수 갱신
		if (max_corr > best_corr_overall) {
			best_corr_overall = max_corr;
			best_rk1_byte = best_guesskey;
			best_rk2_byte5 = guesskey2;
		}

		//printf("rk2 = 0x%02X, max rk1 corr = %f, best rk1[%d] = 0x%02X\n", guesskey2, max_corr, target_byte, best_guesskey);
	}

	printf("\n=== 최종 CPA 결과 ===\n");
	printf("Best rk1[%d] = 0x%02X\n", target_byte, best_rk1_byte);
	printf("Max Correlation = %f\n\n", best_corr_overall);
}

// 2 ~ 5라운드 키 복구
void interm_rk(BYTE** plain, int byte_index, const BYTE rk[5][16], int target_roundkey) {
	for (int guesskey = 0; guesskey < GUESSKEY_NUM; guesskey++) {
		for (int plaintext_row = 0; plaintext_row < WAVEFORM; plaintext_row++) {
			BYTE state[16];
			memcpy(state, plain[plaintext_row], 16); // plain 한 줄을 state에 복사

			switch (target_roundkey) {
			case 2:
				Fo(state, rk[0]); // 1라운드
				state[byte_index] ^= guesskey; // 2라운드 AddRoundKey
				if (byte_index == 0 || byte_index == 4 || byte_index == 8 || byte_index == 12) {
					HW[guesskey][plaintext_row] = HW_S1_1[state[byte_index]];
				}
				else if (byte_index == 1 || byte_index == 5 || byte_index == 9 || byte_index == 13) {
					HW[guesskey][plaintext_row] = HW_S2_1[state[byte_index]];
				}
				else if (byte_index == 2 || byte_index == 6 || byte_index == 10 || byte_index == 14) {
					HW[guesskey][plaintext_row] = HW_S1[state[byte_index]];
				}
				else if (byte_index == 3 || byte_index == 7 || byte_index == 11 || byte_index == 15) {
					HW[guesskey][plaintext_row] = HW_S2[state[byte_index]];
				}
				break;

			case 3:
				Fo(state, rk[0]); // 1라운드
				Fe(state, rk[1]); // 2라운드
				state[byte_index] ^= guesskey; // 3라운드 AddRoundKey
				if (byte_index == 0 || byte_index == 4 || byte_index == 8 || byte_index == 12) {
					HW[guesskey][plaintext_row] = HW_S1[state[byte_index]];
				}
				else if (byte_index == 1 || byte_index == 5 || byte_index == 9 || byte_index == 13) {
					HW[guesskey][plaintext_row] = HW_S2[state[byte_index]];
				}
				else if (byte_index == 2 || byte_index == 6 || byte_index == 10 || byte_index == 14) {
					HW[guesskey][plaintext_row] = HW_S1_1[state[byte_index]];
				}
				else if (byte_index == 3 || byte_index == 7 || byte_index == 11 || byte_index == 15) {
					HW[guesskey][plaintext_row] = HW_S2_1[state[byte_index]];
				}
				break;

			case 4:
				Fo(state, rk[0]); // 1라운드
				Fe(state, rk[1]); // 2라운드
				Fo(state, rk[2]); // 3라운드
				state[byte_index] ^= guesskey; // 4라운드 AddRoundKey
				if (byte_index == 0 || byte_index == 4 || byte_index == 8 || byte_index == 12) {
					HW[guesskey][plaintext_row] = HW_S1_1[state[byte_index]];
				}
				else if (byte_index == 1 || byte_index == 5 || byte_index == 9 || byte_index == 13) {
					HW[guesskey][plaintext_row] = HW_S2_1[state[byte_index]];
				}
				else if (byte_index == 2 || byte_index == 6 || byte_index == 10 || byte_index == 14) {
					HW[guesskey][plaintext_row] = HW_S1[state[byte_index]];
				}
				else if (byte_index == 3 || byte_index == 7 || byte_index == 11 || byte_index == 15) {
					HW[guesskey][plaintext_row] = HW_S2[state[byte_index]];
				}
				break;

			case 5:
				Fo(state, rk[0]); // 1라운드
				Fe(state, rk[1]); // 2라운드
				Fo(state, rk[2]); // 3라운드
				Fe(state, rk[3]); // 4라운드
				state[byte_index] ^= guesskey; // 5라운드 AddRoundKey
				if (byte_index == 0 || byte_index == 4 || byte_index == 8 || byte_index == 12) {
					HW[guesskey][plaintext_row] = HW_S1[state[byte_index]];
				}
				else if (byte_index == 1 || byte_index == 5 || byte_index == 9 || byte_index == 13) {
					HW[guesskey][plaintext_row] = HW_S2[state[byte_index]];
				}
				else if (byte_index == 2 || byte_index == 6 || byte_index == 10 || byte_index == 14) {
					HW[guesskey][plaintext_row] = HW_S1_1[state[byte_index]];
				}
				else if (byte_index == 3 || byte_index == 7 || byte_index == 11 || byte_index == 15) {
					HW[guesskey][plaintext_row] = HW_S2_1[state[byte_index]];
				}
			}
		}
	}
}
void rk_cpa(float** trace, BYTE** plain, BYTE rk[5][16], int target_roundkey) {
	float max_pearson_val, second_pearson_val; // 피어슨 상관계수의 첫째, 둘째값 저장 변수
	int best_guesskey, second_guesskey; // 그 때의 guesskey 저장 변수

	// X : 가상 소비전력 값 (interm), Y : 실제 소비전력 값 (trace), n : 실제 소비전력의 개수(waveform)
	float sum_X2, sum_Y2, sum_X, sum_Y, sum_XY, pearson_value;
	for (int byte_index = 0; byte_index < 16; byte_index++) { // 0~15바이트 각각 계산
		interm_rk(plain, byte_index, rk, target_roundkey); // 중간값 계산
		max_pearson_val = second_pearson_val = 0.0; // 초기화
		best_guesskey = second_guesskey = 0;

		for (int guesskey = 0;guesskey < GUESSKEY_NUM;guesskey++) { // guesskey 00~ff
			sum_X2 = sum_X = 0.0;
			for (int interm_col = 0;interm_col < WAVEFORM;interm_col++) { // 연산 시 point와 상관없는 값들을 미리 저장해서 중복되는 연산 줄임
				sum_X2 += HW[guesskey][interm_col] * HW[guesskey][interm_col];
				sum_X += HW[guesskey][interm_col];
			}
			for (int point = POINT_START;point < POINT_END;point++) { 
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
		printf("rk%d - Byte %d: Max Correlation = %f, Second Max Correlation = %f, Ratio = %f, Best Guesskey = %02x\n", target_roundkey, byte_index, max_pearson_val, second_pearson_val, ratio, best_guesskey);
	}
	printf("\n");
}

// 마스터 키 복구
void compute_T(const BYTE rk0[16], const BYTE rk4[16], BYTE T[16]) { // T = (ek1 <<< 19) ^ (ek5 <<< 31)
	BYTE ek1_rot[16], ek5_rot[16];
	RoL_128bit(rk0, ek1_rot, 19);
	RoL_128bit(rk4, ek5_rot, 31);

	for (int i = 0; i < 16; i++) {
		T[i] = ek1_rot[i] ^ ek5_rot[i];
	}
	//print_hex("T = ", T);
}
void bytes_to_bits(uint8_t bits[128], const BYTE bytes[16]) {
	for (int i = 0; i < 16; i++) {
		for (int b = 0; b < 8; b++) {
			bits[i * 8 + b] = (bytes[i] >> (7 - b)) & 1;
		}
	}
}
void bits_to_bytes(BYTE bytes[16], const uint8_t bits[128]) {
	for (int i = 0; i < 16; i++) {
		bytes[i] = 0;
		for (int j = 0; j < 8; j++) {
			bytes[i] |= bits[i * 8 + j] << (7 - j);
		}
	}
}
void compute_W0_chain(uint8_t W0[128], const uint8_t T_bits[128], int start_bit) {
	int idx = start_bit;
	for (int j = 1; j < 32; j++) {
		int next = (idx + 12) % 128;
		W0[next] = W0[idx] ^ T_bits[idx];
		idx = next;
	}
}
void recover_W0(const BYTE T[16], BYTE MK[16]) {
	uint8_t T_rot19[16], T_bits[128];
	RoR_128bit(T, T_rot19, 19); // T>>>19
	bytes_to_bits(T_bits, T_rot19); // T_rot19를 비트로 변경
	const uint8_t bit_case[16][4] = {
		{0,0,0,0}, {0,0,0,1}, {0,0,1,0}, {0,1,0,0},
		{1,0,0,0}, {0,0,1,1}, {0,1,0,1}, {1,0,0,1},
		{0,1,1,0}, {1,0,1,0}, {1,1,0,0}, {0,1,1,1},
		{1,0,1,1}, {1,1,0,1}, {1,1,1,0}, {1,1,1,1},
	};

	// W0 ^ (W0<<<12) = (T>>>19)
	uint8_t W0[128], W0_rot[128], temp[128];

	const BYTE P[16] = { 0x98, 0xA5, 0xF8, 0x6B, 0xD2, 0xD4, 0x45, 0x02, 0xE0, 0x4C, 0x71, 0x73, 0x79, 0xAA, 0x18, 0x82 };
	const BYTE correct_C[16] = { 0x6F, 0x90, 0x5F, 0x30, 0xDB, 0x9A, 0x19, 0xD6, 0xB6, 0xF4, 0x09, 0xCA, 0x66, 0x23, 0x00, 0x69 };

	// 각 4비트 가정
	for (int bitcase = 0; bitcase < 16; bitcase++) {
		for (int i = 0; i < 4; i++) { // W0[0] ~ W0[3] 가정
			W0[i] = bit_case[bitcase][i];
		}

		// 나머지 비트 계산
		compute_W0_chain(W0, T_bits, 0);
		compute_W0_chain(W0, T_bits, 1);
		compute_W0_chain(W0, T_bits, 2);
		compute_W0_chain(W0, T_bits, 3);

		// W0 <<< 12 계산
		for (int i = 0; i < 128; i++) {
			W0_rot[i] = W0[(i + 12) % 128];
		}
		// W0 ^ (W0 <<< 12) 계산 → temp
		for (int i = 0; i < 128; i++) {
			temp[i] = W0[i] ^ W0_rot[i];
		}
		
		// MK로 암호화 한 결과와 실제 암호문 비교
		int match = 1;
		bits_to_bytes(MK, W0); // 비트 → 바이트 변환

		BYTE cipher[16];
		ARIA128_enc(P, cipher, MK); // 복구된 MK로 평문 암호화
		
		for (int i = 0; i < 16; i++) { // 암호화 결과와 실제 암호문이 일치하는지 확인
			if (cipher[i] != correct_C[i]) {
				match = 0; 
				break;
			}
		}
		if (match) { // 모든 바이트가 일치하면
			printf("Recovered MK : \n");
			for (int i = 0; i < 16; i++) {
				printf("%02x ", MK[i]);
			}
			printf("\n");
			for (int i = 0; i < 16; i++) {
				printf("%c", MK[i]);
			}
			printf("\n\n");
			return;
		}
		
	}
	// 찾지 못할 경우
	printf("W0 복구 실패: 유효한 bit_case 없음\n");
}

int main() {
	clock_t start_time = clock(); // 실행 시작 시간

	// 1. 전력소비 측정 - trace, plain 파일 읽기
	//headerinfo();
	float** trace = tracefile(); // trace 이차원 포인터 선언 (trace 이차원 배열 주소 저장)
	BYTE** plain = plaintext();

	// 2. 1라운드 키 예측
	BYTE known_key[16] = { 0xCB, 0x00, 0x16, 0xA7, 0x91, 0xAA, 0x00, 0x47, 0x4D, 0xA2, 0xD8, 0x00, 0x00, 0x2B, 0xC8, 0x83 };
	int unknown_byte[4] = { 1,6,11,12 };
	for (int i = 0;i < 4;i++) {
		cpa_rk1_byte(trace, plain, known_key, unknown_byte[i]);
	}

	// 3. 2~5 라운드 키 복구
	BYTE rk[5][16] = {
		{ 0xCB, 0xD3, 0x16, 0xA7, 0x91, 0xAA, 0x4D, 0x47, 0x4D, 0xA2, 0xD8, 0x76, 0xCE, 0x2B, 0xC8, 0x83 }, // rk1
		{ 0xBA, 0xE3, 0x64, 0x1F, 0x9E, 0x99, 0x65, 0xFC, 0x3D, 0xED, 0x67, 0xEA, 0x8D, 0x51, 0x5E, 0xA7 },
		{ 0x3F, 0x16, 0xF4, 0xE9, 0xDC, 0x1D, 0x98, 0x32, 0xE0, 0xE3, 0x64, 0x7A, 0x13, 0xE1, 0x18, 0xFE },
		{ 0x10, 0xA0, 0xDB, 0xA0, 0x09, 0xEE, 0x84, 0xDD, 0xD0, 0xCD, 0x60, 0x61, 0x33, 0x22, 0x62, 0x66 },
		{ 0x25, 0x27, 0x59, 0x81, 0x2F, 0x6C, 0x7C, 0xCA, 0x81, 0x97, 0x92, 0x33, 0x08, 0x8A, 0x28, 0xCD }
	};
	for (int target_roundkey = 2;target_roundkey <= 5;target_roundkey++) {
		rk_cpa(trace, plain, rk, target_roundkey);
	}

	// 4. 마스터 키 복구
	BYTE T[16], MK[16];
	compute_T(rk[0], rk[4], T);
	recover_W0(T, MK);

	unsigned char plaintext[16] = { 0x98, 0xA5, 0xF8, 0x6B, 0xD2, 0xD4, 0x45, 0x02, 0xE0, 0x4C, 0x71, 0x73, 0x79, 0xAA, 0x18, 0x82 };
	unsigned char ciphertext[16] = { 0x00, };

	ARIA128_enc(plaintext, ciphertext, MK);

	printf("Plaintext:\n");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", plaintext[i]);
	}
	printf("\n\n");

	printf("Masterkey:\n");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", MK[i]);
	}
	printf("\n\n");

	printf("Ciphertext:\n"); // 6F905F30DB9A19D6B6F409CA66230069
	for (int i = 0; i < 16; i++) {
		printf("%02x ", ciphertext[i]);
	}
	printf("\n\n");

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