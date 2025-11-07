#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define TRACE_FILE "CTF-2-AES-ALIGN-trace.bin"
#define PLAIN_FILE "CTF-2-AES-ALIGN-plain.bin"

#define WAVEFORM 500 // 파형 500 (행)
#define POINT 17110 // 포인트 17110 (열)
#define GUESSKEY_NUM 256 // guesskey 00~ff 256개

#define POINT_START 1000 // SubByte가 시작하는 지점
#define POINT_END 1400 // SubByte가 끝나는 지점 

#define MAX_SHIFT 100 // 파형의 최대 이동 범위

typedef unsigned char BYTE;
BYTE HW[GUESSKEY_NUM][WAVEFORM]; // interm 값에 HW를 적용한 값 저장 (256*1000)

// Sbox 값을 HW모델에 적용한 값을 저장하는 배열 (256)
static const int Sbox_HW[256] = { 4, 5, 6, 6, 5, 5, 6, 4, 2, 1, 5, 4, 7, 6, 5, 5,
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
									 3, 3, 3, 3, 7, 5, 2, 3, 2, 4, 4, 4, 3, 3, 6, 3 };

void headerinfo() {
	// trace 파일 헤더 정보 읽기
	FILE* fp_trace = fopen(TRACE_FILE, "rb");
	if (fp_trace == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	// 1. 파형 수(int) - 4bytes (500 행)
	int waveform_num;
	fread(&waveform_num, sizeof(uint32_t), 1, fp_trace);
	printf("파형 수 : %d\n", waveform_num);

	// 2. 포인트 수(int) - 4bytes (17110 열)
	int point_num;
	fread(&point_num, sizeof(uint32_t), 1, fp_trace);
	printf("포인트 수 : %d\n", point_num);

	// 3. 자료형 크기(int) - 4bytes
	int datatype_size;
	fread(&datatype_size, sizeof(uint32_t), 1, fp_trace);
	printf("자료형 크기 : %d\n", datatype_size);

	// 4. END(int) - 4bytes
	int end;
	fread(&end, sizeof(uint32_t), 1, fp_trace);
	printf("END : 0x%08x\n", end);

	return;
}

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
	*/
}

BYTE** plaintext() {
	// plain 정보 배열에 저장
	FILE* fp_plain = fopen(PLAIN_FILE, "rb");
	if (fp_plain == NULL) {
		puts("파일 오픈 실패");
		return;
	}

	BYTE** plain = (BYTE**)calloc(WAVEFORM, sizeof(BYTE*)); // plain은 500 크기의 포인터 배열

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
	*/
}

void alignment(float** trace, int waveform_num) {
	float* base = trace[0]; // 기준 파형으로 첫 번째 파형 선택

	float base_sum = 0.0f; // 기준 파형 값의 합
	float base_sum_sq = 0.0f; // 기준 파형의 제곱의 합
	for (int p = POINT_START; p < POINT_END; p++) {
		float val = base[p];
		base_sum += val;
		base_sum_sq += val * val;
	}
	int valid_points = POINT_END - POINT_START; // 유효 포인트 수

	float* temp = (float*)calloc(POINT, sizeof(float)); // 비교 파형 정렬 시 사용할 임시 버퍼
	if (!temp) {
		fprintf(stderr, "Memory allocation failed.\n");
		exit(1);
	}

	for (int i = 1; i < waveform_num; i++) { // 기준 파형을 기준으로 trace[1]~trace[499] 정렬
		float* comp = trace[i]; // 현재 비교 대상 파형
		float best_corr = -1.0; // 현재의 최대 상관계수
		int best_shift = 0; // 최대 상관계수일 때의 shift 값

		for (int shift = -MAX_SHIFT; shift <= MAX_SHIFT; shift++) { // -100~100까지 반복
			float sum_comp = 0.0f, sum_comp_sq = 0.0f, sum_prod = 0.0f; // 비교 파형 합, 제곱합, 곱의 총합
			int count = 0; // 유효하게 비교된 포인트 수

			for (int p = POINT_START; p < POINT_END; p++) { // 기준 파형의 포인트와 비교 파형의 shift된 포인트를 비교
				int comp_index = p + shift; // 비교 파형에서 현재 포인트 위치에 shift 적용
				if (comp_index < 0 || comp_index >= POINT) continue; // 유효 범위 확인

				float base_val = base[p]; // 기준 파형의 현재 포인트 값
				float comp_val = comp[comp_index]; // 비교 파형의 shift된 위치의 값

				sum_comp += comp_val;
				sum_comp_sq += comp_val * comp_val;
				sum_prod += base_val * comp_val;
				count++;
			}

			if (count == 0) continue; // 유효 비교 지점이 없으면 계산 생략

			float numerator = count * sum_prod - base_sum * sum_comp * ((float)count / valid_points);
			float denom_base = count * base_sum_sq - base_sum * base_sum * ((float)count / valid_points);
			float denom_comp = count * sum_comp_sq - sum_comp * sum_comp;

			float denominator = sqrtf(denom_base * denom_comp);

			float corr = fabsf(numerator / denominator); // 상관계수 절댓값
			if (corr > best_corr) { // best_corr보다 클 경우 갱신
				best_corr = corr;
				best_shift = shift;
			}
		}

		// best_shift 값만큼 비교 파형을 실제로 shift
		if (best_shift != 0) {
			for (int p = 0; p < POINT; p++) {
				int src_idx = p + best_shift; // 이동된 위치 계산
				temp[p] = (src_idx >= 0 && src_idx < POINT) ? comp[src_idx] : 0.0f; // 유효 범위 외 0 패딩
			}
			memcpy(comp, temp, sizeof(float) * POINT); // 정렬 결과를 comp에 덮어씀
		}
	}
	free(temp);
}

void intermediate_values(BYTE** plain, int byte_index) { // 중간값 계산 : 256*1000 (guesskey 256개 * plain 한 바이트의 1000열)
	for (int guesskey = 0; guesskey < GUESSKEY_NUM; guesskey++) { // guesskey: 00~ff (0~255) 하나씩 대입해서 구하기
		for (int plaintext_row = 0; plaintext_row < WAVEFORM; plaintext_row++) { // plaintext 1000 행까지
			BYTE xor = plain[plaintext_row][byte_index] ^ guesskey; // XOR 연산
			HW[guesskey][plaintext_row] = Sbox_HW[xor]; // HW된 S-box 값을 HW배열에 저장 
			// xor >> 4 : xor 값을 4비트 이동 (0x7d를 0x07로 변경 -> AES_SBOX의 첫 번째 인덱스)
			// xor & 0x0F : xor 값에서 하위 4비트만 추출 (0x7d와 0x0f(1111) 연산 시, 하위 4비트만 남김 -> AES_SBOX의 두 번째 인덱스)
		}
	}
}

void cpa(float** trace, BYTE** plain) {
	float max_pearson_val, second_pearson_val; // 피어슨 상관계수의 첫째, 둘째값 저장 변수
	int best_guesskey, second_guesskey; // 그 때의 guesskey 저장 변수

	// X : 가상 소비전력 값 (interm), Y : 실제 소비전력 값 (trace), n : 실제 소비전력의 개수(waveform)
	float sum_X2, sum_Y2, sum_X, sum_Y, sum_XY, pearson_value;
	for (int byte_index = 0; byte_index < 16; byte_index++) { // 0~15바이트 각각 계산
		intermediate_values(plain, byte_index); // 중간값 계산
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

	// 1. 전력소비 측정 - trace, plain 파일 읽기
	//headerinfo();
	float** trace = tracefile(); // trace 이차원 포인터 선언 (trace 이차원 배열 주소 저장)
	BYTE** plain = plaintext();

	// 2. 파형 정렬
	alignment(trace, WAVEFORM);
	cpa(trace, plain);

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