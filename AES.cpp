/* encrypt.cpp
 * Performs encryption using AES 128-bit
 * @author Cecelia Wisniewska
 */
 /* decrypt.cpp
  * Performs decryption using AES 128-bit
  * @author Cecelia Wisniewska
  */
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
  /* 암호화 중에 초기 라운드 역할 수행
   * AddRoundKey는 128비트 키를 가진 128비트 블록의 XOR일 뿐이다.
   */
void AddRoundKey(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table
 */
/* 16바이트 각각으로 대체
 * S-box를 룩업 테이블로 사용
 */
void SubBytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = s[state[i]];
	}
}

// Shift left, adds diffusion
// 좌측 시프트, 확산(환치) 추가
void ShiftRows(unsigned char* state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* MixColumns uses mul2, mul3 look-up tables
 * Source of diffusion
 */
/* MixColumns는 mul2, mul3 조회 테이블을 사용한다.
 * 확산원
 */
void MixColumns(unsigned char* state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char)state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = (unsigned char)state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = (unsigned char)mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESEncrypt()
 */
/* 각 라운드는 한 번에 128비트로 작동함
 * 라운드 수는 AESEncrypt()에 정의되어 있다.
 */
void Round(unsigned char* state, unsigned char* key) {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

// Same as Round() except it doesn't mix columns
// 열을 혼합하지 않는다는 점을 제외하면 Round()와 동일
void FinalRound(unsigned char* state, unsigned char* key) {
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
/* AES 암호화 함수
* 혼란(전치)과 확산(환치) 단계를 하나의 기능으로 정리
 */
void AESEncrypt(unsigned char* message, unsigned char* expandedKey, unsigned char* encryptedMessage) {
	unsigned char state[16]; // 원본 메시지의 처음 16바이트 저장
							// Stores the first 16 bytes of original message
	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	int numberOfRounds = 9;		// 128비트는 9라운드 + 0라운드 + 10라운드

	AddRoundKey(state, expandedKey); // 처음 라운드
									// Initial round
	for (int i = 0; i < numberOfRounds; i++) {
		Round(state, expandedKey + (16 * (i + 1)));
	}

	FinalRound(state, expandedKey + 160);
	// Copy encrypted state to buffer
	// 암호화된 상태를 버퍼에 복사
	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
}

////////////// Decryption

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 * So basically does the same as AddRoundKey in the encryption
 */
/* Round()()에서 사용되며 암호 해독 중 최종 라운드 역할을 한다.
 * SubRoundKey는 128비트 키를 가진 128비트 블록의 XOR일 뿐이다.
 * 따라서 기본적으로 암호화에서 AddRoundKey와 동일함
 */
void SubRoundKey(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
/* InverseMixColumns는 mul9, mul11, mul13, mul14 검색 테이블을 사용한다.
 * MixColumns의 암호화 효과를 반전시켜 기둥의 혼합 해제
 */
void InverseMixColumns(unsigned char* state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

// Shifts rows right (rather than left) for decryption
// 암호 해독을 위해 왼쪽이 아닌 오른쪽으로 행 이동
void ShiftRows_in(unsigned char* state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
/* 16바이트 각각으로 대체
 * 역 S-box를 룩업 테이블로 사용
 */
void SubBytes_in(unsigned char* state) {
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];// 16바이트 각각으로 대체
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
/* 각 라운드는 한 번에 128비트로 작동함
 * 라운드 수는 AESDecrypt()에 정의되어 있다.
 * 놀랄 것도 없이 암호화 단계를 거꾸로 실행한 경우
 */
void Round_in(unsigned char* state, unsigned char* key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows_in(state);
	SubBytes_in(state);
}

// Same as Round() but no InverseMixColumns
// Round()와 동일하지만 InverseMixColumns은 없음
void InitialRound(unsigned char* state, unsigned char* key) {
	SubRoundKey(state, key);
	ShiftRows_in(state);
	SubBytes_in(state);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
/* AES 암호 해독 기능
 * 모든 암호 해독 단계를 하나의 기능으로 구성
 */
void AESDecrypt(unsigned char* encryptedMessage, unsigned char* expandedKey, unsigned char* decryptedMessage)
{
	unsigned char state[16]; // 암호화된 메시지의 처음 16바이트 저장
							// Stores the first 16 bytes of encrypted message
	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey + 160);

	int numberOfRounds = 9;

	for (int i = 8; i >= 0; i--) {
		Round_in(state, expandedKey + (16 * (i + 1)));
	}

	SubRoundKey(state, expandedKey); // Final round
	// Copy decrypted state to buffer
	// 암호 해독된 상태를 버퍼에 복사
	for (int i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
}


int main() {

	cout << "=============================" << endl;
	cout << " 128-bit AES Encryption Tool   " << endl;
	cout << "=============================" << endl;

	char message[1024];

	cout << "Enter the message to encrypt: ";
	cin.getline(message, sizeof(message));
	cout << message << endl;
	// Pad message to 16 bytes
	// 메시지를 16바이트로 묶음
	int originalLen = strlen((const char *)message);

	int paddedMessageLen = originalLen;

	if ((paddedMessageLen % 16) != 0) {
		paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
	}

	unsigned char * paddedMessage = new unsigned char[paddedMessageLen];
	for (int i = 0; i < paddedMessageLen; i++) {
		if (i >= originalLen) {
			paddedMessage[i] = 0;
		}
		else {
			paddedMessage[i] = message[i];
		}
	}

	unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];

	string str = "01 04 02 03 01 03 04 0A 09 0B 07 0F 0F 06 03 00";

	unsigned char expandedKey[176];
	unsigned char key[16] = { 0x01, 0x04, 0x02, 0x03, 0x01, 0x03, 0x04, 0x0A, 0x09, 0x0B, 0x07, 0x0F, 0x0F, 0x06, 0x03, 0x00 };

	KeyExpansion(key, expandedKey);

	for (int i = 0; i < paddedMessageLen; i += 16) {
		AESEncrypt(paddedMessage+i, expandedKey, encryptedMessage+i);
	}

	cout << "Encrypted message in hex:" << endl;
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int) encryptedMessage[i];
		cout << " ";
	}

	cout << endl;

	cout << "=============================" << endl;
	cout << " 128-bit AES Decryption Tool " << endl;
	cout << "=============================" << endl;

	int messageLen = paddedMessageLen;

	unsigned char* decryptedMessage = new unsigned char[messageLen];

	for (int i = 0; i < messageLen; i += 16) {
		AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
	}

	cout << "Decrypted message in hex:" << endl;
	for (int i = 0; i < messageLen; i++) {
		cout << hex << (int)decryptedMessage[i];
		cout << " ";
	}
	cout << endl;
	cout << "Decrypted message: ";
	for (int i = 0; i < messageLen; i++) {
		cout << decryptedMessage[i];
	}
	cout << endl;

	delete[] encryptedMessage;
	delete[] paddedMessage;
	delete[] decryptedMessage;

	return 0;
}