/* 
 * M2.5 Project: Advanced Encryption Standard (AES)
 * Author: Luis A. Gonzalez Villalobos
 * Date: 02/19/2024 - 1 day late :(
 * AES Implementation as described in the FIPS 197 specification.
 */

// unsigned char arrays are not working
// change all to uint8_t for bytes and uint32_t for words
// #include <iostream> 
// #include <iomanip>
// #include <vector>
#include <stdio.h>
#include <cstdint>

using namespace std;

/* Global Variables */

// AES S-box taken from the aes_arrays_reference.html doc provided in the project write-up.
uint8_t sbox[16][16] = {
  { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
  { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
  { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
  { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
  { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
  { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
  { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
  { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
  { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
  { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
  { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
  { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
  { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
  { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
  { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
  { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};

// Round constant word array. This array can be generated using xtime(), but was provided in the useful arrays doc.
uint32_t rcon[52] = { 
  0x00000000, 0x01000000, 0x02000000, 0x04000000,
  0x08000000, 0x10000000, 0x20000000, 0x40000000,
  0x80000000, 0x1B000000, 0x36000000, 0x6C000000,
  0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
  0x2F000000, 0x5E000000, 0xBC000000, 0x63000000,
  0xC6000000, 0x97000000, 0x35000000, 0x6A000000,
  0xD4000000, 0xB3000000, 0x7D000000, 0xFA000000,
  0xEF000000, 0xC5000000, 0x91000000, 0x39000000,
  0x72000000, 0xE4000000, 0xD3000000, 0xBD000000,
  0x61000000, 0xC2000000, 0x9F000000, 0x25000000,
  0x4A000000, 0x94000000, 0x33000000, 0x66000000,
  0xCC000000, 0x83000000, 0x1D000000, 0x3A000000,
  0x74000000, 0xE8000000, 0xCB000000, 0x8D000000
}; 

// AES inverse S-box; provided in the useful arrays doc.
uint8_t invSbox[16][16] = {
  { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
  { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
  { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
  { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
  { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
  { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
  { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
  { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
  { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
  { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
  { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
  { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
  { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
  { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
  { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
  { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
};


/* Helper functions:
 * 1. Finite Field Arithmetic: 
 *   a. ffAdd(): Takes two unsigned chars (one byte) and XORs them to produce addition in two finite fields.
 *   b. xtime(): Takes one unsigned chars (one byte) and left shifts it to produce multiplication of a finite field by x(0x02). 
 *   c. ffMultiply(): Utilizes xtime() to multiply two unsigned chars producing a result of multiplying one finite field by another finite field.
 * 2. Key Expansion:
 *   a. subWord(): Takes a four-byte input word and substitudes each byte in that word with its appropriate value from the S-Box.
 *   b. rotWord(): Performs a cyclic permutation on its input word.
 * 3. Cipher Function:
 *   a. subBytes(): Transformation that substitutes each byte in the state with its corresponding value from the S-Box.
 *   b. shiftRows(): Transformation that performs a circular shift on each row in the state.
 *   c. mixColumns(): Transformation that treats each column in state as a four-term polynomial. The polynomial is multiplied
 *                    by a fixed polynomial with coefficients. - THIS SUCKs - fixed!
 *   d. addRoundKey(): Transformation adds a round key to the state using XOR.
 * 4. invCipher Function:
 *   a. invSubBytes(): Transformation that substitues each byte in the state with its corresponding value from the inverse S-Box.
 *   b. invShiftRows(): Transformation that performs the inverse of shiftRows() on each row in the state.
 *   c. invMixColumns(): Transformation is the inverse of mixColumns() - ALSO SUCKED
 */

// Adds two finite fields - GF(2^8)
uint8_t ffAdd(uint8_t a, uint8_t b)
{
	return a ^ b; // XOR operation performs addition in GF(2^8)
}

// Multiplies a finite field element by x (0x02) in GF(2^8)
uint8_t xtime(uint8_t a)
{
  // If most significant bit (MSB) of 'a' is 0, do a left shift by 1 bit
  // If MSB is 1, do a left shift and XOR with 0x1B to bring the binary polynomial under the 8th degree
  return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

// Uses xtime() to do finite field multiplication in GF(2^8)
uint8_t ffMultiply(uint8_t a, uint8_t b)
{
  uint8_t result = 0x00;
  while (b) {
    // If the lest significant bit (LSB) of 'b' is 1, add 'a' to the result
    if (b & 0x01)
      result ^= a;
    // Multiply 'a' by x (0x02)
    a = xtime(a);
    // Right shift 'b' by 1 bit
    b >>= 1;
  }
  return result;
}

// // Substitutes each byte in a four-byte word using the AES S-box
// // Takes a pointer to the four-byte word as input
// void subWord(unsigned char* word) 
// {
//   // Loop to iterate through each byte in word
//   for (int i = 0; i < 4; i++)
//     word[i] = sbox[word[i]];
// }

// // Perform a cyclic permutation on a four-byte word by shifting its bytes one position to the left
// void rotWord(unsigned char* word)
// {
//   // Store the first byte of the word
//   unsigned char temp = word[0];
//   // Shift butes one position to the left
//   word[0] = word[1];
//   word[1] = word[2];
//   word[2] = word[3];
//   // Place stored (first) byte at the end
//   word[3] = temp;
// }

// // subBytes tranformation
// void subBytes(vector<unsigned char>& state)
// {
//   for (int i = 0; i < 16; i++)
//     state[i] = sbox[state[i]];
// }

// // shiftRows transformation
// void shiftRows(vector<unsigned char>& state)
// {
//   unsigned char tmp[16];
//   for (int i = 0; i < 16; i++)
//     tmp[i] = state[i];
//   for (int i = 1; i < 4; i++)
//     for (int j = 0; j < 4; j++)
//       state[i + j * 4] = tmp[i * 4 + j];
// }

// // mixColumns transformation
// void mixColumns(vector<unsigned char>& state)
// {
//   for (int i = 0; i < 4; i++) {
//     unsigned char s0 = state[i];
//     unsigned char s1 = state[i + 4];
//     unsigned char s2 = state[i + 8];
//     unsigned char s3 = state[i + 12];

//     state[i] = (unsigned char)(0x02 + s0 ^ 0x03 * s1 ^ s2 ^ s3);
    
//   }
// }




//global for number of rounds
int Nr = 0;

//note: key for us with this algorithm is given as byte[], but both
//	cipher and invCipher require word[] as input. key expansion performs
//	this conversion.

//takes a four-byte input word and substitutes each byte in that
//	word with its appropriate value from (global) s-box
uint32_t subWord(uint32_t a) {
	uint32_t tmp = 0;

	for (int i = 0; i < 4; i++) {
		tmp ^= sbox[(a >> 4) & 0xf][a & 0xf] << i * 8;
		a >>= 8;
	}

	return tmp;
}

//performs cyclic permutation on input word
uint32_t rotWord(uint32_t a) {
	uint32_t tmp = 0;

	tmp ^= a << 8 & 0xffffff00;
	tmp ^= a >> 24 & 0xff;

	return tmp;
}


//determing Nr (number of rounds) as a function
//	of Nb (4) and Nk (4, 6, 8)
int getNr(int Nk) {
	if (Nk == 4) 
		return 10;
	else if(Nk == 6) 
		return 12;
	else 
		return 14;
}

//note: using pseudo-code from specification (5.2)
//		also, do i need 3rd arg (int Nk)?
//take cipher key k and perform a key expansion routine to generate
//	the key schedule.
void keyExpansion(uint8_t *key, uint32_t *w, int Nk) {
	uint32_t tmp;
	int i;

	i = 0;

	while (i < Nk) {
		w[i] = (key[4 * i] << 24) ^ (key[4 * i + 1] << 16) ^ (key[4 * i + 2] << 8) ^ (key[4 * i + 3]);
		i++;
	}

	i = Nk;
	Nr = getNr(Nk);

	//while (i < Nb * (Nr+1) where Nb == 4
	while (i < 4 * (Nr + 1)) {
		tmp = w[i - 1];
		
		if (i % Nk == 0) 
			tmp = subWord(rotWord(tmp)) ^ rcon[i / Nk];
		else if (Nk > 6 && i % Nk == 4)
			tmp = subWord(tmp);
		
		w[i] = w[i - Nk] ^ tmp;
		i++;
	}
}

//how would these work if Nb (second arg of state) wasn't 4?
//	c++ does not like state[4][] or any variant since i defined
//	state in main as "state[4][4]"

//this transformation substitutes each byte in the State with its 
//	corresponding value from the S-Box
void subBytes(uint8_t state[4][4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = sbox[(state[i][j] >> 4) & 0xf][state[i][j] & 0xf];
		}
	}
}

//this transformation performs a circular shift on each row in the 
//	State (5.1.2)
void shiftRows(uint8_t state[4][4]) {
	int i;
	for (int row = 1; row < 4; row++) {
		uint8_t tmp_row[row];
		for (i = 0; i < row; i++) tmp_row[i] = state[row][i];
		
		for (i = row; i < 4; i++) state[row][i-row] = state[row][i];
	 
		for (i = 4 - row; i < 4; i++) state[row][i] = tmp_row[i - (4 - row)];
	}
}

//this transformation treats each column in state as a four-term polynomial 
//this polynomial is multiplied (modulo another polynomial) by a fixed 
//	polynomial with coefficients (4.3 and 5.1.3)
void mixColumns(uint8_t state[4][4]) {
	uint8_t state_prime[4];

	//what was the light weight way to do this, again?
	//	since ffMultiply is overkill or something
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			if (row == 0)
				state_prime[row] = ffMultiply(state[0][col], 0x02) ^ ffMultiply(state[1][col], 0x03) ^ state[2][col] ^ state[3][col];
			else if (row == 1)
				state_prime[row] = state[0][col] ^ ffMultiply(state[1][col], 0x02) ^ ffMultiply(state[2][col], 0x03) ^ state[3][col];
			else if (row == 2)
				state_prime[row] = state[0][col] ^ state[1][col] ^ ffMultiply(state[2][col], 0x02) ^ ffMultiply(state[3][col], 0x03);
			else //row = 3
				state_prime[row] = ffMultiply(state[0][col], 0x03) ^ state[1][col] ^ state[2][col] ^ ffMultiply(state[3][col], 0x02);
		}
		
		for (int i = 0; i < 4; i++) state[i][col] = state_prime[i];
	}
}

//this transformation adds a round key to the State using XOR
void addRoundKey(uint8_t state[4][4], uint32_t *w, int l) {
	uint32_t tmp_col;
	int i;
	for (int col = 0; col < 4; col++) {
		tmp_col = 0;
		
		for (i = 0; i < 4; i++) tmp_col ^= state[i][col] << (24 - (8 * i)); 
		
		printf("%08x", w[l+col]);

		tmp_col ^= w[l+col];

		for (i = 0; i < 4; i++) state[i][col] = tmp_col >> (24 - (8 * i)) & 0xff;
	}
	printf("\n");
}

//note: f*** column major order :)
//function for testing
void printState(uint8_t state[4][4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x", state[j][i]);
		}
	}
	printf("\n");
}

//note: using pseudo-code from specification (5.1)
//the cipher function is specified in section 5.1, and an example is given in appendix B
void cipher(uint8_t *in, uint8_t *out, uint32_t *w) {
	uint8_t state[4][4];
	int i, j, k;


	//state = in;
	for (i = 0, k = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[j][i] = in[k++];
		}
	}

	printf("round[ 0].input     ");
	printState(state);

	printf("round[ 0].k_sch     ");
	addRoundKey(state, w, 0);

	//i == round
	for (i = 1; i < Nr; i++) {
		printf("round[%2d].start     ", i);
		printState(state);
		
		subBytes(state);
		printf("round[%2d].s_box     ", i);
		printState(state);
		
		shiftRows(state);
		printf("round[%2d].s_row     ", i);
		printState(state);
		
		mixColumns(state);
		printf("round[%2d].m_col     ", i);
		printState(state);
		
		printf("round[%2d].k_sch     ", i);
		addRoundKey(state, w, i*4);
	}
	
	printf("round[%d].start     ", Nr);
	printState(state);

	subBytes(state);
	printf("round[%d].s_box     ", Nr);
	printState(state);

	shiftRows(state);
	printf("round[%d].s_row     ", Nr);
	printState(state);
	
	printf("round[%d].k_sch     ", Nr);
	addRoundKey(state, w, Nr*4);

	printf("round[%d].output    ", Nr);
	printState(state);

	//out = state
	for (i = 0, k = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			out[k++] = state[j][i];
		}
	}
}

//this transformation substitutes each byte in the State with its 
//	corresponding value from the inverse S-Box, thus reversing the effect of a subBytes() operation
void invSubBytes(uint8_t state[4][4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = invSbox[(state[i][j] >> 4) & 0xf][state[i][j] & 0xf];
		}
	}
}

//this transformation performs the inverse of shiftRows() on each
//	row in the State (5.3.1)
void invShiftRows(uint8_t state[4][4]) {
	int i;
	for (int row = 1; row < 4; row++) {
		uint8_t tmp_row[row];
		for (i = 0; i < row; i++) tmp_row[i] = state[row][4 - row + i];
		
		for (i = 4 - row - 1; i >= 0; i--) state[row][i + row] = state[row][i];
	 
		for (i = 0; i < row; i++) state[row][i] = tmp_row[i];
	}
}

//this transformation is the inverse of mixColumns (5.3.3)
void invMixColumns(uint8_t state[4][4]) {
	uint8_t state_prime[4];

	//what was the light weight way to do this, again?
	//	since ffMultiply is overkill or something
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			if (row == 0)
				state_prime[row] = ffMultiply(state[0][col], 0x0e) ^ ffMultiply(state[1][col], 0x0b) ^ ffMultiply(state[2][col], 0x0d) ^ ffMultiply(state[3][col], 0x09);
			else if (row == 1)
				state_prime[row] = ffMultiply(state[0][col], 0x09) ^ ffMultiply(state[1][col], 0x0e) ^ ffMultiply(state[2][col], 0x0b) ^ ffMultiply(state[3][col], 0x0d);
			else if (row == 2)
				state_prime[row] = ffMultiply(state[0][col], 0x0d) ^ ffMultiply(state[1][col], 0x09) ^ ffMultiply(state[2][col], 0x0e) ^ ffMultiply(state[3][col], 0x0b);
			else //row = 3
				state_prime[row] = ffMultiply(state[0][col], 0x0b) ^ ffMultiply(state[1][col], 0x0d) ^ ffMultiply(state[2][col], 0x09) ^ ffMultiply(state[3][col], 0x0e);
		}
		
		for (int i = 0; i < 4; i++) state[i][col] = state_prime[i];
	}

}

//note: inverse of addRoundKey is itself :)

//this function is specified in section 5.3. It reverses the effect of the cipher function
void invCipher(uint8_t *in, uint8_t *out, uint32_t *w) {
	uint8_t state[4][4];
	int i, j, k;

	//state = in;
	for (i = 0, k = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[j][i] = in[k++];
		}
	}

	printf("round[ 0].iinput    ");
	printState(state);
	
	printf("round[ 0].ik_sch    ");
	addRoundKey(state, w, Nr*4);

	//i == round
	for (i = Nr-1; i > 0; i--) {
		printf("round[%2d].istart    ", Nr-i);
		printState(state);
		
		invShiftRows(state);
		printf("round[%2d].is_row    ", Nr-i);
		printState(state);
		
		invSubBytes(state);
		printf("round[%2d].is_box    ", Nr-i);
		printState(state);
		
		printf("round[%2d].ik_sch    ", Nr-i);
		addRoundKey(state, w, i*4);
		printf("round[%2d].ik_add    ", Nr-i);
		printState(state);
		
		invMixColumns(state);
	}
	
	printf("round[%d].istart    ", Nr);
	printState(state);

	invShiftRows(state);
	printf("round[%d].is_row    ", Nr);
	printState(state);
	
	invSubBytes(state);
	printf("round[%d].is_box    ", Nr);
	printState(state);
	
	printf("round[%d].ik_sch    ", Nr);
	addRoundKey(state, w, 0);


	printf("round[%d].ioutput   ", Nr);
	printState(state);
	
	//out = state
	for (i = 0, k = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			out[k++] = state[j][i];
		}
	}
}

/* Driver */

int main(int argc, char *argv[])
{
	// C.1 Test Case
	printf("C.1   AES-128 (Nk=4, Nr=10)\n\n");
	printf("PLAINTEXT:          ");
	uint8_t in[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	
  for(int i = 0; i < 16; i++)
    printf("%02x", in[i]);
	printf("\n");
	
	printf("KEY:                ");
	uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	for(int i = 0; i < 16; i++) printf("%02x", key[i]);
	printf("\n\n");

	uint32_t w[44];
	keyExpansion(key, w, 4);
	
	printf("CIPHER (ENCRYPT):\n");
	uint8_t out[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	cipher(in, out, w);

	printf("\nINVERSE CIPHER (DECRYPT):\n");
	invCipher(out, in, w);

  // C.2 Test Case
	printf("\nC.2   AES-192 (Nk=6, Nr=12)\n\n");
	printf("PLAINTEXT:          ");
	uint8_t in1[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	for(int i = 0; i < 16; i++) printf("%02x", in1[i]);
	printf("\n");
	
	printf("KEY:                ");
	uint8_t key1[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
	for(int i = 0; i < 24; i++) printf("%02x", key1[i]);
	printf("\n\n");

	uint32_t w1[52];
	keyExpansion(key1, w1, 6);
	
	printf("CIPHER (ENCRYPT):\n");
	uint8_t out1[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	cipher(in1, out1, w1);
	
	printf("\nINVERSE CIPHER (DECRYPT):\n");
	invCipher(out1, in1, w1);


  // C.3 Test Case
	printf("\nC.3   AES-256 (Nk=8, Nr=14)\n\n");
	printf("PLAINTEXT:          ");
	uint8_t in2[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	for(int i = 0; i < 16; i++) printf("%02x", in2[i]);
	printf("\n");
	
	printf("KEY:                ");
	uint8_t key2[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	for(int i = 0; i < 32; i++) printf("%02x", key2[i]);
	printf("\n\n");

	uint32_t w2[60];
	keyExpansion(key2, w2, 8);
	
	printf("CIPHER (ENCRYPT):\n");
	uint8_t out2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	cipher(in2, out2, w2);

	printf("\nINVERSE CIPHER (DECRYPT):\n");
	invCipher(out2, in2, w2);
	//end testing c.3
	
	return 0; //amen
}

