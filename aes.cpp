#include <iostream>
#include <iomanip>
#include <vector>

using namespace std;

/* Global Variables */

// AES S-box taken from the aes_arrays_reference.html doc provided in the project write-up
static const unsigned char sbox[256] = {
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

/* Helper functions
 * 1. ffAdd(): Takes two unsigned chars (one byte) and XORs them to produce addition in two finite fields.
 * 2. xtime(): Takes one unsigned chars (one byte) and left shifts it to produce multiplication of a finite field by x(0x02). 
 * 3. ffMultiply(): Utilizes xtime() to multiply two unsigned chars producing a result of multiplying one finite field by another finite field.
 * 4. subWord(): Takes a four-byte input word and substitudes each byte in that word with its appropriate value from the S-Box
 * 5. rotWord(): Performs a cyclic permutation on its input word
 */

// Adds two finite fields - GF(2^8)
unsigned char ffAdd(unsigned char a, unsigned char b) 
{
  return a ^ b; // XOR operation performs addition in GF(2^8)
}

// Multiplies a finite field element by x (0x02) in GF(2^8)
unsigned char xtime(unsigned char a)
{
  // If most significant bit (MSB) of 'a' is 0, do a left shift by 1 bit
  // If MSB is 1, do a left shift and XOR with 0x1B to bring the binary polynomial under the 8th degree
  return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

// Uses xtime() to do finite field multiplication in GF(2^8)
unsigned char ffMultiply(unsigned char a, unsigned char b)
{
  unsigned char result = 0x00;
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

// Substitutes each byte in a four-byte word using the AES S-box
// Takes a pointer to the four-byte word as input
void subWord(unsigned char* word) 
{
  // Loop to iterate through each byte in word
  for (int i = 0; i < 4; i++)
    word[i] = sbox[word[i]];
}

// Perform a cyclic permutation on a four-byte word by shifting its bytes one position to the left
void rotWord(unsigned char* word)
{
  // Store the first byte of the word
  unsigned char temp = word[0];
  // Shift butes one position to the left
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  // Place stored (first) byte at the end
  word[3] = temp;
}

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

/* Driver */

int main()
{
  unsigned char result_ffAdd = 0x00;
  unsigned char result_xtime = 0x00;
  unsigned char result_ffMultiply = 0x00;
  unsigned char a = 0x57;
  unsigned char b = 0x13;
  unsigned char word[4] = { 0x2b, 0x7e, 0x15, 0x16 };
  result_ffAdd = ffAdd(a, b);
  result_xtime = xtime(a);
  result_ffMultiply = ffMultiply(a, b);

  cout << "Result of ffAdd:      0x" << setw(2) << setfill('0') << hex << (int)result_ffAdd << endl;
  cout << "Result of xtime:      0x" << setw(2) << setfill('0') << hex << (int)result_xtime << endl;
  cout << "Result of ffMultiply: 0x" << setw(2) << setfill('0') << hex << (int)result_ffMultiply << endl;
  // cout << "Original word:        ";
  // for (int i = 0; i < 4; i++)
  //   cout << hex << (int)word[i];
  // cout << endl;

  // subWord(word);

  // cout << "Substituted word:     ";
  // for (int i = 0; i < 4; i++)
  //   cout << hex << (int)word[i];
  // cout << endl;

  // rotWord(word);

  // cout << "Rotated word:         ";
  // for (int i = 0; i < 4; i++)
  //   cout << hex << (int)word[i];
  // cout << endl;

  return 0;
}