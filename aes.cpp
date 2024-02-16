#include <iostream>
#include <iomanip>

using namespace std;

/* Helper functions
1. ffAdd(): Takes two unsigned chars (one byte) and XORs them to produce addition in two finite fields.
2. xtime(): Takes one unsigned chars (one byte) and left shifts it to produce multiplication of a finite field by x(0x02). 
3. ffMultiply(): Utilizes xtime() to multiply two unsigned chars producing a result of multiplying one finite field by another finite field.
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

/* Driver */

int main()
{
  unsigned char result_ffAdd = 0x00;
  unsigned char result_xtime = 0x00;
  unsigned char result_ffMultiply = 0x00;
  unsigned char a = 0x57;
  unsigned char b = 0x83;

  result_ffAdd = ffAdd(a, b);
  result_xtime = xtime(a);
  result_ffMultiply = ffMultiply(a, b);

  cout << "Result of ffAdd:      " << setw(2) << setfill('0') << hex << (int)result_ffAdd << endl;
  cout << "Result of xtime:      " << setw(2) << setfill('0') << hex << (int)result_xtime << endl;
  cout << "Result of ffMultiply: " << setw(2) << setfill('0') << hex << (int)result_ffMultiply << endl;

  return 0;
}