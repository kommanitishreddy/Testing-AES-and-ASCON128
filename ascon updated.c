#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>



uint64_t state[5] = { 0 }, t[5] = { 0 };
uint64_t constants[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};

void print_state(uint64_t state[5]){
   for(int i = 0; i < 5; i++){
      printf("%016llx\n", state[i]);
   } 
}

uint64_t rotate(uint64_t x, int l) {
   uint64_t temp;
   temp = (x >> l) ^ (x << (64 - l));
   return temp;
}

void add_constant(uint64_t state[5], int i, int a) {
   state[2] = state[2] ^ constants[12 - a + i];
}
void sbox(uint64_t x[5]) {
   x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
   t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
   t[0] =~ t[0]; t[1] =~ t[1]; t[2] =~ t[2]; t[3] =~ t[3]; t[4] =~ t[4];
   t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
   x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
   x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] =~ x[2];
}
void linear(uint64_t state[5]) {
   uint64_t temp0, temp1;
   temp0 = rotate(state[0], 19);
   temp1 = rotate(state[0], 28);
   state[0] ^= temp0 ^ temp1;
   temp0 = rotate(state[1], 61);
   temp1 = rotate(state[1], 39);
   state[1] ^= temp0 ^ temp1;
   temp0 = rotate(state[2], 1);
   temp1 = rotate(state[2], 6);
   state[2] ^= temp0 ^ temp1;
   temp0 = rotate(state[3], 10);
   temp1 = rotate(state[3], 17);
   state[3] ^= temp0 ^ temp1;
   temp0 = rotate(state[4], 7);
   temp1 = rotate(state[4], 41);
   state[4] ^= temp0 ^ temp1;
}

void p(uint64_t state[5], int a){
   for (int i = 0; i < a; i++){
      add_constant(state, i, a);
      sbox(state);
      linear(state);
   }
}

void initialization(uint64_t state[5], uint64_t key[2]) {
   p(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
   // Correctly implement the zero-key XOR operation
   uint64_t zero_key[5] = {0, 0, 0, key[0], key[1]}; // Assuming a 128-bit key
   for (int i = 0; i < 5; i++) {
       state[i] ^= zero_key[i];
   }
}


void finalization(uint64_t state[5], uint64_t key[2]) {
   state[1] ^= key[0];
   state[2] ^= key[1];
   
}

void encrypt(uint64_t state[5], int length, uint64_t plaintext_block[], uint64_t ciphertext_block[]) {
   ciphertext_block[0] = plaintext_block[0] ^ state[0];
   for (int i = 1; i < length; i++){
      p(state, 6);
      ciphertext_block[i] = plaintext_block[i] ^ state[0];
      //printf("ciphertext block %016llx", ciphertext_block[i]);
      state[0] = ciphertext_block[i];
   }
}

int main() {
   // initialize nonce, key and IV
   uint64_t nonce[2] = {0x1234567890abcdef, 0x1234567890abcdef };
   uint64_t key[2] = { 0x1234567890abcdef, 0x1234567890abcdef};
   uint64_t IV = 0x80400c0600000000;
    // File handling
  FILE *input_file = fopen("input.txt", "rb");
  FILE *output_file = fopen("output.txt", "wb"); 

  if (input_file == NULL || output_file == NULL) {
      printf("Error opening files!\n");
      return 1;
  }
  // Read plaintext from file in blocks
  const int BLOCK_SIZE = 64; 
  uint64_t plaintext_block[BLOCK_SIZE];
  uint64_t ciphertext_block[BLOCK_SIZE];
   //encryption
  int bytes_read;
  while ((bytes_read = fread(plaintext_block, sizeof(uint64_t), BLOCK_SIZE, input_file)) > 0) {
   // printf("Read %d blocks from input file.\n", bytes_read);

     //initialize state
   state[0] = IV;
   state[1] = key[0];
   state[2] = key[1];
   state[3] = nonce[0];
   state[4] = nonce[1];
   initialization(state,key);
   //print_state(state);
      // Process each block (encryption)
      encrypt(state, bytes_read, plaintext_block, ciphertext_block);
      for (int i = 0; i < bytes_read; i++) {
    fwrite(ciphertext_block, sizeof(uint64_t), bytes_read, output_file);
    }
      
  fclose(input_file);
  fclose(output_file);
  finalization(state, key);
   state[3] ^= key[0]; 
   state[4] ^= key[1];
   printf("tag: %016llx %016llx\n", state[3], state[4]);
   return 0;
   }
}