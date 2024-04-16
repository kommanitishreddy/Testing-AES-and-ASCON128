#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>



uint64_t state[5] = { 0 }, t[5] = { 0 };
uint64_t constants[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};
/*void print_state(uint64_t state[5]){
   for(int i = 0; i < 5; i++){
      printf("%016llx\n", state[i]);
   } 
}*/
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
}
void finalization(uint64_t state[5], uint64_t key[2]) {
   state[1] ^= key[0];
   state[2] ^= key[1];
   p(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
}

void encrypt(uint64_t state[5], int length, uint64_t plaintext_block[], uint64_t ciphertext_block[]) {
  // ciphertext_block[0] = plaintext_block[0] ^ state[0];
   //state[0] = ciphertext_block[0];
   for (int i = 0; i < length; i++){
      ciphertext_block[i] = plaintext_block[i] ^ state[0];
      state[0] = ciphertext_block[i];
      p(state, 6);
   }
}
void encryptBuffer(uint64_t *buffer, size_t buffer_size, uint64_t *key, uint64_t *nonce, uint64_t IV) {
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    initialization(state, key);
    
    size_t num_blocks = (buffer_size + 7) / 8; // calculate number of 64-bit blocks
    size_t padded_size = num_blocks * 8;       // calculate padded buffer size
    uint64_t *ciphertext_block = (uint64_t*)malloc(padded_size);

    for (size_t i = 0; i < num_blocks; i++) {
        encrypt(state, 1, &buffer[i], &ciphertext_block[i]);
    }
    finalization(state, key);
    printf("Tag: %016llx %016llx\n", state[3], state[4]);
}

int main() {
    // Initialize nonce, key, and IV
    uint64_t nonce[2] = {0x1234567890abcdef, 0x1234567890abcdef};
    uint64_t key[2] = {0xf740ac80eb71906d, 0xded937e44f74ddcc};
    uint64_t IV = 0x80400c0600000000;
    //const char* inputPath = "input3.txt"; 
    //const char* outputPath = "output.txt";
    clock_t start_time, end_time;
    double elapsed_time;
    struct timespec start, end;
double elapsed;
    int repetitions = 1;
   size_t buffer_size = 10000; // Desired buffer size
    size_t padded_size = ((buffer_size + 7) / 8) * 8; // Adjusted for alignment
    uint64_t *buffer = (uint64_t*)malloc(padded_size);
    memset(buffer, 0xAA, padded_size); // Initialize buffer 
    // Apply padding
    if (buffer_size % 8 != 0) {
        unsigned char *padding_start = ((unsigned char*)buffer) + buffer_size;
        *padding_start = 0x80; // Mark the start of padding
    }

    start_time = clock();
    for (int i = 0; i < repetitions; i++) {
        encryptBuffer(buffer, padded_size, key, nonce, IV);
    }
    end_time = clock();

    elapsed_time = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Encryption time (seconds): %f\n", elapsed_time);
    // Calculate elapsed time in seconds
    // Define CPU frequency in Hz
    double cpu_frequency = 3490000000; // 3.49 GHz
    // Calculate total cycles
    double total_cycles = elapsed_time * cpu_frequency;
    // Calculate cycles per byte
    double cycles_per_byte = total_cycles / buffer_size;
    printf("Cycles per byte: %f\n", cycles_per_byte);
    free(buffer);
}
