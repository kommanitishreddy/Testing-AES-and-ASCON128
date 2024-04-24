#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>


uint64_t state[5] = { 0 }, t[5] = { 0 };
uint64_t constants[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

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
  
   for (int i = 1; i < length; i++){
      ciphertext_block[i] = plaintext_block[i] ^ state[0];
      state[0] = ciphertext_block[i];
      p(state, 6);
   }
}
void encryptFile(const char* inputPath, const char* outputPath, uint64_t* key, uint64_t* nonce, uint64_t IV) {
    FILE *input_file = fopen(inputPath, "rb");
    if (input_file == NULL) {
        printf("Error opening input file!\n");
        return;
    }
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    size_t buffer_size = ((file_size + 7) / 8) * 8;
    uint64_t *buffer = (uint64_t*)malloc(buffer_size);
   
    memset(buffer, 0, buffer_size);
    fread(buffer, 1, file_size, input_file);
    fclose(input_file);
    //apply padding
    if (file_size % 8 != 0) {
        unsigned char *padding_start = ((unsigned char*)buffer) + file_size;
        *padding_start = 0x80;
    }
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    initialization(state, key);
    size_t num_blocks = buffer_size / sizeof(uint64_t);
    uint64_t *ciphertext_block = (uint64_t*)malloc(buffer_size);
   
    for (size_t i = 0; i < num_blocks; i++) {
        encrypt(state, 1, &buffer[i], &ciphertext_block[i]);
    }
    finalization(state, key);
    printf("Tage: %016llx %016llx\n", state[3], state[4]);
    FILE *output_file = fopen(outputPath, "wb");
    if (output_file == NULL) {
        printf("Error opening output file!\n");
    } else {
        fwrite(ciphertext_block, buffer_size, 1, output_file);
        fclose(output_file);
    }
    free(buffer);
    free(ciphertext_block);
}
void decrypt(uint64_t state[5], int length, uint64_t ciphertext_block[], uint64_t decrypt_block[]){

   for (int i = 1; i < length; i++){
     
      decrypt_block[i] = ciphertext_block[i] ^ state[0];
      state[0] = ciphertext_block[i];
      p(state, 6);
   }
}
void remove_padding(uint64_t *buffer, size_t *buffer_size) {
    unsigned char *byte_buffer = (unsigned char *)buffer;
    // Iterate backwards over the buffer to find the padding start
    for (ssize_t i = (*buffer_size) - 1; i >= 0; i--) {
        if (byte_buffer[i] == 0x80) { // Padding start found
            *buffer_size = i; // Adjust buffer size to exclude padding
            return;
        }
    }
}
void decryptFile(const char* cipherPath, const char* decryptPath, uint64_t* key, uint64_t* nonce, uint64_t IV) {
    // Open the input file
    FILE *input_file = fopen(cipherPath, "rb");
    if (input_file == NULL) {
        printf("Error opening input file!\n");
        return;
    }
    // Determine file size
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Allocate buffer for the entire ciphertext
    uint64_t *buffer = (uint64_t*)malloc(file_size);

    // Read file into buffer
    fread(buffer, 1, file_size, input_file);
    fclose(input_file);

    //initialize state 
   state[0] = IV;
   state[1] = key[0];
   state[2] = key[1];
   state[3] = nonce[0];
   state[4] = nonce[1];
   initialization(state,key);

    // Decrypt each 64-bit block
    size_t num_blocks = file_size / sizeof(uint64_t);
    uint64_t *plaintext_block = (uint64_t*)malloc(file_size); 

    for (size_t i = 0; i < num_blocks; i++) {
        decrypt(state, 1, &buffer[i], &plaintext_block[i]);
    }

    // Finalization
    finalization(state, key);
    printf("tagd: %016llx %016llx\n", state[3], state[4]);

    // Remove padding
    size_t plaintext_size = file_size;
    remove_padding(plaintext_block, &plaintext_size);

    // Write decrypted plaintext to file, excluding padding
    FILE *output_file = fopen(decryptPath, "wb");
    if (output_file == NULL) {
        printf("Error opening output file!\n");
    } else {
        fwrite(plaintext_block, 1, plaintext_size, output_file);
        fclose(output_file);
    }
    // Cleanup
    free(buffer);
    free(plaintext_block);
}


int main() {
    // Initialize nonce, key, and IV
    uint64_t nonce[2] = {0x1234567890abcdef, 0x1234567890abcdef};
    uint64_t key[2] = {0xf740ac80eb71906d, 0xded937e44f74ddcc};
    uint64_t IV = 0x80400c0600000000;
    struct rusage usage_start, usage_end;
    double user_time, system_time,total_time;

    const char* inputPath = "input.txt"; 
    const char* outputPath = "output.txt";
    const char* cipherPath = "output.txt";
    const char* decryptPath = "decrypt.txt"; 
    getrusage(RUSAGE_SELF, &usage_start);
    encryptFile(inputPath, outputPath, key, nonce, IV);
    getrusage(RUSAGE_SELF, &usage_end);
    decryptFile(cipherPath, decryptPath, key, nonce, IV);

     // Calculate elapsed user and system time in seconds
    user_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) +
                (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1000000.0;
    system_time = (usage_end.ru_stime.tv_sec - usage_start.ru_stime.tv_sec) +
                  (usage_end.ru_stime.tv_usec - usage_start.ru_stime.tv_usec) / 1000000.0;
   total_time = user_time + system_time;  // Total time in seconds
    printf("Total Time (seconds): %f\n", total_time);
    printf("User Time (seconds): %f\n", user_time);
    printf("System Time (seconds): %f\n", system_time);
}
