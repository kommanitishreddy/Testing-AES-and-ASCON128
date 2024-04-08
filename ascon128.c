#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

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
   uint64_t zero_key[5] = {0, 0, 0, key[0], key[1]}; 
   for (int i = 0; i < 5; i++) {
       state[i] ^= zero_key[i];
   }
}

void finalization(uint64_t state[5], uint64_t key[2]) {
   state[1] ^= key[0];
   state[2] ^= key[1];
   
}
void string_to_binary_chunks(const char* str, uint64_t** binary_chunks, int* length) {
    int str_len = strlen(str);
    *length = (str_len + 7) / 8; // Determine how many 64-bit chunks are needed, with padding.
    
    // Allocate memory for the binary chunks.
    *binary_chunks = (uint64_t*)malloc(*length * sizeof(uint64_t));
    memset(*binary_chunks, 0, *length * sizeof(uint64_t)); // Initialize with zeros for padding.
    
    // Copy the string into the allocated 64-bit chunks.
    for (int i = 0; i < str_len; i++) {
        ((char*)(*binary_chunks))[i] = str[i];
    }
}
void encrypt(uint64_t state[5], int length, uint64_t plaintext[], uint64_t ciphertext[]) {
   ciphertext[0] = plaintext[0] ^ state[0];
   for (int i = 1; i < length; i++){
      p(state, 6);
      ciphertext[i] = plaintext[i] ^ state[0];
      state[0] = ciphertext[i];
   }
}

int main() {
   // initialize nonce, key and IV
   uint64_t nonce[2] = {0x1234567890abcdef, 0x1234567890abcdef };
   uint64_t key[2] = { 0x1234567890abcdef, 0x1234567890abcdef};
   uint64_t IV = 0x80400c0600000000;
    uint64_t* binary_chunks;
    int length;
    FILE *inputFile, *outputFile;
    char *inputFileName = "/Users/nitishreddyk/Desktop/ascontest/input.txt"; 
    char *outputFileName = "/Users/nitishreddyk/Desktop/ascontest/output.txt"; 
    
    // Open the input file for reading
    inputFile = fopen(inputFileName, "r");
    if (inputFile == NULL) {
        perror("Failed to open input file");
        return 1;
    }

    // Determine the size of the file
    fseek(inputFile, 0, SEEK_END);
    long fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // Allocate memory for reading the file
    char *plaintext = malloc(fileSize + 1);
    if (plaintext == NULL) {
        perror("Memory allocation failed for plaintext");
        fclose(inputFile);
        return 1;
    }

    // Read the file into the plaintext buffer
    size_t readSize = fread(plaintext, 1, fileSize, inputFile);
    plaintext[readSize] = '\0'; // Ensure null-termination
    fclose(inputFile);

// Convert string to binary chunks.
    string_to_binary_chunks(plaintext, &binary_chunks, &length);
    
    // Proceed with your encryption setup...
    uint64_t* ciphertext = (uint64_t*)malloc(length * sizeof(uint64_t));
if (ciphertext == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return 1; 
}
    
   //encryption
   //initialize state
   state[0] = IV;
   state[1] = key[0];
   state[2] = key[1];
   state[3] = nonce[0];
   state[4] = nonce[1];
   initialization(state,key);
   print_state(state);
    encrypt(state, length, binary_chunks, ciphertext);
  // Open the output file for writing
    outputFile = fopen(outputFileName, "w");
    if (outputFile == NULL) {
        perror("Failed to open output file");
        free(plaintext); 
        return 1;
    }
    fprintf(outputFile, "Ciphertext: \n");
    for (int i = 0; i < length; i++) {
        fprintf(outputFile, "%016" PRIx64 " ", ciphertext[i]);
    }
    fprintf(outputFile, "\n");

    fclose(outputFile);

   finalization(state, key);
   state[3] ^= key[0]; 
   state[4] ^= key[1];
   printf("tag: %016llx %016llx\n", state[3], state[4]);
  
    free(plaintext);
    free(binary_chunks);
    free(ciphertext);
 
}


        
   