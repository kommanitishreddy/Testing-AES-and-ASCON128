
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <openssl/bio.h>


void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


int main(void)
{
    /*
     * Set up the key and iv.
     */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* File pointers for input and output files */
    FILE *inputFile, *outputFile;

    /* Open the input file */
    inputFile = fopen("/Users/nitishreddyk/Desktop/aes/input.txt", "rb");
    if (inputFile == NULL)
    {
        perror("Error opening input file\n");
        return 1;
    }

    /* Open the output file */
    outputFile = fopen("/Users/nitishreddyk/Desktop/aes/output.txt", "w");
    if (outputFile == NULL)
    {
        fprintf(stderr, "Error opening output file\n");
        fclose(inputFile);
        return 1;
    }

    /* Get the size of the input file */
    fseek(inputFile, 0, SEEK_END);
    long inputFileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);
    /* Allocate memory for the plaintext buffer */
    unsigned char *plaintext = (unsigned char *)malloc(inputFileSize + 1); // +1 for null terminator
    if (plaintext == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }
    /* Read plaintext from the input file */
    fread(plaintext, 1, inputFileSize, inputFile);
    plaintext[inputFileSize] = '\0'; // Null-terminate the plaintext
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char *ciphertext = malloc(inputFileSize + EVP_MAX_BLOCK_LENGTH);
    if (ciphertext == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }

    /* Buffer for the decrypted text */
    unsigned char *decryptedtext = malloc(inputFileSize + 1);

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, inputFileSize, key, iv, ciphertext);

    /* Write the ciphertext to the output file */
    for (int i = 0; i < ciphertext_len; i++) {
        fprintf(outputFile, "%02x", ciphertext[i]);
    }
    //fwrite(ciphertext, 1, ciphertext_len, outputFile);
    //printf("Ciphertext is:\n");
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    //printf("%s\n", decryptedtext);
    fclose(inputFile);
    fclose(outputFile);
    return 0;
}


void handleErrors(void)
{
    fprintf(stderr, "Error occurred:\n");
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}