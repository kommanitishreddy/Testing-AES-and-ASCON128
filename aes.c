
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <openssl/bio.h>


void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);



int main(void)
{
    /* A 256 bit key */
    static unsigned char key_data[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                                        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31 };
    unsigned char *key = key_data;

/* A 128 bit IV */
    static unsigned char iv_data[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                       0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };
    unsigned char *iv = iv_data;

    /* File pointers for input and output files */
    FILE *inputFile, *outputFile;
    /* Open the input file */
    inputFile = fopen("/Users/nitishreddyk/Desktop/aes/input.txt", "r");
    if (inputFile == NULL)
    {
        perror("Error opening input file\n");
        return 1;
    }
    /* Open the output file */
    outputFile = fopen("/Users/nitishreddyk/Desktop/aes/output.txt", "wb");
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
    unsigned char *plaintext = (unsigned char *)malloc(inputFileSize);
    if (plaintext == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }
    /* Read plaintext from the input file */
    fread(plaintext, 1, inputFileSize, inputFile);

    unsigned char *ciphertext = malloc(inputFileSize + EVP_MAX_BLOCK_LENGTH);
    if (ciphertext == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(inputFile);
        fclose(outputFile);
        return 1;
    }

    int  ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, inputFileSize, key, iv, ciphertext);

    /* Write the ciphertext to the output file */
    fwrite(ciphertext, 1, ciphertext_len, outputFile);

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

