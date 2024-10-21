#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>

#define CHUNK_SIZE 8192  // Read in 8KB chunks

void sha256_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File opening failed");
        return;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char buffer[CHUNK_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    size_t bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, CHUNK_SIZE, file))) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    fclose(file);

    // Print the SHA-256 hash as a hex string
    printf("SHA-256: ");
    for (unsigned int i = 0; i < hash_len; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    // Hardcoded filename to be hashed
    const char *filename = "C:\\Users\\macgu\\OneDrive\\Documents\\GitHub\\test-repo\\client\\test1.txt";

    sha256_file(filename);

    return 0;
}
