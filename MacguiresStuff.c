#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>

#define HASH_SIZE 65
#define CHUNK_SIZE 8192  // Read in 8KB chunks

unsigned char sha256_file(const char *filename) {
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

    return hash;
}

void compare_files_with_server(const char *server_response) {
    char hash1[HASH_SIZE] = {0}; // Server hash
    char client_hash[HASH_SIZE] = {0}; // Client hash
    char mismatched_files[1024] = {0}; // To store mismatched file names

    int mismatch_count = 0;

    // Parse server response (assumes format: "file1.txt : hash\nfile2.txt : hash\n")
    char *line = strtok((char *)server_response, "\n");
    while (line != NULL) {
        char filename[256] = {0};
        char server_hash[HASH_SIZE] = {0};

        // Parse filename and server-side hash from each line
        sscanf(line, "%s : %s", filename, server_hash);

        // Compute the hash of the corresponding file on the client side
        unsigned char *computed_client_hash = sha256_file(filename);
        if (computed_client_hash == NULL) {
            printf("Could not compute hash for client-side file: %s\n", filename);
            line = strtok(NULL, "\n");
            continue;
        }

        // Convert computed client-side hash to a readable hex string
        for (int i = 0; i < 32; i++) {
            snprintf(client_hash + (i * 2), 3, "%02x", computed_client_hash[i]);
        }

        free(computed_client_hash);

        // Compare the server-side hash and client-side hash
        if (strcmp(server_hash, client_hash) != 0) {
            // Hashes do not match, add the filename to the list of mismatches
            if (mismatch_count > 0) {
                strncat(mismatched_files, ", ", sizeof(mismatched_files) - strlen(mismatched_files) - 1);
            }
            strncat(mismatched_files, filename, sizeof(mismatched_files) - strlen(mismatched_files) - 1);
            mismatch_count++;
        }

        // Move to the next line
        line = strtok(NULL, "\n");
    }

    // Print the result
    if (mismatch_count == 0) {
        printf("All files match between the client and the server.\n");
    } else {
        printf("Mismatched files: %s\n", mismatched_files);
    }
}

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
