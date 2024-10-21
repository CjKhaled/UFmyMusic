#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <stdbool.h>

#define COMMANDBUFFERSIZE 8
#define RECEIVEBUFFERSIZE 512
#define FILENAMESBUFFERSIZE 512
#define MAXHASHMAPSIZE 50
#define CHUNK_SIZE 8192
#define MAXOUTPUTSIZE 512
#define MAXERRORSIZE 256


// Dumbed down version of a hashmap- just using two arrays
struct HashMap {
    int size;
    char keys[MAXHASHMAPSIZE][100];
    unsigned char values[MAXHASHMAPSIZE][32];
};

struct RequestMessage {
    char commandBuffer[COMMANDBUFFERSIZE];
    struct HashMap map;
};

struct ResponseMessage {
    char commandBuffer[COMMANDBUFFERSIZE];
    struct HashMap map;
    char output[MAXOUTPUTSIZE];
    char error[MAXERRORSIZE];
};

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

char *allowedMessages[] = {
    "LIST",
    "DIFF",
    "PULL",
    "LEAVE"
};

int is_valid_command(const char *command) {
    for (int i = 0; i < sizeof(allowedMessages) / sizeof(allowedMessages[0]); i++) {
        if (strcmp(command, allowedMessages[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void flush_input() {
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);
}

unsigned char* sha256_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File opening failed");
        return NULL;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char buffer[CHUNK_SIZE];    
    unsigned char *hash = malloc(EVP_MAX_MD_SIZE);
    if (!hash) {
        perror("Could not allocate memory for hash\n");
        fclose(file);
        return NULL;
    };

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

bool createHashMap(struct HashMap *map) {
    // for each filename the client has saved, 
    // add it as a key and add it's hashed contents as a value
    DIR *d;
    struct dirent *dir;
    struct stat fileStat;
    char path[512];
    unsigned char *fileHash;
    d = opendir("./client");

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            // ignore client file
            if (strcmp(dir->d_name, "client-f.c") == 0) {
                continue;
            }

            snprintf(path, sizeof(path), "./client/%s", dir->d_name);

            if (stat(path, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
                // make sure hashmap doesn't overflow
                if (map->size >= MAXHASHMAPSIZE) {
                    perror("Maximum of 50 files allowed.\n");
                    break;
                }

                strcpy(map->keys[map->size], dir->d_name);
                fileHash = sha256_file(path);
                if (fileHash) {
                    memcpy(map->values[map->size], fileHash, 32);
                    free(fileHash);

                } else {
                    // server will know if the value is the filename, it had trouble hashing
                    strcpy(map->values[map->size], dir->d_name);
                    printf("Failed to generate file hash for %s\n", dir->d_name);
                }

                map->size++;
            }
        }

        closedir(d);
    } else {
        perror("opendir failed\n");
        return false;
    }

    return true;
}

struct RequestMessage craft_request(const char *command, struct HashMap *map) {
    struct RequestMessage request;
    if (strcmp(command, "LIST") == 0) {
        strcpy(request.commandBuffer, "LIST");

    } else if (strcmp(command, "DIFF") == 0) {
        // indicate errors by setting the command buffer to \0
        if (createHashMap(map) == 1) {
            strcpy(request.commandBuffer, "DIFF");
            request.map = *map;
        } else {
            printf("Please try again.\n");
            request.commandBuffer[0] = '\0';
            return request;
        }
        
    } else if (strcmp(command, "PULL") == 0) {
        if (createHashMap(map) == 1) {
            strcpy(request.commandBuffer, "PULL");
            request.map = *map;
        } else {
            strcpy(request.commandBuffer, "ERROR");
        }

    } else {
        strcpy(request.commandBuffer, "LEAVE");
    }
    
    return request;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in serverAddress;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
    char receiveBuffer[RECEIVEBUFFERSIZE];
    struct RequestMessage request;
    struct ResponseMessage response;
    struct HashMap map = {.size = 0};
    
    // create socket
    if ((clientSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed");
    }

    // set address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddress.sin_port = htons(9999);

    // connect to server
    if (connect(clientSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        close(clientSocket);
        handle_error("connect() failed");
    }

    // print welcome message
    printf("You Are Now Connected To Our UFmyMusic App!\n");
    printf("These are the requests you can send to the server:\n");
    printf("LIST (Lists all files server currently has saved)\n");
    printf("DIFF (Sends filenames for files you do not have compared to the server)\n");
    printf("PULL (Sends filenames and file contents for files you do not have compared to the server)\n");
    printf("LEAVE (Exits the program and your connection to the server)\n");
    
    // continously accept input
    while (1) {
        printf("\nEnter message: ");

        // read input
        fgets(commandBuffer, sizeof(commandBuffer), stdin);
        
        // remove newline character from fgets
        size_t len = strlen(commandBuffer);
        if (len > 0 && commandBuffer[len - 1] == '\n') {
            commandBuffer[len - 1] = '\0';
        }

        // prevent bugs from long input
        if (len == sizeof(commandBuffer) - 1 && commandBuffer[len - 1] != '\n') {
            flush_input();
        }

        // validate 
        if (is_valid_command(commandBuffer) == 0) {
            printf("Invalid input.\n");
        } else {
            // refactoring to communicate with structs instead of strings.
            // craft request
            request = craft_request(commandBuffer, &map);

            if (request.commandBuffer[0] == '\0') {
                continue;
            }

            // send request to server
            if (send(clientSocket, &request, sizeof(request), 0) != sizeof(request)) {
                close(clientSocket);
                handle_error("send() failed");
            }

            // receive response from server
            // since it comes as a stream, make sure we get all of it
            int totalReceived = 0;
            while (totalReceived < sizeof(struct ResponseMessage)) {
                int n = recv(clientSocket, ((char*)&response) + totalReceived, sizeof(struct ResponseMessage) - totalReceived, 0);
                if (n <= 0) {
                    if (n == 0) {
                        printf("Server closed connection.\n");
                    } else {
                        perror("recv() failed");
                    }
                    close(clientSocket);
                    exit(1);
                }
                totalReceived += n;
            }

            // print the server's response
            printf("Response: %s\n", response.output);
            if (strcmp(response.commandBuffer, "ERROR") == 0) {
                printf("Error: %s\n", response.error);
            }
        }        
    }    

    close(clientSocket);
    return 0;
}