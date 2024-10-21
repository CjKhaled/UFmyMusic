#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <stdbool.h>

#define COMMANDBUFFERSIZE 8

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

bool compare_hashes(const unsigned char hash1[], const unsigned char hash2[], int length) {
    //must input longer of the 2 lengths to check for correctness
    return memcmp(hash1, hash2, length) == 0;
}

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

char* listService() {
    printf("Starting the LIST service...\n");

    // dynamically allocatting memory since it's temporary
    char *buffer = malloc(512 * sizeof(char));
    if (buffer == NULL) {
        perror("malloc failed\n");
        return "Could not send files.";
    }

    buffer[0] = '\0';
    int bufferSize = 512;

    DIR *d;
    struct dirent *dir;
    struct stat fileStat;
    char path[512];
    d = opendir("./server");

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            // ignore server file
            if (strcmp(dir->d_name, "server-f.c") == 0) {
                continue;
            }

            snprintf(path, sizeof(path), "./server/%s", dir->d_name);

            // for some reason DT_REG wouldn't work
            if (stat(path, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
                strncat(buffer, dir->d_name, bufferSize - strlen(buffer) - 1);
                strncat(buffer, " ", bufferSize - strlen(buffer) - 1);
            }
        }

        closedir(d);
    } else {
        perror("opendir failed\n");
        free(buffer);
        return "Could not send files.";
    }

    return buffer;
}

char* diffService() {
    printf("Starting the DIFF service...\n");
    return "This is the DIFF service.";
}

char* pullService() {
    printf("Starting the PULL service...\n");
    return "This is the PULL service.";
}

char* leaveService() {
    printf("Starting the LEAVE service...\n");
    return "This is the LEAVE service.";
}

char* find_correct_service(const char *commandBuffer) {
    if (strcmp(commandBuffer, "LIST") == 0) {
        return listService();
    } else if (strcmp(commandBuffer, "DIFF") == 0) {
        return diffService();
    } else if (strcmp(commandBuffer, "PULL") == 0) {
        return pullService();
    } else if (strcmp(commandBuffer, "LEAVE") == 0) {
        return leaveService();
    } else {
        return "Service not available.\n";
    }
}

struct ConnectedClientDetails {
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
};

void* handleClientConnect(void *connectedClientPointer) {
    // for some reason, i HAVE to pass in a void pointer
    struct ConnectedClientDetails *connectedClient = (struct ConnectedClientDetails*) connectedClientPointer;

    while (1) {
        // receive command from client
        int receiveSize;
        if ((receiveSize = recv(connectedClient->clientSocket, connectedClient->commandBuffer, COMMANDBUFFERSIZE - 1, 0)) <= 0) {
            if (receiveSize == 0) {
                printf("Closing connection...\n");
                printf("Closed connection with client.\n");
            } else {
                perror("recv() failed\n");
            }

            break;
        }

        connectedClient->commandBuffer[receiveSize] = '\0';

        // perform service
        char* output = find_correct_service(connectedClient->commandBuffer);

        // send output
        printf("Sending output...\n");
        int outputLength = strlen(output);
        if (send(connectedClient->clientSocket, output, outputLength, 0) != outputLength) {
            perror("send() failed\n");
            break;
        }

        // quick fix for now, change later
        if (strncmp(output, "Could", 5) != 0 && strncmp(output, "This", 4) != 0) {
            free(output);
        }
    }

    close(connectedClient->clientSocket);
    free(connectedClient);

    return NULL;
}


int main(int argc, char *argv[]) {
    int serverSocket;
    struct sockaddr_in serverAddress, clientAddress;
    unsigned short serverPort = 9999;
    socklen_t clientLength;

    // create socket
    if ((serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed\n");
    }

    // set address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(serverPort);

    // bind socket
    if (bind(serverSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        close(serverSocket);
        handle_error("bind() failed\n");
    }

    // listen for connections - max of 5 connections can be queued
    if (listen(serverSocket, 5) < 0) {
        close(serverSocket);
        handle_error("listen() failed\n");
    }

    // accept connections
    while (1) {
        printf("Waiting for connections...\n");
        
        // connect to client - each should have their own socket
        clientLength = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, &clientLength);
        if (clientSocket < 0) {
            perror("accept() failed\n");
            continue;
        }

        printf("Connected to client at %s\n", inet_ntoa(clientAddress.sin_addr));

        // allocate a thread for each client
        struct ConnectedClientDetails *connectedClient = malloc(sizeof(struct ConnectedClientDetails));
        if (connectedClient == NULL) {
            perror("malloc()  failed\n");
            close(clientSocket);
            continue;
        }

        connectedClient->clientSocket = clientSocket;
        pthread_t clientThread;
        
        if (pthread_create(&clientThread, NULL, handleClientConnect, connectedClient) != 0) {
            perror("pthread_create() failed\n");
            close(clientSocket);
            free(connectedClient);
            continue;
        }

        // free up resources for a new client after one leaves
        pthread_detach(clientThread);
        
    }

    close(serverSocket);
    return 0;
}