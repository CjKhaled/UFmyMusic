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
#define MAXHASHMAPSIZE 50
#define MAXOUTPUTSIZE 512
#define MAXERRORSIZE 256
#define CHUNK_SIZE 8192

struct ConnectedClientDetails {
    int clientSocket;
};

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
    // for each filename the server has saved, 
    // add it as a key and add it's hashed contents as a value
    DIR *d;
    struct dirent *dir;
    struct stat fileStat;
    char path[512];
    unsigned char *fileHash;
    d = opendir("./server");

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            // ignore server file
            if (strcmp(dir->d_name, "server-f.c") == 0) {
                continue;
            }

            snprintf(path, sizeof(path), "./server/%s", dir->d_name);

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

void listService(struct ResponseMessage *response) {
    printf("Starting the LIST service...\n");

    // dynamically allocatting memory since it's temporary
    char *buffer = malloc(512 * sizeof(char));
    if (buffer == NULL) {
        perror("malloc failed\n");
        strcpy(response->commandBuffer, "ERROR");
        strcpy(response->error, "Could not send files.");
        return;
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
        // use the output and/or map fields for successful responses
        strcpy(response->output, buffer);
        free(buffer);
    } else {
        // if an error occurs, set the command buffer to ERROR
        // set the error to the error message the client should see
        perror("opendir failed\n");
        free(buffer);
        strcpy(response->commandBuffer, "ERROR");
        strcpy(response->error, "Could not send files.");
        return;
    }
}

void diffService(struct ResponseMessage *response, const struct RequestMessage *request) {
    printf("Starting the DIFF service...\n");
    // the request contains the filenames and hashes the client has, and the server has the same structure
    // for each filename the server has, look for it in the client
    // if there is match, check their hashes
    // if their hashes match, we don't need to send the file back to server
    // populate the response content with the remaining keys separated by a space
    char *buffer = malloc(512 * sizeof(char));
    if (buffer == NULL) {
        perror("malloc failed\n");
        strcpy(response->commandBuffer, "ERROR");
        strcpy(response->error, "Could not allocate memory.");
        return;
    }
    
    buffer[0] = '\0';

    for (int i = 0; i < response->map.size; i++) {
        bool found = false;
        for (int j = 0; j < request->map.size; j++) {
            if (strcmp(response->map.keys[i], request->map.keys[j]) == 0) {
                if (memcmp(response->map.values[i], request->map.values[j], 32) == 0) {
                    found = true;
                    break;
                }
            }
        }
        
        if (!found) {
            strncat(buffer, response->map.keys[i], 512 - strlen(buffer) - 1);
            strncat(buffer, " ", 512 - strlen(buffer) - 1);
        }
    }

    if (strlen(buffer) == 0) {
        strcpy(response->output, "No differences found.");
    } else {
        strcpy(response->output, buffer);
    }

    free(buffer);
}

void pullService(struct ResponseMessage *response, const struct RequestMessage *request) {
    printf("Starting the PULL service...\n");
    // figure out what files need to be sent
    // send filenames and file content
    // file content will have to be sent in chunks, with a marker to determine the end of a file

    for (int i = 0; i < response->map.size; i++) {
        bool found = false;

        for (int j = 0; j < request->map.size; j++) {
            if (strcmp(response->map.keys[i], request->map.keys[j]) == 0) {
                if (memcmp(response->map.values[i], request->map.values[j], 32) == 0) {
                    found = true;
                    break;
                }
            }
        }

        if (found) {
            for (int k = i; k < response->map.size - 1; k++) {
                strcpy(response->map.keys[k], response->map.keys[k + 1]);
                memcpy(response->map.values[k], response->map.values[k + 1], 32);
            }
            response->map.size--;  
            i--; 
        }
    }

    if (response->map.size == 0) {
        strcpy(response->output, "No pull necessary.");
    } else {
        strcpy(response->output, "Completed file transer.");
    }
}

void leaveService(struct ResponseMessage *response) {
    printf("Starting the LEAVE service...\n");
    strcpy(response->output, "Client has requested to leave. Goodbye!");
}

void craft_response(const struct RequestMessage *request, struct ResponseMessage *response) {
    // instead of sending back strings, the server will craft responses using structs
    // whatever service is sent in the commandBuffer is how the client knows what to read
    if (strcmp(request->commandBuffer, "LIST") == 0) {
        strcpy(response->commandBuffer, "LIST");
        listService(response);
    } else if (strcmp(request->commandBuffer, "DIFF") == 0) {
        strcpy(response->commandBuffer, "DIFF");
        diffService(response, request);
    } else if (strcmp(request->commandBuffer, "PULL") == 0) {
        strcpy(response->commandBuffer, "PULL");
        pullService(response, request);
    } else if (strcmp(request->commandBuffer, "LEAVE") == 0) {
        strcpy(response->commandBuffer, "LEAVE");
        leaveService(response);
    } else {
        strcpy(response->commandBuffer, "ERROR");
        strcpy(response->error, "Service does not exist.");
    }
}

int send_files(int clientSocket, struct HashMap *map) {
    for (int i = 0; i < map->size; i++) {
        char filePath[512];
        snprintf(filePath, sizeof(filePath), "./server/%s", map->keys[i]);
        
        // Get file size
        struct stat st;
        if (stat(filePath, &st) != 0) {
            perror("Failed to get file stats");
            continue;
        }
        long fileSize = st.st_size;
        
        // Send filename length and filename
        int filenameLen = strlen(map->keys[i]) + 1;
        if (send(clientSocket, &filenameLen, sizeof(int), 0) != sizeof(int)) {
            perror("Failed to send filename length");
            return -1;
        }
        
        if (send(clientSocket, map->keys[i], filenameLen, 0) != filenameLen) {
            perror("Failed to send filename");
            return -1;
        }

        // Send file size
        if (send(clientSocket, &fileSize, sizeof(long), 0) != sizeof(long)) {
            perror("Failed to send file size");
            return -1;
        }
        
        // Open and send file
        FILE *file = fopen(filePath, "rb");
        if (!file) {
            perror("Failed to open file");
            return -1;
        }
        
        unsigned char buffer[CHUNK_SIZE];
        size_t bytesRead;
        long totalBytesSent = 0;

        while ((bytesRead = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
            if (send(clientSocket, buffer, bytesRead, 0) != bytesRead) {
                perror("Failed to send file content");
                fclose(file);
                return -1;
            }
            totalBytesSent += bytesRead;
            
            // Print progress
            float progress = ((float)totalBytesSent / fileSize) * 100;
            printf("\rSending %s: %.1f%%", map->keys[i], progress);
            fflush(stdout);
        }
        printf("\n");
        
        fclose(file);
    }

    // Send end-of-files marker
    const char *eofMarker = "EOF_ALL";
    int markerLen = strlen(eofMarker) + 1;
    if (send(clientSocket, &markerLen, sizeof(int), 0) != sizeof(int)) {
        perror("Failed to send EOF marker length");
        return -1;
    }
    if (send(clientSocket, eofMarker, markerLen, 0) != markerLen) {
        perror("Failed to send EOF marker");
        return -1;
    }
    
    return 0;
}

void* handleClientConnect(void *connectedClientPointer) {
    // for some reason, i HAVE to pass in a void pointer
    struct ConnectedClientDetails *connectedClient = (struct ConnectedClientDetails*) connectedClientPointer;

    while (1) {
        // refactor to recieving and sending request structs instead of strings
        struct RequestMessage request;
        struct ResponseMessage response;
        struct HashMap map = {.size = 0};

        // populate map
        createHashMap(&map);
        response.map = map;
        

        // bug fix, tcp sends as a stream of bytes so ensure all of request message is received
        int totalReceived = 0;
        while (totalReceived < sizeof(struct RequestMessage)) {
            int n = recv(connectedClient->clientSocket, ((char*)&request) + totalReceived, sizeof(struct RequestMessage) - totalReceived, 0);
            if (n <= 0) {
                if (n == 0) {
                    printf("Closed connection with client.\n");
                } else {
                    perror("recv() failed\n");
                }
                break;
            }
            totalReceived += n;
        }

        // create response
        craft_response(&request, &response);

        if (strcmp(request.commandBuffer, "LEAVE") == 0) {
            printf("Client requested to leave. Closing connection...\n");
            if (send(connectedClient->clientSocket, &response, sizeof(response), 0) != sizeof(response)) {
                perror("send() failed\n");
            }
            break;
        }

        // send response
        printf("Sending response...\n");
        if (send(connectedClient->clientSocket, &response, sizeof(response), 0) != sizeof(response)) {
            perror("send() failed\n");
            break;
        }

        // client is still expecting file content if there is a DIFF
        if (strcmp(response.commandBuffer, "PULL") == 0) {
            send_files(connectedClient->clientSocket, &response.map);
        }
    }

    close(connectedClient->clientSocket);
    free(connectedClient);

    return NULL;
}


int main(int argc, char *argv[]) {
    int serverSocket;
    struct sockaddr_in serverAddress, clientAddress;
    unsigned short serverPort = 8555;
    socklen_t clientLength;

    // create socket
    if ((serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed\n");
    }

    // quick bug fix, port would still be in use after terminating the server
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        handle_error("setsockopt() failed\n");
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