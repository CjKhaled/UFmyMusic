#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>


#define COMMANDBUFFERSIZE 8
#define MAXHASHMAPSIZE 50
#define MAXOUTPUTSIZE 512
#define MAXERRORSIZE 256

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

void diffService(struct ResponseMessage *response) {
    printf("Starting the DIFF service...\n");
    strcpy(response->output, "This is the DIFF service.");
}

void pullService(struct ResponseMessage *response) {
    printf("Starting the PULL service...\n");
    strcpy(response->output, "This is the PULL service.");
}

void leaveService(struct ResponseMessage *response) {
    printf("Starting the LEAVE service...\n");
    strcpy(response->output, "This is the LEAVE service.");
}

void craft_response(const struct RequestMessage *request, struct ResponseMessage *response) {
    // instead of sending back strings, the server will craft responses using structs
    // whatever service is sent in the commandBuffer is how the client knows what to read
    if (strcmp(request->commandBuffer, "LIST") == 0) {
        strcpy(response->commandBuffer, "LIST");
        listService(response);
    } else if (strcmp(request->commandBuffer, "DIFF") == 0) {
        strcpy(response->commandBuffer, "DIFF");
        diffService(response);
    } else if (strcmp(request->commandBuffer, "PULL") == 0) {
        strcpy(response->commandBuffer, "PULL");
        pullService(response);
    } else if (strcmp(request->commandBuffer, "LEAVE") == 0) {
        strcpy(response->commandBuffer, "LEAVE");
        leaveService(response);
    } else {
        strcpy(response->commandBuffer, "ERROR");
        strcpy(response->error, "Service does not exist.");
    }
}

void* handleClientConnect(void *connectedClientPointer) {
    // for some reason, i HAVE to pass in a void pointer
    struct ConnectedClientDetails *connectedClient = (struct ConnectedClientDetails*) connectedClientPointer;

    while (1) {
        // refactor to recieving and sending request structs instead of strings
        struct RequestMessage request;
        struct ResponseMessage response;

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

        // send response
        printf("Sending response...\n");
        if (send(connectedClient->clientSocket, &response, sizeof(response), 0) != sizeof(response)) {
            perror("send() failed\n");
            break;
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