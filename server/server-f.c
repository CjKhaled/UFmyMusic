#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define COMMANDBUFFERSIZE 8
#define SENDBUFFERSIZE 512

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

int send_service_output(clientSocket, sendBuffer) {
    if (send(clientSocket, sendBuffer, SENDBUFFERSIZE, 0) != SENDBUFFERSIZE) {
        perror("send() failed");
        close(clientSocket);
        return 0;
    }
}

void listService() {
    char* output = "This is the LIST service.";
}

void diffService() {
    char* output = "This is the DIFF service.";
}

void pullService() {
    char* output = "This is the PULL service.";
}

void leaveService() {
    char* output = "This is the LEAVE service.";
}

void find_correct_service(char commandBuffer) {
    if (strcmp(commandBuffer, "LIST")) {
        listService();
    } else if (strcmp(commandBuffer, "DIFF")) {
        diffService();
    } else if (strcmp(commandBuffer, "PULL")) {
        pullService();
    } else if (strcmp(commandBuffer, "LEAVE")) {
        leaveService();
    }
}

int main(int argc, char *argv[]) {
    int serverSocket;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
    char sendBuffer[SENDBUFFERSIZE];
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    unsigned short serverPort = 8888;
    socklen_t clientLength;

    // create socket
    if ((serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed");
    }

    // set address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(serverPort);

    // bind socket
    if (bind(serverSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        close(serverSocket);
        handle_error("bind() failed");
    }

    // listen for connections
    if (listen(serverSocket, 5) < 0) {
        close(serverSocket);
        handle_error("listen() failed");
    }

    // accept connections
    while (1) {
        // connect to client
        clientLength = sizeof(clientAddress);
        if ((clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, &clientLength)) < 0) {
            perror("accept() failed");
            continue;
        }

        // stay connected indefinitely
        while (1) {
            // receive command from client
            int receiveSize;
            if ((receiveSize = recv(clientSocket, commandBuffer, COMMANDBUFFERSIZE - 1, 0)) <= 0) {
                perror("recv() failed");
                close(clientSocket);
                break;
            }

            commandBuffer[receiveSize] = '\0';

            // perform service
            find_correct_service(commandBuffer);

            // send command back
            if (send(clientSocket, commandBuffer, receiveSize, 0) != receiveSize) {
                perror("send() failed");
                close(clientSocket);
                break;
            }
        }

        close(clientSocket);
    }

    close(serverSocket);
    return 0;
}