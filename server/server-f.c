#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define COMMANDBUFFERSIZE 6

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

int main(int argc, char *argv[]) {
    int serverSocket;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    unsigned short serverPort = 9090;
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
        clientLength = sizeof(clientAddress);
        if ((clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, &clientLength)) < 0) {
            perror("accept() failed");
            continue;
        }

        int receiveSize;
        if ((receiveSize = recv(clientSocket, commandBuffer, COMMANDBUFFERSIZE - 1, 0)) <= 0) {
            perror("recv() failed");
            close(clientSocket);
            continue;
        }

        commandBuffer[receiveSize] = '\0';

        if (send(clientSocket, commandBuffer, receiveSize, 0) != receiveSize) {
            perror("send() failed");
            close(clientSocket);
            continue;
        }

        close(clientSocket);
    }
}