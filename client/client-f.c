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
    struct sockaddr_in serverAddress;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
    char *command;

    command = argv[1];
    strncpy(commandBuffer, command, COMMANDBUFFERSIZE - 1);
    
    if ((clientSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddress.sin_port = htons(8080);

    if (connect(clientSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        close(clientSocket);
        handle_error("connect() failed");
    }

    if (send(clientSocket, commandBuffer, strlen(commandBuffer), 0) < 0) {
        close(clientSocket);
        handle_error("send() failed");
    }

    int receiveSize;
    if ((receiveSize = recv(clientSocket, commandBuffer, COMMANDBUFFERSIZE-1, 0)) <= 0) {
        close(clientSocket);
        handle_error("recv() failed");
    }

    close(clientSocket);
    return 0;
}