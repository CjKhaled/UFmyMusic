#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define COMMANDBUFFERSIZE 8

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

char* listService() {
    return "This is the LIST service.";
}

char* diffService() {
    return "This is the DIFF service.";
}

char* pullService() {
    return "This is the PULL service.";
}

char* leaveService() {
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
        return "Service not available.";
    }
}

int main(int argc, char *argv[]) {
    int serverSocket;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
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
            char* output = find_correct_service(commandBuffer);

            // send output
            int outputLength = strlen(output);
            if (send(clientSocket, output, outputLength, 0) != outputLength) {
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