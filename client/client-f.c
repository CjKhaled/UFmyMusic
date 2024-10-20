#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define COMMANDBUFFERSIZE 8
#define RECEIVEBUFFERSIZE 512

void handle_error(const char *message) {
    perror(message);
    exit(1);
}

char *allowedCommands[] = {
    "LIST",
    "DIFF",
    "PULL",
    "LEAVE"
};

int is_valid_command(const char *command) {
    for (int i = 0; i < sizeof(allowedCommands) / sizeof(allowedCommands[0]); i++) {
        if (strcmp(command, allowedCommands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void flush_input() {
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in serverAddress;
    int clientSocket;
    char commandBuffer[COMMANDBUFFERSIZE];
    char receiveBuffer[RECEIVEBUFFERSIZE];
    
    // create socket
    if ((clientSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        handle_error("socket() failed");
    }

    // set address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddress.sin_port = htons(8888);

    // connect to server
    if (connect(clientSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        close(clientSocket);
        handle_error("connect() failed");
    }

    // print welcome message
    printf("Welcome To Our UFmyMusic App!\n");
    printf("These are the messages you can send to the server:\n");
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
            // send input to server
            if (send(clientSocket, commandBuffer, strlen(commandBuffer), 0) < 0) {
                close(clientSocket);
                handle_error("send() failed");
            }

            // receive and print response from server
            int receiveSize;
            if ((receiveSize = recv(clientSocket, receiveBuffer, RECEIVEBUFFERSIZE - 1, 0)) <= 0) {
                close(clientSocket);
                handle_error("recv() failed");
            }

            receiveBuffer[receiveSize] = '\0';
            printf("%s\n", receiveBuffer);
        }        
    }    

    close(clientSocket);
    return 0;
}