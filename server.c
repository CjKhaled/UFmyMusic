/*///////////////////////////////////////////////////////////
*
* FILE:		server.c
* AUTHOR:	Macguire McDuff
* PROJECT:	CNT 4007 Project 1 - Professor Traynor
* DESCRIPTION:	Network Server Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */
#include <stdio.h>	  /* for printf() and fprintf() */
#include <sys/socket.h>	  /* for socket(), connect(), send(), and recv() */
#include <arpa/inet.h>	  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>	  /* supports all sorts of functionality */
#include <unistd.h>	  /* for close() */
#include <string.h>	  /* support any string ops */
#include <openssl/evp.h>  /* for OpenSSL EVP digest libraries/SHA256 */

#define RCVBUFSIZE 512       /* The receive buffer size */
#define SNDBUFSIZE 512       /* The send buffer size */
#define BUFSIZE 40           /* Your name can be as many as 40 chars */
#define MAXPENDING 5         /* Maximum number of pending connections */

/* The main function */
int main(int argc, char *argv[]) {

    int serverSock;                            /* Server Socket */
    int clientSock;                            /* Client Socket */
    struct sockaddr_in changeServAddr;         /* Local address */
    struct sockaddr_in changeClntAddr;         /* Client address */
    unsigned short changeServPort = 9090;      /* Server port */
    unsigned int clntLen;                      /* Length of address data struct */

    char nameBuf[BUFSIZE];                     /* Buffer to store name from client */
    unsigned char md_value[EVP_MAX_MD_SIZE];   /* Buffer to store change result */
    EVP_MD_CTX *mdctx;                         /* Digest data structure declaration */
    const EVP_MD *md;                          /* Digest data structure declaration */
    int md_len;                                /* Digest data structure size tracking */

    /* Create new TCP Socket for incoming requests */
    if ((serverSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("socket() failed\n");
        exit(1);  // Exit the program with failure
    }

    /* Construct local address structure */
    memset(&changeServAddr, 0, sizeof(changeServAddr));    /* Zero out structure */
    changeServAddr.sin_family = AF_INET;                   /* Internet address family */
    changeServAddr.sin_addr.s_addr = inet_addr("127.0.0.1");/* Set IP address */
    changeServAddr.sin_port = htons(changeServPort);       /* Set port */

    /* Bind to local address structure */
    if (bind(serverSock, (struct sockaddr *) &changeServAddr, sizeof(changeServAddr)) < 0) {
        printf("bind() failed\n");
        close(serverSock);  // Close the socket before exiting
        exit(1);
    }

    /* Listen for incoming connections */
    if (listen(serverSock, MAXPENDING) < 0) {
        printf("listen() failed\n");
        close(serverSock);
        exit(1);
    }

    /* Loop server forever */
    while (1) {
        clntLen = sizeof(changeClntAddr);  // Set the size of the client address structure

        /* Accept incoming connection */
        if ((clientSock = accept(serverSock, (struct sockaddr *) &changeClntAddr, &clntLen)) < 0) {
            printf("accept() failed\n");
            continue;  // Skip and continue listening for the next connection
        }

        printf("Handling client %s\n", inet_ntoa(changeClntAddr.sin_addr));

        /* Extract client's name from the packet */
        int recvSize;
        if ((recvSize = recv(clientSock, nameBuf, BUFSIZE - 1, 0)) <= 0) {
            printf("recv() failed or connection closed prematurely\n");
            close(clientSock);  // Close the socket and go back to accepting new clients
            continue;           // Skip to the next iteration to handle a new client
        }

        /* Null-terminate the received name to make it a valid C string */
        nameBuf[recvSize] = '\0';

        /* Handle client connection after receiving the name */
        printf("Received client name: %s\n", nameBuf);

        /* Run this and return the final value in md_value to the client */
        /* Takes the client name and changes it */
        /* Students should NOT touch this code */
        OpenSSL_add_all_digests();
        md = EVP_get_digestbyname("SHA256");
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, nameBuf, strlen(nameBuf));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);

        /* Return md_value to the client */
        /* Send the hash back to the client */
        if (send(clientSock, md_value, md_len, 0) != md_len) {
            printf("send() failed\n");
        } else {
            printf("SHA-256 hash sent to client\n");
        }

        /* Close the client socket after handling the connection */
        close(clientSock);
    }
}
