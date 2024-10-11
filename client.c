/*///////////////////////////////////////////////////////////
*
* FILE:		client.c
* AUTHOR:	Macguire McDuff
* PROJECT:	CNT 4007 Project 1 - Professor Traynor
* DESCRIPTION:	Network Client Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */

#include <stdio.h>		    /* for printf() and fprintf() */
#include <sys/socket.h>		    /* for socket(), connect(), send(), and recv() */
#include <arpa/inet.h>		    /* for sockaddr_in and inet_addr() */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>	    /* for OpenSSL EVP digest libraries/SHA256 */

/* Constants */
#define RCVBUFSIZE 512		    /* The receive buffer size */
#define SNDBUFSIZE 512		    /* The send buffer size */
#define MDLEN 32

/* The main function */
int main(int argc, char *argv[])
{

    int clientSock;		    /* socket descriptor */
    struct sockaddr_in serv_addr;   /* The server address */

    char *studentName;		    /* Your Name */

    char sndBuf[SNDBUFSIZE];	    /* Send Buffer */
    char rcvBuf[RCVBUFSIZE];	    /* Receive Buffer */
    int bytesReceived;
    
    int i;			    /* Counter Value */

    /* Get the Student Name from the command line */
    if (argc != 2) 
    {
	printf("Incorrect input format. The correct format is:\n\tnameChanger your_name\n");
	exit(1);
    }
    studentName = argv[1];
    memset(&sndBuf, 0, RCVBUFSIZE);
    memset(&rcvBuf, 0, RCVBUFSIZE);

     /* Create a new TCP socket */
    if ((clientSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket() failed");
        exit(1);
    }

    /* Construct the server address structure */
    memset(&serv_addr, 0, sizeof(serv_addr));           /* Zero out the structure */
    serv_addr.sin_family = AF_INET;                     /* Internet address family */
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); /* Server IP address */
    serv_addr.sin_port = htons(8080);                  /* Server port */

    /* Establish connection to the server */
    if (connect(clientSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect() failed");
        close(clientSock);
        exit(1);
    }

    /* Send the string (student's name) to the server */
    strncpy(sndBuf, studentName, SNDBUFSIZE - 1);  // Copy the student name to the send buffer
    if (send(clientSock, sndBuf, strlen(sndBuf), 0) < 0) {
        perror("send() failed");
        close(clientSock);
        exit(1);
    }

    /* Receive the transformed name (SHA-256 hash) from the server */
    if ((bytesReceived = recv(clientSock, rcvBuf, MDLEN, 0)) <= 0) {
        perror("recv() failed or connection closed prematurely");
        close(clientSock);
        exit(1);
    }

    /* Print the received SHA-256 hash */
    printf("%s\n", studentName);
    printf("Transformed input is: ");
    for (i = 0; i < MDLEN; i++) {
        printf("%02x", (unsigned char)rcvBuf[i]);
    }
    printf("\n");

    /* Close the client socket */
    close(clientSock);

    return 0;
}

