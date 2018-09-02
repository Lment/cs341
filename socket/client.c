#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_SIZE 10 * 1000 * 1000 // set max size to 10MB

/* TO-DO
   1. parse cmd and create a message following protocol
   2. create a socket and connect to a server
   3. send a message to the server
   4. receive the message from the server, check and parse the message
*/

int main(int argc, char *argv[]) {
    /* header structure
       00  04  08  12  16  20  24  28
       --------------------------------
       |  op  |  shift |   checksum   |
       --------------------------------
       |            length            |
       --------------------------------
    */

    /* variables for message */
    uint8_t op;
    uint8_t shift;
    uint32_t length;  
    char *string;

    /* variables for socket api */
    int sock_fd;
    char raw_srvr_addr[10];
    struct sockaddr_in srvr_addr;
    uint16_t port;

    /* others */
    int opt;
    int send_bytes;
    int recv_bytes;

    /* parse the command line
       ex. ./client -h 143.248.111.222 -p 1234 -o 0 -s 5
    */
    while ((opt = getopt(argc, argv, "h:p:o:s:")) != -1) {
        switch (opt) {
            case 'h':
                memcpy(raw_srvr_addr, optarg, strlen(optarg));
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'o':
                op = atoi(optarg);
                break;
            case 's':
                shift = atoi(optarg);
        }
    }

    /* create a socket and connect to a server */
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Fail to create socket\n");
        return -1;
    } else {
        /* set server address */
        memset(&srvr_addr, 0, sizeof(srvr_addr));
        srvr_addr.sin_family = AF_INET;
        srvr_addr.sin_addr.s_addr = inet_addr(raw_srvr_addr);
        srvr_addr.sin_port = htobe16(port);

        if (connect(sock_fd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr)) < 0) {
            perror("Fail to connect to server\n");
            return -1;
        }
    }

    /* message following protocol */
    
    /* TO-DO
       1. stdin message
       2. add op, shift, checksum, and length to the data
       3. send to server
       4. receive the response
    */

    while (1) {
        
    }
