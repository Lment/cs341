#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_SIZE 10 * 1000 * 1000 // 10MB
#define MAX_DATA 10 * 1000 * 1000 - 8 // 10MB - 8(Header size)
#define CARRY 0x10000
#define CAPTURE 0xFFFF

/* References
   https://beej.us/guide/bgnet/html/single/bgnet.html
   https://github.com/strollkim/cs341_old/socket/client.c
   (My private github repository used in Fall, 2017 for the same class, I will provide the access right if required) 
*/

/* Overall Structure
   Functions: Define addtional functions used in this program
   Variables: Declare variables used in this program
   Part A: Parse a command line and create a message following the given protocal
   Part B: Create a socket and connect to a server
   Part C: Send and receive a message to/from server
*/


/* -------------
   ||Functions||
   ------------- */


// Calculate checksum right before '~' operation required at the end
int calc_checksum (uint8_t *msg, uint32_t len) {
    uint16_t *tmp = malloc(2);
    int checksum = 0;
    memset(&msg[len], 0, 1);
    for (int i = 0;i < len;i = i + 2) {
        int carry = 0;
        memcpy(tmp, msg + i, 2);
        checksum = checksum + (int)*tmp;
        carry = checksum & CARRY;
        checksum = checksum & CAPTURE;
        if (carry) {
            checksum = checksum + 1;
        }
    }
    free(tmp);
    return checksum;
}

// Main function
int main(int argc, char *argv[]) {

    /* header structure
       00  04  08  12  16  20  24  28
       --------------------------------
       |  op  |  shift |   checksum   |
       --------------------------------
       |            length            |
       --------------------------------
    */

    /* -------------
       ||Variables||
       -------------
    */
    int opt; // Command line option
    uint8_t op; // Save op from command line
    uint8_t shift; // Save shift from command line
    uint32_t length; // Save length of the message
    uint32_t ordered_length; // Networ-ordered length
    char *raw_srvr_addr; // Save server address from command line
    uint16_t port; // Save port from command line
    struct sockaddr_in srvr_addr; // Create struct for server address
    int sock_fd; // Socket file descriptor
    char *data; // Object data following after header
    uint8_t *msg; // Sent message
    uint8_t *res; // Received message
    int send_bytes; // Bytes sent
    int recv_bytes; // Byte received

    /* ----------
       ||Part A||
       ----------
    */

    // Parse the command line (./client -h 143.248.111.222 -p 1234 -o 0 -s 5)
    while ((opt = getopt(argc, argv, "h:p:o:s:")) != -1) {
        switch (opt) {
            case 'h':
                raw_srvr_addr = malloc(strlen(optarg));
                memcpy(raw_srvr_addr, optarg, strlen(optarg));
                break;
            case 'p':
                port = (uint16_t)atoi(optarg);
                break;
            case 'o':
                op = (uint8_t)atoi(optarg);
                break;
            case 's':
                shift = (uint8_t)atoi(optarg);
                break;
        }
    }

    // Create a socket and connect to a server
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        // perror("Socket failed\n");
        return -1;
    } else {
        // Set server address
        memset(&srvr_addr, 0, sizeof(srvr_addr));
        srvr_addr.sin_family = AF_INET;
        srvr_addr.sin_addr.s_addr = inet_addr(raw_srvr_addr);
        // fprintf(stderr, "%s\n", raw_srvr_addr);
        free(raw_srvr_addr);
        srvr_addr.sin_port = htobe16(port);

        if (connect(sock_fd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr)) < 0) {
            // perror("Connect failed\n");
            return -1;
        }
    }

    /* ----------
       ||Part B||
       ----------
    */

    /* TO-DO
       1. stdin message
       2. add op, shift, checksum, and length to the data
       3. send to server
       4. receive the response
     */

    while (1) {
        int total_send = 0;
        int total_recv = 0;
        int data_len = 0;
        int eof_flag = 0;
        data = malloc(MAX_DATA);
        msg = malloc(MAX_SIZE);
        res = malloc(MAX_SIZE);

        while (data_len < MAX_DATA) {
            int cur_char = getchar();
            if (cur_char == EOF) {
                if (feof(stdin)) {
                    if (data_len == 0) {
                        // fprintf(stderr, "%s\n", "No data");
                        free(msg);
                        free(res);
                        free(data);
                        close(sock_fd);
                        return 0;
                    } else {
                        // fprintf(stderr, "%s\n", "Normal EOF");
                        eof_flag = 1;
                        break;
                    }
                }

                if (ferror(stdin)) {
                    // perror("Stdin failed\n");
                    free(msg);
                    free(res);
                    free(data);
                    close(sock_fd);
                    return -1;
                }
            }
            data[data_len] = (char)cur_char;
            data_len++;
        }

        /* header structure
           00  04  08  12  16  20  24  28
           --------------------------------
           |  op  |  shift |   checksum   |
           --------------------------------
           |        ordered_length        |
           --------------------------------
         */

        memcpy(&msg[0], &op, 1);
        memcpy(&msg[1], &shift, 1);
        memset(&msg[2], 0, 2);

        length = data_len + 8;
        ordered_length = htobe32(length);
        memcpy(&msg[4], &ordered_length, 4);
        memcpy(&msg[8], data, data_len);

        int checksum = calc_checksum (msg, length);
        checksum = (~checksum);
        memcpy(&msg[2], &checksum, 2);
 
        /* ----------
           ||Part C||
           ----------
        */

        while (total_send < length) {
            if ((send_bytes = send(sock_fd, msg, (size_t)length, 0)) < 0) {
                // perror("Send failed\n");
                free(msg);
                free(res);
                free(data);
                close(sock_fd);
                return -1;
            }

            total_send = total_send + send_bytes;
            // fprintf(stderr,"total: %d/%d, send: %d, left: %d\n", total_send, length, send_bytes, length - total_send);
        }
 
        uint8_t *total_res = malloc(MAX_SIZE);
 
        while (total_recv < total_send) {
            // fprintf(stderr, "%d\n", total_recv);
            if ((recv_bytes = recv(sock_fd, res, (size_t)length, 0)) < 0) {
                // perror("Recv failed\n");
                free(msg);
                free(res);
                free(total_res);
                free(data);
                close(sock_fd);
                return -1;
            }
 
            memcpy(&total_res[total_recv], res, recv_bytes);
            total_recv = total_recv + recv_bytes;
            // fprintf(stderr,"total: %d/%d, recv: %d, left: %d\n", total_recv, length, recv_bytes, total_send - total_recv);
        }
 
        memset(&total_res[total_recv], 0, 3);
        int recv_checksum = calc_checksum (total_res, total_recv);

        if (recv_checksum - 0xFFFF) {
            free(msg);
            free(res);
            free(total_res);
            free(data);
            close(sock_fd);
            return -1;
        }

        for (int i = 0;i < total_recv - 8;i++) {
            printf("%c", total_res[8 + i]);
        }

        free(msg);
        free(res);
        free(total_res);
        free(data);

        if (eof_flag) {
            break;
        }
    }

    close(sock_fd);
    return 0;   
}
