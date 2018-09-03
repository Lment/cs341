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

uint16_t calc_checksum (uint8_t *msg, uint32_t length, char *data) {
    uint16_t *tmp = malloc(2);
    int checksum = 0;
    memset(&msg[length], 0, 1);
    for (int i = 0;i < length;i = i + 2) {
        int carry = 0;
        memcpy(tmp, data + i, 2);
        checksum = checksum + (int)*tmp;
        carry = checksum & 0x10000;
        checksum = checksum & 0xFFFF;
        if (carry) {
            checksum = checksum +1;
        }
    }
    free(tmp);
    checksum = (uint16_t)(~checksum);
    return checksum;
}

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
    uint32_t ordered_length;
    char *data;
    uint8_t *msg;
    uint8_t *res;
    int send_bytes;
    int recv_bytes;
    
    /* variables for socket api */
    int sock_fd;
    char raw_srvr_addr[10];
    struct sockaddr_in srvr_addr;
    uint16_t port;

    /* others */
    int opt;

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
        data = malloc(MAX_SIZE - 8);
        msg = malloc(MAX_SIZE);
        res = malloc(MAX_SIZE);
        
        while (data_len < MAX_SIZE - 16) {
            int cur_char = getchar();
            if (first_char == EOF) {
                if (feof(stdin)) {
                    if (data_len = 0) {
                        fprintf(stderr, "%s\n", "Reach EOF with zero data");
                        free(msg);
                        free(res);
                        free(data);
                        close(sock_fd);
                        return 0;
                    } else {
                        fprintf(stderr, "%s\n", "eof with some body");
                        eof = 1;
                        break;
                    }
                }

                if (ferror(stdin)) {
                    perror("Fail to get body from stdin\n");
                    free(msg);
                    free(res);
                    free(data);
                    close(sock);
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
        memset(&msg[2], 0, 2); // checksum place

        length = 8 + data_len;
        ordered_length = htobe32(length);
        memcpy(&msg[4], &length, 4);
        
        memcpy(&msg[8], data, data_len);
        
        /* checksum */
        int checksum = calc_checksum (uint8_t *msg, uint32_t length, char *data);
        memcpy(&message[2], &checksum, 2);
    
        while (total_send < length) {
            if ((send_bytes = send(sock_fd, msg, (size_t)length, 0)) < 0) {
                perror("Fail to send message\b");
                free(msg);
                free(res);
                free(data);
                close(sock_fd);
                return -1;
            }
            total_send = total_send + send_bytes;
            fprintf(stderr,"total: %d/%d, send: %d, left: %d\n", total_send, raw_length, send_bytes, raw_length - total_send);
        }

        uint8_t *total_res = malloc(MAX_SIZE);

        while (total_recv < total_send) {
            if ((recv_bytes = recv(sock_fd, res, (size_t)length, 0)) < 0) {
                perror("Fail to receive message\n");
                free(msg);
                free(res);
                free(data);
                close(sock_fd);
                return -1;
            }
            memcpy(&total_res[total_recv], res, recv_bytes);
            total_recv = total_recv + recv_bytes;
        }

        
