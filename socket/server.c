#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_SIZE 10 * 1000 * 1000

/* basic usage of socket api functions are referenced from  https://beej.us/guide/bgnet/html/single/bgnet.html*/
/* multiple connection lines are referenced from http://www.tutorialspoint.com/unix_sockets/socket_server_example.htm */

int calc_checksum (uint8_t *msg, uint32_t length) {
    uint16_t *tmp = malloc(2);
    int checksum = 0;
    memset(&msg[length], 0, 1);
    for (int i = 0;i < length;i = i + 2) {
        int carry = 0;
        memcpy(tmp, msg + i, 2);
        checksum = checksum + (int)*tmp;
        carry = checksum & 0x10000;
        checksum = checksum & 0xFFFF;
        if (carry) {
            checksum = checksum +1;
        }
    }
    free(tmp);
    return checksum;
}

/* 1. create a new server socket
   2. bind the socket with port number and IP address
   3. listen()
   4. accept client
   5. read/write
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

    int opt;
    uint16_t port;
    int svr_sock_fd;
    int cli_sock_fd;
    struct sockaddr_in svr_addr;
    struct sockaddr_in cli_addr;
    uint32_t cli_addr_size;

    uint8_t *recv_d;
    uint8_t *final_recv;
    uint8_t *data;
    uint8_t *ciphered_data;
    uint8_t *msg;
    int recv_bytes = -1;
    int send_bytes = -1;

    int pid;
    
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            }
    }

    if ((svr_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    svr_addr.sin_port = htobe16(port);

    if (bind(svr_sock_fd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0) {
        return -1;
    }

    if (listen(svr_sock_fd, 100) < 0) {
        return -1;
    }

    cli_addr_size = sizeof(cli_addr);

    /* reference : http://forum.falinux.com/zbxe/index.php?mid=C_LIB&document_srl=438304 */
    while (1) {
        if ((cli_sock_fd = accept(svr_sock_fd, (struct sockaddr *)&cli_addr, &cli_addr_size)) < 0) {
            return -1;
        }

        if ((pid = fork()) < 0) {
            return -1;
        }

        if (pid == 0) {
            close(svr_sock_fd);

            while (1) {
                int total_recv = 0;
                int total_send = 0;
                int length;
                int op;
                int shift;
                recv_d = malloc(MAX_SIZE + 1);
                final_recv = malloc(MAX_SIZE + 1);
                data = malloc(MAX_SIZE - 7);
                ciphered_data = malloc(MAX_SIZE - 8);
                msg = malloc(MAX_SIZE + 1);

                while (1) {
                    if ((recv_bytes = recv(cli_sock_fd, recv_d, (size_t)MAX_SIZE, 0)) == -1) {
                        free(recv_d);
                        free(final_recv);
                        free(data);
                        // free(ciphered_data);
                        free(msg);
                        close(cli_sock_fd);
                        return -1;
                    }
                    if (recv_bytes == 0) {
                        free(recv_d);
                        free(final_recv);
                        free(data);
                        // free(ciphered_data);
                        free(msg);
                        close(cli_sock_fd);
                        return 0;
                    }
                    memcpy(&final_recv[total_recv], recv_d, recv_bytes);
                    total_recv = total_recv + recv_bytes;
                    
                    if (total_recv >= 8) {
                        if ((length = be32toh(*(uint32_t *)(&final_recv[4]))) == total_recv) {
                            break;
                        }
                    }
                }
 
                op = ntohs(*(uint8_t *)(&final_recv[0]));
                shift = (int)*(uint8_t *)(&final_recv[2]);
                fprintf(stderr, "op is %d\n", op);
                fprintf(stderr, "shift is %d\n", shift);
            }
        }
    }

}
