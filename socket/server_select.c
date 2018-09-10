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
#include <sys/select.h>

#define MAX_SIZE 10 * 1000 * 1000 // 10MB
#define MAX_DATA 10 * 1000 * 1000 - 8 // 10MB - 8(Header size)
#define CARRY 0x10000
#define CAPTURE 0xFFFF
#define FD_SETSIZE 128

/* References
   usage of socket api functions are **mostly** referenced from
   https://beej.us/guide/bgnet/html/single/bgnet.html
   http://ospace.tistory.com/147
   usage of getaddrinfo is referenced from
   https://www.joinc.co.kr/w/man/3/getaddrinfo
   multiple connection lines are referenced from
   http://www.tutorialspoint.com/unix_sockets/socket_server_example.htm
   http://forum.falinux.com/zbxe/index.php?mid=C_LIB&document_srl=438304
   https://github.com/strollkim/cs341_old/socket/server.c
   (My private github repository used in Fall, 2017 for the same class, I will provide the access right if required) 
*/

/* Overall Structure
   Functions: Define addtional functions used in this program
   Variables: Declare variables used in this program
   Part A: Parse a command line, create, bind, listen
   Part B: Accept client, read and write
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
            checksum = checksum +1;
        }
    }
    free(tmp);
    return checksum;
}

// Check if a given character is alphabet
int abc_check(char c) {
    if ('A' <= c && c <= 'Z') {
        return 1;
    }
    if ('a' <= c && c <='z') {
        return 1;
    }
    return 0;
}

// Encrypt function
char enc(char c, int shift) {
    char abc[27] = "abcdefghijklmnopqrstuvwxyz";
    int s = shift;
    int no, new;

    while (s < 0) {
        s = s + 26;
    }

    s = s % 26;

    for (int i = 0;i < 26;i++) {
        if (c == abc[i]) {
            no = i;
        }
    }

    new = no + s;
    new = new % 26;

    return abc[new];
}

// Decrypt function
char dec(char c, int shift) {
    int s = 0 - shift;
    char result = enc(c, s);
    return result;
}

// Main function
int main(int argc, char *argv[]) {

    /* 1. create a new server socket
       2. bind the socket with port number and IP address
       3. listen()
       4. accept client
       5. read/write
    */ 

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
    uint16_t port; // Save port from command line
    int svr_sock_fd; // Socket file descriptor
    int cli_sock_fd; // Socket file descriptor for connection
    struct sockaddr_in svr_addr;
    struct sockaddr_in cli_addr; //
    uint32_t cli_addr_size; // Variable for accept function
    uint8_t *recv_d; // Received data
    uint8_t *final_recv; // Concatatenated received data
    uint8_t *data; // Raw data
    uint8_t *ciphered_data; // Encrypted/Decrypted data
    uint8_t *msg; // Received message
    int recv_bytes = -1; // Bytes sent
    int send_bytes = -1; // Byte received
    int pid; // pid

    // select implementation
    fd_set master;
    fd_set read_fds;
    FD_ZERO(&master); // initialize
    FD_ZERO(&read_fds); // initialize
    int fd_max;
    int new_fd;
    int yes = 1;
    int i, j;
    //struct addrinfo svr_addr, *ai, *p;
    
     /* ----------
       ||Part A||
       ----------
    */
    
    // Pare the command line (./server -p 5000)
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
        }
    }
/*
    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.ai_family = AF_INET;
    svr_addr.ai_socktype = SOCK_STREAM;
    svr_addr.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, htobe16(port), &svr_addr, &ai) != 0) {
        return -1;
    }
    for (p = ai;p != NULL;p = p->ai_next) {
        if ((svr_sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            continue;
        }
        setsockopt(svr_sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (bind(svr_sock_fd, p->ai_addr, p->ai_addrlen) < 0) {
            //perror("Bind failed\n");
            close(svr_sock_fd);
            continue;
        }
        break;
    }


    if (p == NULL) {
        //perror("Nothing to bind\n");
        return -1;
    }
    
    freeaddrinfo(ai); // all done with this

    if (listen(svr_sock_fd, 100) < 0) {
        // perror("Listen failed\n");
        return -1;
    }
*/

    // Create a socket
    if ((svr_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        // perror("Socket failed\n");
        return -1;
    } else {
        memset(&svr_addr, 0, sizeof(svr_addr));
        svr_addr.sin_family = AF_INET;
        svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        svr_addr.sin_port = htobe16(port);

        if (bind(svr_sock_fd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0) {
            // perror("Bind failed\n");
            return -1;
        }

        if (listen(svr_sock_fd, 100) < 0) {
            // perror("Listen failed\n");
            return -1;
        }
    }

    
    // add the svr_sock_fd to the amster set
    FD_SET(svr_sock_fd, &master);

    // Keep track of the biggest file descriptor
    fd_max = svr_sock_fd; // so far, it's this one

    /* ----------
       ||Part B||
       ----------
    */

    while (1) {
        read_fds = master;
        if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) < 0) {
            //perror("Select failed\n");
            return -1;
        }
        
        for (i = 0;i <= fd_max;i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == svr_sock_fd) {
                    cli_addr_size = sizeof(cli_addr);
                    if ((new_fd = accept(svr_sock_fd, (struct sockaddr *)&cli_addr, &cli_addr_size)) < 0) {
                        //perror("Accept failed\n");
                    } else {
                        FD_SET(new_fd, &master); // Add to master set
                        if (new_fd > fd_max) { // Keep track of the max
                            fd_max = new_fd;
                        }
                    }
                } else {
                    // Data handling, identical to server.c
                    while (1) {
                        int total_recv = 0;
                        int total_send = 0;
                        int length;
                        int op;
                        int shift;
                        recv_d = malloc(MAX_SIZE + 1);
                        final_recv = malloc(MAX_SIZE + 1);
                        data = malloc(MAX_DATA + 1);
                        ciphered_data = malloc(MAX_DATA +1);
                        msg = malloc(MAX_SIZE + 1);

                        while (1) {
                            if ((recv_bytes = recv(cli_sock_fd, recv_d, (size_t)MAX_SIZE, 0)) == -1) {
                                // perror("Recv failed\n");
                                free(recv_d);
                                free(final_recv);
                                free(data);
                                free(ciphered_data);
                                free(msg);
                                close(cli_sock_fd);
                                return -1;
                            }

                            if (recv_bytes == 0) {
                                free(recv_d);
                                free(final_recv);
                                free(data);
                                free(ciphered_data);
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
                        shift = (int)*(uint8_t *)(&final_recv[1]);
                        // fprintf(stderr, "op is %d\n", op);
                        // fprintf(stderr, "shift is %d\n", shift);

                        memset(&final_recv[total_recv], 0, 3);
                        int checksum_recv = calc_checksum(final_recv, total_recv);
                        if (checksum_recv - 0xFFFF) {
                            free(recv_d);
                            free(final_recv);
                            free(data);
                            free(ciphered_data);
                            free(msg);
                            close(cli_sock_fd);
                            return -1;
                        }

                        memcpy(&msg[0], &final_recv[0], 1);
                        memcpy(&msg[1], &final_recv[1], 1);
                        memset(&msg[2], 0, 2);
                        memcpy(&msg[4], &final_recv[4], 4);
                        memcpy(data, &final_recv[8], length - 8);

                        if (op) { //dec
                            for (int i = 0;i < length - 8;i++) {
                                if (abc_check(data[i])) {
                                    ciphered_data[i] = dec((char)tolower(data[i]), shift);
                                } else {
                                    ciphered_data[i] = data[i];
                                }
                            }
                        } else { //enc
                            for (int i = 0;i < length - 8;i++) {
                                if (abc_check(data[i])) {
                                    ciphered_data[i] = enc((char)tolower(data[i]), shift);
                                } else {
                                    ciphered_data[i] = data[i];
                                }
                            }
                        }
                
                        memcpy(&msg[8], ciphered_data, length - 8);
                        int checksum_send = calc_checksum (msg, length);
                        checksum_send = (~checksum_send);
                        memcpy(&msg[2], &checksum_send, 2);

                        while (total_send < total_recv) {
                            if ((send_bytes = send(cli_sock_fd, msg, (size_t)total_recv, 0)) == -1) {
                                // perror("Send failed\n");
                                free(recv_d);
                                free(final_recv);
                                free(data);
                                free(ciphered_data);
                                free(msg);
                                close(cli_sock_fd);
                            return -1;
                            }
                            total_send = total_send + send_bytes;
                        }
                    }
                }
            }
        }
    }
}
