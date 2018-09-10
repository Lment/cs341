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

#define MAX_SIZE 10 * 1000 * 1000 // 10MB
#define MAX_DATA 10 * 1000 * 1000 - 8 // 10MB - 8(Header size)
#define CARRY 0x10000
#define CAPTURE 0xFFFF

/* References
   basic usage of socket api functions are referenced from
   https://beej.us/guide/bgnet/html/single/bgnet.html
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

    fd_set master; // Master file descriptor list
    fd_set read_fds; // Temp file descriptor list for select()
    int fdmax; // Maximum file descriptor number
    int yes = 1; // For setsockopt() SO_REUSEADDR, below
    int i, j, rv;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master); // clear the master and temp sets
    FD_ZERO(&read_fds);
    


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

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; //AF_INET?
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, htobe16(port), &hints, &ai)) != 0) {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }
    for (p = ai;p != NULL;p = p->ai_next) {
        svr_sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (svr_sock_fd < 0) {
            continue;
        }
    
        setsockopt(svr_sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(svr_sock_fd, p->ai_addr, p->ai_addrlen) < 0) {
            close(svr_sock_fd);
            continue;
        }
    
        break;
    }


    // If we got here, it means we didn't get bound
    if (p == NULL) {
        fprintf(stderr, "selecttserver: failed to bind\n");
        exit(2);
    }
    
    freeaddrinfo(ai); // all done with this

    if (listen(svr_sock_fd, 100) < 0) {
        perror("Listen failed\n");
        exit(3);
    }
    
    // add the svr_sock_fd to the amster set
    FD_SET(svr_sock_fd, &master);

    // Keep track of the biggest file descriptor
    fdmax = svr_sock_fd; // so far, it's this one

    /* ----------
       ||Part B||
       ----------
    */

    while (1) {
        read_fds = master; // Copy it

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("Select failed\n");
            exit(4);
        }
        
        // Run through the existing connections looking for data to read
        for (i = 0;i <= fdmax;i++) {
            if (FD_ISSET(i, &read_fds)) { // We got one!!
                if (i == svr_sock_fd) {
                    // Handle new connections
                    cli_addr_size = sizeof(cli_addr);
                    newfd = accept(svr_sock_fd,
                        (struct sockaddr *)&cli_addr,
                        &cli_addr_size);
            
                    if (newfd == -1) {
                        perror("Accept failed\n");
                    } else {
                        FD_SET(newfd, &master); // Add to master set
                        if (newfd > fdmax) { // Keep track of the max
                            fdmax = newfd;
                        }
                    }
                } else {
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
