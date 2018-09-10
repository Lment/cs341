CC = gcc

CFLAGS = -Wall

all: server client server_select

client : client.c
	$(CC) $(CFLAGS)  -o client client.c

server : server.c
	$(CC) $(CFLAGS) -o server server.c

server_select : server_select.c
	$(CC) $(CFLAGS) -o server_select server.c

test-client : test-client-normal test-client-laggy

test-client-normal : client
	./client -h 143.248.56.16 -p 5000 -o 0 -s 5 < test-cases-updated/test-vector/1KB.txt > result.txt
	diff result.txt test-cases-updated/test-results_enc/1KB_enc.txt
	./client -h 143.248.56.16 -p 5000 -o 0 -s 5 < test-cases-updated/test-vector/1MB.txt > result.txt
	diff result.txt test-cases-updated/test-results_enc/1MB_enc.txt
	./client -h 143.248.56.16 -p 5000 -o 0 -s 5 < test-cases-updated/test-vector/20MB.txt > result.txt
	diff result.txt test-cases-updated/test-results_enc/20MB_enc.txt
	./client -h 143.248.56.16 -p 5000 -o 1 -s 5 < test-cases-updated/test-vector/1KB.txt > result.txt
	diff result.txt test-cases-updated/test-results_dec/1KB_dec.txt
	./client -h 143.248.56.16 -p 5000 -o 1 -s 5 < test-cases-updated/test-vector/1MB.txt > result.txt
	diff result.txt test-cases-updated/test-results_dec/1MB_dec.txt
	./client -h 143.248.56.16 -p 5000 -o 1 -s 5 < test-cases-updated/test-vector/20MB.txt > result.txt
	diff result.txt test-cases-updated/test-results_dec/20MB_dec.txt

test-client-laggy : client
	 ./client -h 143.248.56.16 -p 5003 -o 0 -s 5 < test-cases-updated/test-vector/1KB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_enc/1KB_enc.txt
	 ./client -h 143.248.56.16 -p 5003 -o 0 -s 5 < test-cases-updated/test-vector/1MB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_enc/1MB_enc.txt
	 ./client -h 143.248.56.16 -p 5003 -o 0 -s 5 < test-cases-updated/test-vector/20MB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_enc/20MB_enc.txt
	 ./client -h 143.248.56.16 -p 5003 -o 1 -s 5 < test-cases-updated/test-vector/1KB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_dec/1KB_dec.txt
	 ./client -h 143.248.56.16 -p 5003 -o 1 -s 5 < test-cases-updated/test-vector/1MB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_dec/1MB_dec.txt
	 ./client -h 143.248.56.16 -p 5003 -o 1 -s 5 < test-cases-updated/test-vector/20MB.txt > result.txt
	 diff result.txt test-cases-updated/test-results_dec/20MB_dec.txt

clean: client server server_select
	rm client server server_select
