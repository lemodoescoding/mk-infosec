CC = gcc

CFLAGS = -Wall -Wextra -std=c11 -g

COMMON_OBJ = des_functions.o constant.o util.o protocol.o keygen.o

SERVER = server
CLIENT = client

.PHONY: all clean

all: $(SERVER) $(CLIENT)

$(SERVER): server.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT): client.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(SERVER) $(CLIENT)
