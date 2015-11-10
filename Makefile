CC=gcc
CFLAGS=-lpthread -lcurl 

arjfuzz: arjfuzz.c
	$(CC) -o arjfuzz arjfuzz.c $(CFLAGS)

install:
	cp arjfuzz /usr/local/bin

uninstall:
	rm /usr/local/bin/arjfuzz



