CC=musl-gcc 
CFLAGS= -I . -Wall -ggdb -g 
CFLAGS= -I. -Ictty -Iptrace_do -Wall -Os -s -static

BIN=mara
all:
	make -C ptrace_do
	make -C ctty
	$(CC) $(CFLAGS) main.c  log.c shelljack.c -o $(BIN) ptrace_do/libptrace_do.a ctty/libctty.a
clean:
	make -C ptrace_do clean
	make -C ctty clean
	rm $(BIN)
