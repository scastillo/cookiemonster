SRC_PATH = ./src
BIN_PATH = ./bin
INSTALL_PATH = /usr/sbin

SRC_NAME= fluidsnarfs.c
EXEC_NAME = fluidsnarfs

CC = gcc
CFLAGS = -Wall -Werror

LIBS = -lpcap

fluidsnarfs: $(SRC_PATH)/$(SRC_NAME)
		$(CC) $(CFLAGS) $(LIBS) -o $(BIN_PATH)/$(EXEC_NAME) $(SRC_PATH)/$(SRC_NAME)

clean:
	rm $(BIN_PATH)/*

install: 
	install $(BIN_PATH)/$(EXEC_NAME) $(INSTALL_PATH)

uninstall:
	rm $(INSTALL_PATH)/$(EXEC_NAME)

check-syntax:
	$(CC) $(CFLAGS) -o /tmp/fluidsnarf_sytax_check_output -S ${CHK_SOURCES}
