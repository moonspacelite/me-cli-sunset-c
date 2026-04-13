CC ?= gcc
CFLAGS = -Wall -I./include
LDFLAGS = -lssl -lcrypto -lcurl -lm

SRC = $(wildcard src/*.c src/*/*.c)
OBJ = $(SRC:.c=.o)
TARGET = me_cli

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o src/*/*.o $(TARGET)
