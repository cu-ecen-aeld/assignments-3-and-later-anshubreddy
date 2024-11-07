CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -g
TARGET ?= aesdsocket
LDFLAGS ?= -lpthread -lrt

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS) 

clean:
	rm -f  *.o *.elf $(TARGET)

default: all
