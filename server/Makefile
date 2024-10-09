CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Werror -g
TARGET = aesdsocket
SRCS = aesdsocket.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) -lpthread 

clean:
	rm -f $(TARGET)

default: all
