CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -g -Wunused -Wunused-variable -Wextra 
TARGET ?= aesdsocket
LDFLAGS ?= -lpthread -lrt

SRC = aesdsocket.c
OBJS = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS)
#$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@
	
clean:
	rm -f  $(OBJS) $(TARGET)
