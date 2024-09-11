# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror

# Check if CROSS_COMPILE is set, if so, use it
ifdef
   CC = $(CROSS_COMPILE)gcc
endif

# Default target
all: writer

# Build the writer application
writer: writer.o
	$(CC) $(CFLAGS) -o writer writer.o

# Compile the writer.o object file
writer.o: writer.c
	$(CC) $(CFLAGS) -c writer.c

# Clean target to remove the writer application and all .o files
clean:
	rm -f writer writer.o

.PHONY: all clean
