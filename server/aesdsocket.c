#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#pragma GCC diagnostic warning "-Wunused-variable"

#define PORT 9000
#define BACKLOG 10
#define USE_AESD_CHAR_DEVICE 1

#ifdef USE_AESD_CHAR_DEVICE
    #define FILE_PATH "/dev/aesdchar"
#else
    #define FILE_PATH "/var/tmp/aesdsocketdata"
#endif

#define BUFFER_LEN 1024
// int sock_fd = -1, run 1;
FILE *file = NULL;
bool exit_loop = false;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
    int new_fd;
    int device_fd;
    struct sockaddr_storage sock_addr;
} ThreadArgs;

// Define the thread_node structure
typedef struct thread_node
{
    pthread_t thread;
    SLIST_ENTRY(thread_node) entry;
} thread_node;

// Set head of list
SLIST_HEAD(ThreadList, thread_node) head = SLIST_HEAD_INITIALIZER(head);

// Signal handler for SIGINT and SIGTERM
void handle_signal(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
    }

/*
        run = 0;

#ifndef USE_AESD_CHAR_DEVICE
        if (remove(FILE_PATH) != 0)
	{
            syslog(LOG_ERR, "Failed to remove file");
        }
#endif

	if (file != NULL)
	{
            fclose(file);
	    file = NULL;
	}

        if (sockfd != -1)
	{
            close(sockfd);
        }

        closelog();
        exit(0);
    }
*/

    exit_loop = true;
}

void initialize_sigaction()
{
    struct sigaction sighandle;
    // Initialize sigaction
    sighandle.sa_handler = handle_signal;
    sigemptyset(&sighandle.sa_mask); // Initialize the signal set to empty
    sighandle.sa_flags = 0;          // No special flags

    // Catch SIGINT
    if (sigaction(SIGINT, &sighandle, NULL) == -1)
    {
        syslog(LOG_ERR, "Error setting up signal handler SIGINT: %s \n", strerror(errno));
    }

    // Catch SIGTERM
    if (sigaction(SIGTERM, &sighandle, NULL) == -1)
    {
        syslog(LOG_ERR, "Error setting up signal handler SIGINT: %s \n", strerror(errno));
    }
}

int receive_store_socket_data(int new_fd, int device_fd)
{
    char *buffer = NULL;
    size_t total_received = 0;
    size_t current_size = BUFFER_LEN;
    size_t mult_factor = 1;
    struct aesd_seekto seekto;

    buffer = (char *) calloc(current_size, sizeof(char));
    if (buffer == NULL)
    {
        syslog(LOG_ERR, "Failed to allocate client buffer");
        return -1;
    }

    while (true)
    {
        ssize_t numbytes = recv(new_fd, buffer + total_received, current_size - total_received - 1, 0);
        if (numbytes <= 0)
        {
            break;
        }

        total_received += numbytes;
        buffer[total_received] = '\0';

        if (strchr(buffer, '\n') != NULL)
        {
            break;
        }

        mult_factor <<= 1;
        size_t rev_size = mult_factor * BUFFER_LEN;
        char *rev_buffer = (char *) realloc(buffer, rev_size);
        if (rev_buffer == NULL)
        {
            syslog(LOG_ERR, "Reallocation of client buffer failed, returning with error");
            free(buffer);
            return -1;
        }

        buffer = rev_buffer;
        current_size = rev_size;
    }

    // Check if the buffer contains an ioctl command
    if (strncmp(buffer, "AESDCHAR_IOCSEEKTO:", 19) == 0)
    {
        // Extract command and offset from the received data
        if (sscanf(buffer + 19, "%u,%u", &seekto.write_cmd, &seekto.write_cmd_offset) == 2)
        {
            syslog(LOG_INFO, "Parsed ioctl command AESDCHAR_IOCSEEKTO with command %u, offset %u", seekto.write_cmd, seekto.write_cmd_offset);

            // Perform the ioctl operation
            if (ioctl(device_fd, AESDCHAR_IOCSEEKTO, &seekto) == -1)
            {
                syslog(LOG_ERR, "ioctl AESDCHAR_IOCSEEKTO failed: %s", strerror(errno));
                free(buffer);
                return -1;
            }
            syslog(LOG_INFO, "Seek operation successful");

            // Since this was an ioctl command, skip writing to the file
            free(buffer);
            return 0;
        }
        else
        {
            syslog(LOG_ERR, "Failed to parse AESDCHAR_IOCSEEKTO command and offset");
        }
    }
    // Now we have the complete data, store it in the file
    syslog(LOG_INFO, "Writing received data to the sockedata file");
    // Lock the mutex before writing to the file
    pthread_mutex_lock(&file_mutex);
    if (write(device_fd, buffer, total_received) != -1)
    {
        syslog(LOG_INFO, "Syncing data to the disk");
        fdatasync(device_fd);
    }
    else
    {
        syslog(LOG_ERR, "Writing received data to the socketdata file failed");
        pthread_mutex_unlock(&file_mutex); //Unlock mutex before returning from function
        free(buffer);
        return -1;
    }
    // UnLock the mutex after writing to the file
    pthread_mutex_unlock(&file_mutex);
    syslog(LOG_INFO, "Unlocked mutex and returning from write");
    free(buffer);
    return 0; // Return success
}

int return_data_to_client(int new_fd, int device_fd)
{
    char *send_buff;
    size_t loaded_bytes;
    lseek(device_fd, 0, SEEK_SET);
    send_buff = (char *) malloc(BUFFER_LEN);
    if (send_buff == NULL)
    {
        syslog(LOG_INFO, "Failure to allocate buffer");
        return -1;
    }

    pthread_mutex_lock(&file_mutex);
    while ((loaded_bytes = read(device_fd, send_buff, sizeof(send_buff) - 1)) > 0)
    {
        send_buff[loaded_bytes] = '\0';

        if (send(new_fd, send_buff, loaded_bytes, 0) == -1)
        {
            break;
        }
    }

    pthread_mutex_unlock(&file_mutex);
    free(send_buff);
    return 0;
}

// Thread function to handle each connection
void *handle_connection(void *arg)
{
    ThreadArgs *threadArg = (ThreadArgs *)arg;
    char client_ip[INET_ADDRSTRLEN];

    if (threadArg->sock_addr.ss_family == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&threadArg->sock_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), client_ip, sizeof(client_ip));
    }
    else if (threadArg->sock_addr.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &threadArg->sock_addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), client_ip, sizeof(client_ip));
    }

    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    if (receive_store_socket_data(threadArg->new_fd, threadArg->device_fd) == 0)
    {
        return_data_to_client(threadArg->new_fd, threadArg->device_fd);
    }

    if (close(threadArg->new_fd) == 0)
    {
        syslog(LOG_INFO, "Closed connection");
    }
    else
    {
	syslog(LOG_ERR, "Failed to close connection");
    }
}

// Function to add a thread to the linked list
void add_thread_to_list(pthread_t thread)
{
    thread_node *new_node = (thread_node *)malloc(sizeof(thread_node));

    if (!new_node)
    {
        syslog(LOG_ERR, "Failed to allocate memory for thread node");
        return;
    }

    new_node->thread = thread;
    pthread_mutex_lock(&thread_list_mutex);
    syslog(LOG_INFO, "Inserting thread node");
    SLIST_INSERT_HEAD(&head, new_node, entry);
    pthread_mutex_unlock(&thread_list_mutex);
}

// Function to join and remove completed threads from the linked list
void join_and_remove_threads()
{
    thread_node *current = SLIST_FIRST(&head);
    thread_node *next;
    pthread_mutex_lock(&thread_list_mutex);

    while (current != NULL)
    {
        next = SLIST_NEXT(current, entry);
        if (pthread_join(current->thread, NULL))
        {
            syslog(LOG_INFO, "Removing the thread node");
            SLIST_REMOVE(&head, current, thread_node, entry);
            free(current);
        }
        else
        {
            syslog(LOG_INFO, "Thread %ld unable to join: %s", current->thread, strerror(errno));
        }

        current = next;
    }

    pthread_mutex_unlock(&thread_list_mutex);
}

#ifndef USE_AESD_CHAR_DEVICE
// Thread function to append timestamp to the file every 10 seconds
void *timestamp_thread(void *arg)
{
    while (run)
    {
        sleep(10);
	pthread_mutex_lock(&file_mutex);
	FILE *local_file = fopen(FILE_PATH, "a+");

	if (local_file)
	{
            time_t now = time(NULL);
	    struct tm *tm_info = localtime(&now);
	    char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tm_info);
            fputs(timestamp, local_file);
            fflush(local_file);
            fclose(local_file);
	}

	pthread_mutex_unlock(&file_mutex);
    }

    return NULL;
}
#endif

int main(int argc, char *argv[])
{
    struct addrinfo inputs, *server_info;
    int sock_fd, new_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_size;
    int device_fd = -1;
    int status;
    int yes = 1;


    // Open a system logger connection for aesdsocket utility
    openlog("aesdsocket", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);
    syslog(LOG_INFO, "Starting aesdsocket server...");

#ifdef USE_AESD_CHAR_DEVICE
    syslog(LOG_INFO, "USE_AESD_CHAR_DEVICE is enabled");
#else
    syslog(LOG_INFO, "USE_AESD_CHAR_DEVICE is not enabled");
#endif

    /*Line  was partly referred from https://beej.us/guide/bgnet/html/#socket */
    memset(&inputs, 0, sizeof(inputs));
    inputs.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    inputs.ai_socktype = SOCK_STREAM; // TCP stream sockets
    inputs.ai_flags = AI_PASSIVE;     // fill in my IP for me

    // Get address info
    if ((status = getaddrinfo(NULL, "9000", &inputs, &server_info)) != 0)
    {
        syslog(LOG_ERR, "Error occurred while getting the address info: %s \n", gai_strerror(status));
        closelog();
        exit(1);
    }

    // Open a stream socket
    sock_fd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
    if (sock_fd == -1)
    {
        syslog(LOG_ERR, "Error occurred while creating a socket: %s\n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    // Set socket options
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    {
        syslog(LOG_ERR, "Error occurred while setting a socket option: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    if (bind(sock_fd, server_info->ai_addr, server_info->ai_addrlen) == -1)
    {
        syslog(LOG_ERR, "Error occurred while binding a socket: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    // Check for the -d argument to run as a daemon
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        pid_t pid = fork();

        if (pid < 0)
	{
            syslog(LOG_ERR, "Fork failed");
            return -1;
        }

        if (pid > 0)
	{
            exit(EXIT_SUCCESS); // Parent process exits
        }

        if (setsid() < 0) 
	{
            syslog(LOG_ERR, "setsid failed");
            return -1;
        }

        pid = fork();

        if (pid < 0) 
	{
            syslog(LOG_ERR, "Fork failed");
            return -1;
        }

        if (pid > 0) 
	{
            exit(EXIT_SUCCESS); // Parent process exits
        }

        if (chdir("/") < 0) 
	{
            syslog(LOG_ERR, "chdir failed");
            return -1;
        }

        // Close all open file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // Redirect standard input, output, and error to /dev/null
        open("/dev/null", O_RDONLY); // stdin
        open("/dev/null", O_WRONLY); // stdout
        open("/dev/null", O_RDWR);   // stderr
    }

    if (listen(sock_fd, 20) == -1)
    {
        syslog(LOG_ERR, "Error occurred during listen operation: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    initialize_sigaction();
    client_size = sizeof(client_addr);

    // Main server loop
    while (!exit_loop)
    {
        new_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &client_size);
        if (new_fd == -1)
        {
            syslog(LOG_ERR, "Error occurred during accept operation: %s \n", strerror(errno));
            continue;
        }

        pthread_t thread;
        ThreadArgs *arg = malloc(sizeof(ThreadArgs));
        if (arg == NULL)
        {
            syslog(LOG_ERR, "Failed to allocate memory for thread arguments");
            close(new_fd);
            continue;
        }

        arg->new_fd = new_fd;
        arg->sock_addr = client_addr;

#ifdef USE_AESD_CHAR_DEVICE
        // Open file descriptor for /dev/aesdchar only when a client connects
        arg->device_fd = open(FILE_PATH, O_RDWR);
        if (arg->device_fd == -1)
        {
            syslog(LOG_ERR, "Failed to open %s", FILE_PATH);
            close(new_fd);
            free(arg);
            continue;
        }
#else
        // Use already opened file descriptor
        arg->device_fd = device_fd;
#endif

        syslog(LOG_INFO, "Creating a new thread");
        int err = pthread_create(&thread, NULL, handle_connection, (void *)arg);
        if (err != 0)
        {
            syslog(LOG_ERR, "Error creating thread: %s", strerror(err));
            close(new_fd);
            free(arg);
            continue;
        }

        add_thread_to_list(thread);
        join_and_remove_threads();
    }

    // Clean up before exiting
    syslog(LOG_ERR, "Waiting for active threads to join");
    join_and_remove_threads();

    close(device_fd);
    // Remove the temporary file if it exists
    unlink(FILE_PATH);

    syslog(LOG_INFO, "Deleted the temporary socket data file before exiting.");
    freeaddrinfo(server_info);
    closelog();
    return 0;
}
