#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT 9000
#define BACKLOG 10
#define USE_AESD_CHAR_DEVICE 1

#ifdef USE_AESD_CHAR_DEVICE
    #define FILE_PATH "/dev/aesdchar"
#else
    #define FILE_PATH "/var/tmp/aesdsocketdata"
#endif

int sockfd = -1, run = 1;
FILE *file;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

// Define the thread_node_t structure
typedef struct thread_node
{
    pthread_t thread;
    struct thread_node *next;
} thread_node_t;

thread_node_t *thread_list = NULL;

// Signal handler for SIGINT and SIGTERM
void handle_signal(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
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
}

// Thread function to handle each connection
void *handle_connection(void *arg)
{
    int new_fd = *(int *)arg;
    free(arg);
    char buffer[1024];
    int numbytes;

    syslog(LOG_INFO, "Accepted connection");

    // Lock the mutex before accessing the file
    pthread_mutex_lock(&file_mutex);
    FILE *local_file = fopen(FILE_PATH, "a+");

    if (!local_file)
    {
        syslog(LOG_ERR, "File opening failed");
        close(new_fd);
        pthread_mutex_unlock(&file_mutex);
        return NULL;
    }

    int fd = fileno(local_file);

    // Receive data from the client and write to the file
    while ((numbytes = recv(new_fd, buffer, sizeof(buffer) - 1, 0)) > 0) 
    {
        buffer[numbytes] = '\0';
        if (strncmp(buffer, "AESDCHAR_IOCSEEKTO:", 19) == 0)
        {
            unsigned int write_cmd, write_cmd_offset;
            if (sscanf(buffer + 19, "%u,%u", &write_cmd, &write_cmd_offset) == 2)
            {
                struct aesd_seekto seekto;
                seekto.write_cmd = write_cmd;
                seekto.write_cmd_offset = write_cmd_offset;

                if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) == -1)
                {
                    syslog(LOG_ERR, "ioctl failed");
                }

                fseek(local_file, 0, SEEK_SET);
                while ((numbytes = fread(buffer, 1, sizeof(buffer) - 1, local_file)) > 0)
                {
                    buffer[numbytes] = '\0';
                    send(new_fd, buffer, numbytes, 0);
                }

                fclose(local_file);
                local_file = fopen(FILE_PATH, "a+");
                fd = fileno(local_file);
            }
        }
        else
        {
            fputs(buffer, local_file);
            fflush(local_file);

            if (strchr(buffer, '\n')) 
	    {
                // Send the full content of the file back to the client
                fseek(local_file, 0, SEEK_SET);

                while ((numbytes = fread(buffer, 1, sizeof(buffer) - 1, local_file)) > 0) 
	        {
                    buffer[numbytes] = '\0';
                    send(new_fd, buffer, numbytes, 0);
                }
            }
        }
    }

    // Close the file and unlock the mutex
    fclose(local_file);
    pthread_mutex_unlock(&file_mutex);
    close(new_fd);
    syslog(LOG_INFO, "Closed connection");
    return NULL;
}

// Function to add a thread to the linked list
void add_thread_to_list(pthread_t thread) 
{
    // pthread_mutex_lock(&thread_list_mutex)
    thread_node_t *new_node = (thread_node_t *)malloc(sizeof(thread_node_t));
    new_node->thread = thread;
    new_node->next = thread_list;
    thread_list = new_node;
    // pthread_mutex_unlock(&thread_list_mutex)
}

// Function to join and remove completed threads from the linked list
void join_and_remove_threads() 
{
    // pthread_mutex_lock(&thread_list_mutex);
    thread_node_t *current = thread_list;
    thread_node_t *prev = NULL;

    while (current != NULL) 
    {
        pthread_join(current->thread, NULL);

        if (prev == NULL) 
	{
            thread_list = current->next;
        } 
	else 
	{
            prev->next = current->next;
        }

        thread_node_t *temp = current;
        current = current->next;
        free(temp);
    }

    // pthread_mutex_unlock(&thread_list_mutex);
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
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size;
    pthread_t thread, ts_thread;
    int *new_fd;

    // Open log for syslogging
    openlog("aesdsocket", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Starting aesdsocket server...");

#ifdef USE_AESD_CHAR_DEVICE
    syslog(LOG_INFO, "USE_AESD_CHAR_DEVICE is enabled");
#else
    syslog(LOG_INFO, "USE_AESD_CHAR_DEVICE is not enabled");
#endif

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

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

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        syslog(LOG_ERR, "Socket creation failed");
        return -1;
    }

    // Configure server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(server_addr.sin_zero), '\0', 8);

    // Bind the socket to the port
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) 
    {
        syslog(LOG_ERR, "Binding failed");
        close(sockfd);
        return -1;
    }

    // Listen for incoming connections
    if (listen(sockfd, BACKLOG) == -1) 
    {
        syslog(LOG_ERR, "Listening failed");
        return -1;
    }


    while (run)
    {
        sin_size = sizeof(struct sockaddr_in);
        new_fd = malloc(sizeof(int));

        if ((*new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1) 
	{
            syslog(LOG_ERR, "Accepting connection failed");
            free(new_fd);
            continue;
        }

        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(client_addr.sin_addr));

        // Create a new thread to handle the connection
        if (pthread_create(&thread, NULL, handle_connection, new_fd) != 0) 
	{
            syslog(LOG_ERR, "Thread creation failed");
            close(*new_fd);
            free(new_fd);
        }
	else
	{
            add_thread_to_list(thread);
        }

	// Join and remove completed threads
	join_and_remove_threads();
    }

    // Join and remove any remaining threads before exiting
    join_and_remove_threads();

#ifndef USE_AESD_CHAR_DEVICE
    pthread_cancel(ts_thread);
#endif

    if (sockfd != -1)
    {
        close(sockfd);
    }

    syslog(LOG_INFO, "aesdsocket server is shutting down");
    closelog();
    return 0;
}
