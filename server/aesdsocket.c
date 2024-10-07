#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

#define PORT 9000
#define BACKLOG 10
#define FILE_PATH "/var/tmp/aesdsocketdata"

int sockfd = -1, new_fd = -1;
FILE *file;

// Signal handler for SIGINT and SIGTERM
void handle_signal(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
    
        if (file) 
        {
            fclose(file);
        }

        if (new_fd != -1) 
        {
            close(new_fd);
        }

        if (sockfd != -1) 
        {
            close(sockfd);
        }

        remove(FILE_PATH);
        closelog();
	exit(0);
    }
}

int main(int argc, char *argv[])
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size;
    char buffer[1024];
    int numbytes;
    
    // Open log for syslogging
    openlog("aesdsocket", LOG_PID, LOG_USER);

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

	// Fork again to ensure the daemon can't acquire a controlling terminal
	pid = fork();
	if (pid < 0)
	{
            syslog(LOG_ERR, "Fork failed");
	    return -1;
	}

	if (pid > 0)
        {
            exit(EXIT_SUCCESS); // Parent process exists
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

    while(1)
    {
        sin_size = sizeof(struct sockaddr_in);

	// Accept a new connection
	if ((new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1)
        {
            syslog(LOG_ERR, "Accepting connection failed");
	    continue;
        }

	// Log the accepted connection
        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(client_addr.sin_addr));

	// Open the file for appending
        file = fopen(FILE_PATH, "a+");
	if (!file)
        {
            syslog(LOG_ERR, "File opening failed");
	    close(new_fd);
	    continue;
        }

	// Receive data from the client 
        while ((numbytes = recv(new_fd, buffer, sizeof(buffer) - 1, 0)) > 0)
        {
            buffer[numbytes] = '\0';

	    // Append received data to the file
            fprintf(file, "%s", buffer);
	    fflush(file);

	    // Check for newline character to determine end of packet
	    if (strchr(buffer, '\n'))
            {    
                // Send the full content of the file back to the client
                fseek(file, 0, SEEK_SET);
                while ((numbytes = fread(buffer, 1, sizeof(buffer) - 1, file)) > 0)
                {
                    buffer[numbytes] = '\0';
                    send(new_fd, buffer, numbytes, 0);
                }
	    }
	}

	// Log the closed connection
        syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(client_addr.sin_addr));
        fclose(file);
	close(new_fd);
    }

    return 0;
}
