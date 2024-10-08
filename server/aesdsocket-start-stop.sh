#!/bin/sh

# Script to start aesdsocket in daemon mode

case "$1" in
    start)
        echo "Starting aesdsocket"
        # Starts aesdsocket process by also having daemon in the background with -d flag
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
        echo "$DAEMON_NAME started."
        ;;
    stop)
        echo "Stopping aesdsocket"
        # Stops process via issuing of SIGTERM
        start-stop-daemon -K -n aesdsocket
        ;;
    *)
        # Displays usage information if the script is called with an invalid argument
        echo "Usage: $0 {start|stop}"
        exit 1
esac

exit 0

