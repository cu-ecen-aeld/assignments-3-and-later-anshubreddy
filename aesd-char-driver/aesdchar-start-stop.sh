#!/bin/sh

case "$1" in
    start)
        echo "Loading aesdchar"
        aesdchar_load
        ;;
    stop)
        echo "Unloading aesdchar"
        aesdchar_unload
        ;;
    *)
        echo "Usage: $0 {start|stop}"
    exit 1
esac

exit 0
