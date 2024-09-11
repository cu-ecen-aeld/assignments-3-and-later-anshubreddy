#!/bin/bash

# Check if the correct number of arguments are provided
if [ $# -ne 2 ] 
then
    echo "Error: Two arguments required. Usage: writer.sh <writefile> <writestr>"
    exit 1
fi

writefile=$1
writestr=$2

# Extract the directory path
dirpath=$(dirname "$writefile")
echo "dirpath: $dirpath"

# Create the directory path if it doesn't exist
if [ ! -d "$dirpath" ] 
then
    echo "Creating directory path: $dirpath"
    mkdir -p "$dirpath"
    if [ $? -ne 0 ]
    then
        echo "Error: Could not create directory path $dirpath"
	exit 1
    fi
fi

# Write the string to the file, overwriting if it exists
echo "$writestr" > "$writefile"

# Check if the file was created successfully
if [ $? -ne 0 ] 
then
    echo "Error: Could not create file $writefile"
    exit 1
fi

echo "File created successfully with content: $writestr"
exit 0
