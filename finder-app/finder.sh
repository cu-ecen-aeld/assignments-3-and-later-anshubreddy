#!/bin/bash

# Check if the correct number of arguments are provided
if [ $# -ne 2 ]
then
    echo "Error: Two arguments required: <filesdir> <searchstr>"
    exit 1
fi

filesdir=$1
searchstr=$2

# Check if filesdir is a directory
if [ ! -d "$filesdir" ] 
then
    echo "Error: $filesdir is not a directory"
    exit 1
fi

# Find the number of files and matching lines
num_files=$(find "$filesdir" -type f | wc -l)
num_matching_lines=$(grep -r "$searchstr" "$filesdir" | wc -l)

# Print the result
echo "The number of files are $num_files and the number of
matching lines are $num_matching_lines"
