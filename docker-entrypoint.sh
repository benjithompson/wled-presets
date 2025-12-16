#!/bin/sh
set -e

# Ensure data directory exists and is writable
mkdir -p /app/data

# Check if we can write to data directory
if [ ! -w /app/data ]; then
    echo "ERROR: /app/data is not writable. Please check volume permissions."
    echo "On Unraid, ensure the appdata folder has proper permissions."
    exit 1
fi

# Run the application
exec node server.js
