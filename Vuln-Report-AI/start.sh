#!/bin/bash
# start.sh
# Navigates to the source directory and runs the Python agent with a target IP.

# Exit immediately if a command exits with a non-zero status.
set -e

# Change to the script's directory
cd "$(dirname "$0")"

# Check if a target IP was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TARGET_IP=$1

echo "Starting the security agent..."
python3 src/agent.py "$TARGET_IP"

echo "Security scan and report generation complete."
