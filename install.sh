#!/bin/bash

# Update package lists
sudo apt update

# Install build-essential and Crypto++ library
sudo apt install build-essential libcrypto++-dev -y

# Compile the oddkey.cpp file, using the Crypto++ library cause we need it
g++ -o oddsuperuser oddsuperuser.cpp -lcryptopp

# Check if the compilation succeeded
if [ $? -eq 0 ]; then
    echo "Compilation successful."

    # Run the program with elevated privileges
    sudo ./oddsuperuser
else
    echo "Compilation failed."
    exit 1
fi
