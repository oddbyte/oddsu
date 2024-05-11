#!/bin/bash

# Update package lists
sudo apt update

# Install build-essential and Crypto++ library
sudo apt install build-essential libcrypto++-dev -y

# Compile the key editor and install it, using the Crypto++ library cause we need it
g++ -o editosu editosu.cpp -lcryptopp
sudo mv editosu /usr/bin/
sudo chown root:root /usr/bin/editosu
sudo chmod 0500 /usr/bin/editosu

# Compile the oddkey.cpp file, using the Crypto++ library cause we need it
g++ -o oddsuperuser oddsuperuser.cpp -lcryptopp

# Check if the compilation succeeded
if [ $? -eq 0 ]; then
    echo "Compilation successful."

    # Run the program with root perms and trigger a forced installation
    sudo ./oddsuperuser --install-force
else
    echo "Compilation failed."
    exit 1
fi
