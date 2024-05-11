#!/bin/bash

git clone https://github.com/OddbyteWasTaken/oddsu.git


# Update packages
sudo apt update -y

# Install build-essential and Crypto++ library
sudo apt install build-essential libcrypto++-dev -y

# Install the key editor and set the perms
sudo mv editosu /usr/bin/
sudo chown root:root /usr/bin/editosu
sudo chmod 0500 /usr/bin/editosu

# Install OddSU, all perms are handled by the installation script inside of here.
sudo ./oddsuperuser
