#!/bin/bash

# Install necessary libraries
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y libssl-dev
elif command -v yum &> /dev/null; then
    sudo yum install -y openssl-devel
else
    echo "Package manager not supported. Please install OpenSSL development libraries manually."
    exit 1
fi

# Compile
g++ -o osuserver server.cpp -lssl -lcrypto
g++ -o osumiddleman middleman.cpp -lssl -lcrypto
g++ -o osu client.cpp

# Create installation directories
sudo mkdir -p /bin/oddbyte
sudo chown root:root /bin/oddbyte
sudo chmod 0000 /bin/oddbyte

# Install binaries
sudo cp osuserver /bin/oddbyte/osuserver
sudo cp osumiddleman /bin/oddbyte/osumiddleman
sudo cp osu /bin/osu

# Set permissions for binaries
sudo chown root:root /bin/oddbyte/osuserver /bin/oddbyte/osumiddleman /bin/osu
sudo chmod 700 /bin/oddbyte/osuserver /bin/oddbyte/osumiddleman
sudo chmod 755 /bin/osu

# Create whitelist directory and file
sudo touch /bin/oddbyte/whitelist
sudo chown root:root /bin/oddbyte/whitelist
sudo chmod 600 /bin/oddbyte/whitelist

# Configure firewall rules
sudo iptables -A INPUT -p tcp --dport 98 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 98 -j DROP
sudo iptables -A INPUT -p tcp --dport 99 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 99 -j DROP

# Persist firewall rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Create systemd service files
echo "[Unit]
Description=Oddbyte Server Service
After=network.target

[Service]
ExecStart=/bin/oddbyte/osuserver
Restart=always
User=root

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/oddbyte-server.service

echo "[Unit]
Description=Oddbyte Permission Middleman Service
After=network.target

[Service]
ExecStart=/bin/oddbyte/osumiddleman
Restart=always
User=root

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/oddbyte-middleman.service

# Reload systemd and enable services
sudo systemctl daemon-reload
sudo systemctl enable oddbyte-server
sudo systemctl enable oddbyte-middleman

# Start services
sudo systemctl start oddbyte-server
sudo systemctl start oddbyte-middleman

# Fallback to crontab if systemd is not available
if ! command -v systemctl &> /dev/null
then
    echo "@reboot root /bin/oddbyte/osuserver" | sudo tee -a /etc/crontab
    echo "@reboot root /bin/oddbyte/osumiddleman" | sudo tee -a /etc/crontab
    echo "Systemd is not available. Server and Permission Middleman will start on reboot using crontab."
else
    echo "Systemd services for Oddbyte Server and Permission Middleman have been installed and started."
fi

# SELinux setup (skip if SELinux is not installed)
if command -v semanage &> /dev/null; then
    sudo semanage fcontext -a -t unconfined_exec_t "/bin/oddbyte(/.*)?"
    sudo restorecon -R -v /bin/oddbyte
fi

# Prompt for initial whitelist entries
echo "Enter initial whitelist entries (end with EOF):"
echo "Format: FilePath`FileHash`AllowedUsers (e.g., /bin/bash`*`root)"
index=0
while read -r line; do
    if [[ -z "$line" ]]; then
        break
    fi
    filepath=$(echo $line | cut -d'`' -f1)
    filehash=$(echo $line | cut -d'`' -f2)
    users=$(echo $line | cut -d'`' -f3)
    userids=""
    for user in $(echo $users | tr "::" "\n"); do
        uid=$(id -u $user 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            userids+="$uid::"
        fi
    done
    userids=${userids%::*} # Remove trailing ::
    echo "$index`$filepath`$filehash`$userids" | sudo tee -a /bin/oddbyte/whitelist
    index=$((index + 1))
done

echo "Installation complete."
