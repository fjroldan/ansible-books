#!/bin/bash
username=defaultuser

sudo sed -i "s|PASS_MAX_DAYS.*|PASS_MAX_DAYS   365|g" /etc/login.defs

sudo chage --maxdays 365 $username

# 5.6.1.2
sudo sed -i "s|PASS_MIN_DAYS.*|PASS_MIN_DAYS   7|g" /etc/login.defs

sudo chage --mindays 7 $username

# 5.6.1.3
sudo sed -i "s|PASS_WARN_AGE.*|PASS_WARN_AGE   7|g" /etc/login.defs

sudo chage --warndays 1 $username

# 5.6.1.4
sudo useradd -D -f 30

sudo chage --inactive 30 $username

echo "FIN"
