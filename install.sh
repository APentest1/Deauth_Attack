#!/bin/bash

# Make the Python script executable
chmod +x deauth.py

# Copy the Python script to /usr/local/bin
sudo cp deauth.py /usr/local/bin/

# Copy the icon to the system icon directory
sudo cp icon.png /usr/share/pixmaps/deauth_icon.png

# Copy the desktop entry to the applications directory
sudo cp deauth.desktop /usr/share/applications/

# Update desktop database
sudo update-desktop-database

echo "Installation complete! You can now find 'Wi-Fi Deauth Tool' in the applications menu."
