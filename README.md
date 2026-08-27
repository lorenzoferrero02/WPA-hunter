# WPA Hunter

Automated WPA/WPA2 Security Assessment Tool for Linux

## Features

- Automated network scanning and target selection
- Client discovery and targeted deauth attacks
- WPA handshake capture with live monitoring
- Automatic conversion to hashcat format
- Dictionary attack with progress monitoring
- Clean interface with colored output
- Session logging for professional reporting

## Requirements

- Linux with wireless


sudo ip link set wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set wlan1 up

sudo python3 wpa-hunter.py 
