# WPA Hunter

Automated WPA/WPA2 security assessment workflow for Linux, built in Python.

WPA Hunter is a command-line tool designed to help automate common Wi-Fi security testing steps during authorized assessments. It wraps and coordinates existing Linux security tools to make the workflow easier to follow, from interface setup and network discovery to handshake capture and password auditing.

> This project is intended exclusively for authorized security testing, lab environments, and educational purposes.

## Overview

Manual Wi-Fi security testing often requires switching between multiple tools, commands, terminal windows, capture files, and validation steps.

WPA Hunter aims to provide a cleaner workflow around those tools by offering an interactive CLI that can:

- detect available wireless interfaces
- enable monitor mode
- scan nearby wireless networks
- select a target access point
- discover connected clients
- run handshake capture
- validate captured WPA handshakes
- convert captures to Hashcat format
- run dictionary, rule-based, or mask-based auditing workflows

The goal is not to replace tools like Aircrack-ng, Hashcat, or hcxtools.

The goal is to automate the repetitive parts of the workflow while making each step easier to understand and reproduce.

## Features

- Interactive CLI menu
- Wireless interface detection
- Monitor mode setup
- WPA/WPA2 network discovery
- Target access point selection
- Connected client discovery
- Broadcast or targeted deauthentication workflow
- WPA handshake capture
- Basic handshake validation
- Capture listing
- Hashcat `.hc22000` conversion through `hcxpcapngtool`
- Dictionary-based auditing with Hashcat
- Aircrack-ng fallback support
- Rule-based Hashcat workflows
- Mask attack support
- Configurable scan time, capture timeout, deauth packets, and output directory

## Demo

Demo video/GIF coming soon.

Suggested demo flow:

```text
sudo python3 wpa-hunter.py
Select wireless interface
Scan networks
Select authorized test network
Capture WPA handshake
Validate capture
Run password auditing workflow against the captured handshake

```

## Architecture

```text
        Wireless Interface
                |
                v
        Monitor Mode Setup
                |
                v
        Network Discovery
                |
                v
        Target Selection
                |
                v
        Client Discovery
                |
                v
   Capture + Deauthentication Workflow
                |
                v
        Handshake Validation
                |
                v
      Hashcat Format Conversion
                |
                v
        Password Auditing
                |
                v
             Results

```

## Requirements

WPA Hunter is designed for Linux systems with a wireless adapter that supports monitor mode and packet injection.

Recommended environment:

* Kali Linux or Debian-based Linux distribution
* Python 3.8+
* Root privileges
* External Wi-Fi adapter supporting monitor mode
* Aircrack-ng suite
* Hashcat
* hcxtools
* tcpdump
* iw
* wireless-tools

System packages:

```bash
sudo apt update
sudo apt install -y aircrack-ng tcpdump hcxtools hashcat wireless-tools iw python3-pip

```

Python packages:

```bash
pip3 install -r requirements.txt

```

## Installation

Clone the repository:

```bash
git clone https://github.com/lorenzoferrero02/WPA-hunter.git
cd WPA-hunter

```

Install dependencies:

```bash
sudo ./install.sh

```

Or install manually:

```bash
sudo apt update
sudo apt install -y aircrack-ng tcpdump hcxtools hashcat wireless-tools iw python3-pip
pip3 install -r requirements.txt
chmod +x wpa-hunter.py
mkdir -p captures

```

## Usage

Run the interactive menu:

```bash
sudo python3 wpa-hunter.py

```

Use a specific wireless interface:

```bash
sudo python3 wpa-hunter.py --iface wlan1

```

Set a custom capture timeout:

```bash
sudo python3 wpa-hunter.py --timeout 240

```

Set a custom output directory:

```bash
sudo python3 wpa-hunter.py --output ./captures

```

Crack an existing capture file:

```bash
sudo python3 wpa-hunter.py --crack-only ./captures/example/capture-01.cap --wordlist /usr/share/wordlists/rockyou.txt

```

Use a Hashcat rule file:

```bash
sudo python3 wpa-hunter.py --crack-only ./captures/example/capture-01.cap --wordlist /usr/share/wordlists/rockyou.txt --rules /usr/share/hashcat/rules/best64.rule

```

Open advanced cracking options:

```bash
sudo python3 wpa-hunter.py --advanced

```

## Configuration

Default settings can be changed in `config.ini`:

```ini
[DEFAULT]
scan_time = 30
deauth_packets = 10
deauth_rounds = 3
capture_timeout = 180
wordlist_path = /usr/share/wordlists/rockyou.txt
hashcat_rules =
output_dir = ./captures
default_interface =

```

## Output Files

By default, captures are saved under `./captures/`.

Generated files may include:

* `.cap` packet captures
* `.hc22000` Hashcat-compatible hashes
* local cracking result files

> Do not commit real capture files, real passwords, or data from third-party networks.

## Security And Legal Disclaimer

WPA Hunter is intended only for:

* authorized penetration testing
* personal lab environments
* educational cybersecurity research
* testing networks you own or have explicit permission to assess

Do not use this tool against networks you do not own or do not have permission to test. Unauthorized access to computer networks is illegal. The author is not responsible for misuse, damage, legal consequences, or unauthorized activity performed with this tool.

This repository must not contain:

* real WPA/WPA2 passwords
* real capture files from third-party networks
* BSSIDs or ESSIDs belonging to networks you do not own
* unauthorized test data

Use responsibly.

## Known Limitations

- **Linux Only:** Relies heavily on Linux wireless tools (`iw`, `wireless-tools`, `tcpdump`) and network stack behavior.
- **Hardware Dependent:** Requires a wireless network interface card (NIC) that natively supports both **monitor mode** and **packet injection**.
- **Scope Limitation:** Designed specifically for WPA/WPA2-PSK network assessments in authorized lab environments.

## Roadmap

Planned improvements:

* Better error handling
* Cleaner process management
* Optional automatic cracking after handshake capture
* Improved reporting output
* JSON/CSV session summaries
* Safer dry-run/demo mode
* Better capture validation
* More detailed setup checks
* Packaging as an installable Python CLI
* Automated tests for parsing and command generation

## Project Status

WPA Hunter is an early open-source project built as part of a cybersecurity engineering learning path.

The current version focuses on automating and documenting a practical Wi-Fi security testing workflow using existing Linux tools.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
