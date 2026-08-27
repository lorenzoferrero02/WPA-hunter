#!/usr/bin/env python3
"""
WiFi Connection Management Module - Improved Version
Handles connecting to, disconnecting from, and monitoring WiFi networks
"""

import os
import time
import subprocess
import re
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()

class WiFiConnection:
    """Handle WiFi network connections with proper verification"""
    
    def __init__(self):
        self.interface = None
        self.current_ssid = None
    
    def set_managed_mode(self, interface):
        """Set interface to managed mode"""
        console.print(f"[dim]Setting {interface} to managed mode...[/dim]")
        
        try:
            # Kill any processes that might interfere
            subprocess.run(['sudo', 'killall', 'wpa_supplicant'], capture_output=True)
            subprocess.run(['sudo', 'killall', 'dhclient'], capture_output=True)
            
            # Set managed mode
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, timeout=5)
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], 
                         capture_output=True, timeout=5)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            return True
        except Exception as e:
            console.print(f"[red][✗] Error setting managed mode: {e}[/red]")
            return False
    
    def connect_to_network(self, interface, bssid, essid, encryption, password=None):
        """Connect to a WiFi network with proper verification"""
        console.print(f"\n[bold cyan][*] Attempting to connect to '{essid}' ({bssid})[/bold cyan]")
        
        self.interface = interface
        
        # First, disconnect from any existing network
        self.disconnect_network(interface)
        
        # Check if network is open
        is_open = 'OPEN' in encryption.upper() or 'None' in encryption or not encryption or encryption == 'Unknown'
        
        if is_open:
            console.print("[green][*] Open network detected - connecting without password[/green]")
            return self._connect_open(interface, essid)
        else:
            if not password:
                console.print("[red][✗] Password required for secure network[/red]")
                return False
            return self._connect_secure(interface, essid, bssid, password)
    
    def _connect_open(self, interface, essid):
        """Connect to an open (no password) WiFi network"""
        try:
            # Use iwconfig for open connection
            cmd = ['sudo', 'iwconfig', interface, 'essid', essid]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                console.print(f"[red][✗] iwconfig error: {result.stderr}[/red]")
                return False
            
            # Wait for association
            console.print("[dim]Waiting for association...[/dim]")
            time.sleep(3)
            
            # Verify association
            if not self._verify_association(interface, essid):
                console.print("[red][✗] Failed to associate with network[/red]")
                return False
            
            # Get IP via DHCP
            console.print("[dim]Requesting IP address via DHCP...[/dim]")
            
            # Release any existing lease
            subprocess.run(['sudo', 'dhclient', '-r', interface], capture_output=True)
            time.sleep(1)
            
            # Request new lease
            dhcp_result = subprocess.run(['sudo', 'dhclient', '-v', interface], 
                                       capture_output=True, text=True, timeout=15)
            
            # Verify connection
            time.sleep(2)
            if self._verify_connection(interface, essid):
                self.current_ssid = essid
                console.print("[bold green][✓] Successfully connected to open network![/bold green]")
                self._show_ip(interface)
                return True
            else:
                console.print("[red][✗] Failed to get IP address[/red]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print("[red][✗] Connection timeout[/red]")
            return False
        except Exception as e:
            console.print(f"[red][✗] Error connecting: {e}[/red]")
            return False
    
    def _connect_secure(self, interface, essid, bssid, password):
        """Connect to a secure (WPA/WPA2) WiFi network with proper verification"""
        try:
            # Create temporary config file
            config_file = f"/tmp/wpa_supplicant_{int(time.time())}.conf"
            
            config_content = f"""ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1
network={{
    ssid="{essid}"
    bssid={bssid}
    psk="{password}"
    key_mgmt=WPA-PSK
    proto=RSN WPA
    pairwise=CCMP TKIP
    group=CCMP TKIP
    scan_ssid=1
    priority=1
}}
"""
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            # Kill existing wpa_supplicant processes
            subprocess.run(['sudo', 'pkill', '-f', 'wpa_supplicant'], capture_output=True)
            time.sleep(2)
            
            # Start wpa_supplicant in foreground to capture output
            console.print("[dim]Authenticating with network...[/dim]")
            
            wpa_cmd = [
                'sudo', 'wpa_supplicant', '-i', interface,
                '-c', config_file, '-D', 'nl80211,wext'
            ]
            
            # Run wpa_supplicant and wait for connection
            process = subprocess.Popen(wpa_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                      text=True, bufsize=1)
            
            # Wait for connection (max 15 seconds)
            connected = False
            for i in range(15):
                time.sleep(1)
                # Check if already associated
                if self._verify_association(interface, essid):
                    connected = True
                    break
                
                # Check for error in output
                if process.poll() is not None:
                    break
            
            # If not connected, try with different driver
            if not connected:
                process.terminate()
                time.sleep(1)
                
                console.print("[dim]Trying with wext driver...[/dim]")
                wpa_cmd = [
                    'sudo', 'wpa_supplicant', '-B', '-i', interface,
                    '-c', config_file, '-D', 'wext'
                ]
                result = subprocess.run(wpa_cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    console.print(f"[red][✗] wpa_supplicant error: {result.stderr}[/red]")
                    return False
                
                # Wait for association
                time.sleep(5)
                connected = self._verify_association(interface, essid)
            
            if not connected:
                console.print("[red][✗] Failed to authenticate with network[/red]")
                console.print("[dim]Possible causes: wrong password, wrong encryption type, or out of range[/dim]")
                return False
            
            # Get IP via DHCP
            console.print("[dim]Requesting IP address via DHCP...[/dim]")
            subprocess.run(['sudo', 'dhclient', '-r', interface], capture_output=True)
            time.sleep(1)
            dhcp_result = subprocess.run(['sudo', 'dhclient', '-v', interface], 
                                       capture_output=True, text=True, timeout=15)
            
            # Verify connection
            time.sleep(2)
            if self._verify_connection(interface, essid):
                self.current_ssid = essid
                console.print("[bold green][✓] Successfully connected to secure network![/bold green]")
                self._show_ip(interface)
                
                # Keep wpa_supplicant running in background
                if process.poll() is None:
                    # Already running in foreground, leave it
                    pass
                return True
            else:
                console.print("[red][✗] Connected to AP but no IP address assigned[/red]")
                console.print("[dim]Try: sudo dhclient " + interface + "[/dim]")
                return True  # Still connected even without IP
                
        except subprocess.TimeoutExpired:
            console.print("[red][✗] Connection timeout[/red]")
            return False
        except Exception as e:
            console.print(f"[red][✗] Error connecting: {e}[/red]")
            return False
        finally:
            # Don't delete config file immediately, wpa_supplicant might need it
            pass
    
    def disconnect_network(self, interface):
        """Disconnect from current network completely"""
        console.print(f"\n[cyan][*] Disconnecting from network on {interface}...[/cyan]")
        
        try:
            # Kill wpa_supplicant
            subprocess.run(['sudo', 'pkill', '-f', 'wpa_supplicant'], capture_output=True)
            
            # Release DHCP lease
            subprocess.run(['sudo', 'dhclient', '-r', interface], capture_output=True)
            
            # Disconnect from any network
            subprocess.run(['sudo', 'iwconfig', interface, 'essid', 'off'], capture_output=True)
            
            # Bring interface down and up to reset
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], capture_output=True)
            time.sleep(1)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], capture_output=True)
            
            # Clear any cached IP
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface], capture_output=True)
            
            self.current_ssid = None
            console.print("[green][✓] Disconnected successfully[/green]")
            return True
        except Exception as e:
            console.print(f"[red][✗] Error disconnecting: {e}[/red]")
            return False
    
    def show_current_connection(self, interface):
        """Show current WiFi connection status with detailed info"""
        try:
            # Check if connected via iwconfig
            iw_result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            
            if 'Not-Associated' in iw_result.stdout:
                console.print("[yellow][!] Not currently connected to any network[/yellow]")
                return None
            
            # Parse ESSID
            essid_match = re.search(r'ESSID:"([^"]*)"', iw_result.stdout)
            essid = essid_match.group(1) if essid_match else "Unknown"
            
            # Parse access point BSSID
            ap_match = re.search(r'Access Point: ([0-9A-F:]+)', iw_result.stdout, re.IGNORECASE)
            ap_mac = ap_match.group(1) if ap_match else "Unknown"
            
            # Parse frequency/channel
            freq_match = re.search(r'Frequency:([\d.]+) GHz', iw_result.stdout)
            
            # Parse signal quality
            quality_match = re.search(r'Quality[=:](\d+)/(\d+)', iw_result.stdout)
            
            console.print(f"\n[bold green]Current Connection:[/bold green]")
            console.print(f"  SSID: [yellow]{essid}[/yellow]")
            console.print(f"  BSSID: [dim]{ap_mac}[/dim]")
            if freq_match:
                console.print(f"  Frequency: [dim]{freq_match.group(1)} GHz[/dim]")
            if quality_match:
                quality = int(quality_match.group(1)) * 100 // int(quality_match.group(2))
                if quality > 70:
                    quality_color = "green"
                elif quality > 30:
                    quality_color = "yellow"
                else:
                    quality_color = "red"
                console.print(f"  Signal quality: [{quality_color}]{quality}%[/{quality_color}]")
            
            # Show IP address
            self._show_ip(interface)
            
            # Show connection test
            self._test_connection()
            
            return essid
        except Exception as e:
            console.print(f"[red][✗] Error checking connection: {e}[/red]")
            return None
    
    def _verify_association(self, interface, essid):
        """Verify if interface is associated with the network"""
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            return essid in result.stdout and 'Not-Associated' not in result.stdout
        except:
            return False
    
    def _verify_connection(self, interface, essid):
        """Verify full connection including IP"""
        if not self._verify_association(interface, essid):
            return False
        
        # Check if we have an IP address
        try:
            ip_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                     capture_output=True, text=True)
            has_ip = 'inet ' in ip_result.stdout and not '127.0.0.1' in ip_result.stdout
            
            if has_ip:
                return True
            else:
                # Try to get IP via DHCP
                subprocess.run(['sudo', 'dhclient', interface], capture_output=True, timeout=10)
                time.sleep(2)
                
                ip_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                         capture_output=True, text=True)
                return 'inet ' in ip_result.stdout and not '127.0.0.1' in ip_result.stdout
        except:
            return False
    
    def _show_ip(self, interface):
        """Show IP address of interface"""
        try:
            ip_cmd = ['ip', 'addr', 'show', interface]
            ip_result = subprocess.run(ip_cmd, capture_output=True, text=True)
            for line in ip_result.stdout.split('\n'):
                if 'inet ' in line and not '127.0.0.1' in line:
                    ip = line.strip().split()[1]
                    console.print(f"  IP Address: [dim]{ip}[/dim]")
        except:
            pass
    
    def _test_connection(self):
        """Test internet connectivity by pinging a reliable host"""
        try:
            result = subprocess.run(['ping', '-c', '2', '-W', '2', '8.8.8.8'], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                console.print(f"  Internet: [green]Connected[/green]")
            else:
                console.print(f"  Internet: [yellow]Limited or no connectivity[/yellow]")
        except:
            console.print(f"  Internet: [yellow]Cannot test connectivity[/yellow]")