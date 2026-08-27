#!/usr/bin/env python3
"""
WPA Hunter - Automated WPA/WPA2 Security Assessment Tool
For authorized security testing only
"""

import os
import sys
import time
import signal
import subprocess
import re
import argparse
import configparser
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

# Import modules
from modules.scanner import WPAScanner
from modules.cracker import HandshakeCracker, AdvancedCracker
from modules.utils import clear_input_buffer, check_root, get_timestamp

# Initialize Rich console
console = Console()

# Global variables
running = True
capture_process = None
deauth_process = None
scanner_instance = None
cracker_instance = None

# Banner
BANNER = """
[bold cyan]
██╗    ██╗██████╗  █████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║    ██║██╔══██╗██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝███████║█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║███╗██║██╔═══╝ ██╔══██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝██║     ██║  ██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold yellow]Automated WPA/WPA2 Security Assessment Tool v1.0[/bold yellow]
[dim]For authorized security testing only[/dim]
"""

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running, scanner_instance, cracker_instance
    
    console.print("\n[yellow]\n[!] Ctrl+C detected - Stopping...[/yellow]")
    running = False
    
    if scanner_instance:
        scanner_instance.cleanup()
    
    console.print("[bold red]Program terminated by user[/bold red]")
    sys.exit(0)

def show_menu():
    """Display main menu"""
    menu_text = """
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                      MAIN MENU                                      ║
╠════════════════════════════════════════════════════════════════════╣
║  [1] New Attack - Capture WPA Handshake                            ║
║  [2] Crack Existing Handshake                                      ║
║  [3] Advanced Cracking Options                                     ║
║  [4] Exit                                                          ║
╚════════════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(menu_text)
    choice = Prompt.ask("[bold yellow]Select option[/bold yellow]", 
                        choices=["1", "2", "3", "4"], 
                        default="1")
    return choice


def new_attack_mode(scanner, args):
    """Perform full attack: scan, capture, crack"""
    global running, capture_process
    
    # Setup interface
    if not scanner.setup_interface(args.iface):
        return False
    
    # Scan networks
    networks = scanner.scan_networks(duration=30)
    if not networks or not running:
        return False
    
    # Select target
    target = scanner.select_target(networks)
    if not target:
        return False
    
    # Discover clients
    clients = scanner.discover_clients(target['BSSID'], target['channel'])
    target_client = scanner.select_client(clients) if clients else None
    
    # Attack and capture
    if running and Confirm.ask("\nStart deauth attack and capture?"):
        success = scanner.start_capture_and_deauth(
            target['ESSID'],
            target['BSSID'],
            target['channel'],
            target_client,
            args.timeout
        )
        
        if success and running:
            console.print("[bold green][✓] Handshake captured successfully![/bold green]")
            
            clear_input_buffer()
            subprocess.run(['stty', 'sane'], capture_output=True)
            
            # Return to main menu without cracking
            console.print("\n[dim]Press Enter to return to main menu...[/dim]")
            input()
    
    return True

def crack_existing_mode(scanner, args):
    """Crack an existing handshake capture"""
    cracker = HandshakeCracker(scanner.config)
    
    # Find existing handshakes
    handshakes = scanner.list_handshake_files()
    
    if not handshakes:
        console.print("[yellow][!] No handshake files found![/yellow]")
        cap_file = Prompt.ask("Enter path to .cap file", default="")
        if not cap_file or not os.path.exists(cap_file):
            return False
    else:
        # Display and select
        table = Table(title="Found Handshake Captures")
        table.add_column("#", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Date", style="blue")
        
        for idx, hs in enumerate(handshakes, 1):
            table.add_row(str(idx), hs['name'], hs['size'], hs['date'])
        
        console.print(table)
        choice = Prompt.ask("Select handshake", default="1")
        
        try:
            cap_file = handshakes[int(choice) - 1]['path']
        except (ValueError, IndexError):
            console.print("[red][✗] Invalid selection[/red]")
            return False
    
    # Crack
    cracker.crack(cap_file, args.wordlist, args.rules)
    return True

def advanced_cracking_mode(scanner, args):
    """Advanced cracking with more options"""
    global running
    
    console.print("\n[bold cyan]═══════════ Advanced Cracking ═══════════[/bold cyan]")
    
    # Select handshake file
    handshakes = scanner.list_handshake_files()
    if not handshakes:
        cap_file = Prompt.ask("Enter path to .cap file")
        if not cap_file or not os.path.exists(cap_file):
            return False
    else:
        for idx, hs in enumerate(handshakes, 1):
            console.print(f"[{idx}] {hs['name']} - {hs['date']}")
        choice = Prompt.ask("Select handshake", default="1")
        try:
            cap_file = handshakes[int(choice) - 1]['path']
        except:
            return False
    
    # Advanced options
    console.print("\n[bold yellow]Cracking Options:[/bold yellow]")
    console.print("1. Dictionary attack (wordlist)")
    console.print("2. Mask attack (brute force pattern)")
    console.print("3. Rule-based attack")
    console.print("4. Show handshake info")
    
    crack_choice = Prompt.ask("Select attack type", choices=["1", "2", "3", "4"], default="1")
    
    cracker = AdvancedCracker(scanner.config)
    
    if crack_choice == "1":
        # Dictionary attack
        wordlist = Prompt.ask("Wordlist path", default=cracker.get_wordlist())
        rules = Prompt.ask("Rules file (optional)", default="")
        cracker.crack(cap_file, wordlist, rules if rules else None)
        
    elif crack_choice == "2":
        # Mask attack
        console.print("[dim]Mask examples:[/dim]")
        console.print("  ?d?d?d?d?d?d?d?d  - 8 digits")
        console.print("  ?l?l?l?l?l?l?l?l  - 8 lowercase")
        console.print("  ?u?l?l?d?d?d      - Upper+2lower+3digits")
        mask = Prompt.ask("Enter mask", default="?d?d?d?d?d?d?d?d")
        cracker.mask_attack(cap_file, mask)
        
    elif crack_choice == "3":
        # Rule-based
        wordlist = Prompt.ask("Wordlist path", default=cracker.get_wordlist())
        if cracker.rule_files:
            console.print("\n[dim]Available rule files:[/dim]")
            for idx, rule in enumerate(cracker.rule_files[:15], 1):
                rule_name = os.path.basename(rule)
                # Recupera la descrizione dal dizionario dell'oggetto cracker o usa un fallback
                desc = cracker.rule_descriptions.get(rule_name, "Regola di mutazione standard")
                console.print(f"  {idx}. [cyan]{rule_name}[/cyan] - [dim]{desc}[/dim]")
                
            rule_choice = Prompt.ask("Select rule", default="1")
            try:
                rules = cracker.rule_files[int(rule_choice) - 1]
            except:
                rules = Prompt.ask("Enter rules file path")
        else:
            rules = Prompt.ask("Enter rules file path")
        
        cracker.crack(cap_file, wordlist, rules)
        
    elif crack_choice == "4":
        cracker.show_statistics(cap_file)
    
    return True

def main():
    """Main program entry point"""
    global running, scanner_instance
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='WPA Hunter - Automated WPA/WPA2 Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--iface', help='Wireless interface to use')
    parser.add_argument('--timeout', type=int, default=180, help='Capture timeout')
    parser.add_argument('--deauth', type=int, default=10, help='Number of deauth packets')
    parser.add_argument('--crack-only', help='Crack existing .cap file')
    parser.add_argument('--wordlist', help='Path to wordlist')
    parser.add_argument('--rules', help='Hashcat rules file')
    parser.add_argument('--output', default='./captures', help='Output directory')
    parser.add_argument('--advanced', action='store_true', help='Advanced cracking mode')
    
    args = parser.parse_args()
    
    # Print banner
    console.print(BANNER)
    
    # Check root
    if not check_root():
        sys.exit(1)
    
    # Initialize scanner
    scanner_instance = WPAScanner(args)
    scanner = scanner_instance
    
    # Update config
    if args.output:
        scanner.config['DEFAULT']['output_dir'] = args.output
    if args.deauth:
        scanner.config['DEFAULT']['deauth_packets'] = str(args.deauth)
    
    # Check dependencies
    if not scanner.check_dependencies():
        sys.exit(1)
    
    try:
        # Direct crack mode
        if args.crack_only:
            cracker = HandshakeCracker(scanner.config)
            cracker.crack(args.crack_only, args.wordlist, args.rules)
            sys.exit(0)
        
        # Interactive menu
        while True:
            if args.advanced:
                choice = "3"
            else:
                choice = show_menu()
            
            if choice == "1":
                console.print("\n[bold cyan]═══════════ New Attack Mode ═══════════[/bold cyan]")
                new_attack_mode(scanner, args)
                
                if not Confirm.ask("\nReturn to main menu?", default=True):
                    break
                
                # Reset
                running = True
                scanner.reset()
                
            elif choice == "2":
                console.print("\n[bold cyan]═══════════ Crack Existing Mode ═══════════[/bold cyan]")
                crack_existing_mode(scanner, args)
                
                if not Confirm.ask("\nReturn to main menu?", default=True):
                    break
                    
            elif choice == "3":
                console.print("\n[bold cyan]═══════════ Advanced Cracking Mode ═══════════[/bold cyan]")
                advanced_cracking_mode(scanner, args)
                
                if not Confirm.ask("\nReturn to main menu?", default=True):
                    break
                    
            elif choice == "4":
                console.print("\n[bold green]Goodbye![/bold green]")
                break          

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Program interrupted[/yellow]")
    except Exception as e:
        console.print(f"[bold red][✗] Error: {e}[/bold red]")
        console.print_exception()
    finally:
        if scanner.monitor_interface:
            scanner.cleanup()

if __name__ == "__main__":
    main()