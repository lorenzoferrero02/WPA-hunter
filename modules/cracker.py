#!/usr/bin/env python3
"""
Handshake Cracking Module
Supports multiple cracking methods:
- Hashcat (default)
- Aircrack-ng (fallback)
- Custom wordlist management
- Rule-based attacks
- GPU acceleration
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
import re

console = Console()

class HandshakeCracker:
    """Advanced handshake cracking module"""
    
    def __init__(self, config):
        self.config = config
        self.hash_file = None
        self.cap_file = None
        self.cracked_password = None
        self.cracking_method = None
        
    def check_cracking_tools(self):
        """Check if cracking tools are available"""
        tools = {
            'hashcat': 'hashcat',
            'aircrack-ng': 'aircrack-ng',
            'hcxpcapngtool': 'hcxtools'
        }
        
        available = {}
        for tool, package in tools.items():
            result = subprocess.run(
                f'which {tool} > /dev/null 2>&1',
                shell=True
            )
            available[tool] = (result.returncode == 0)
        
        return available
    
    def convert_to_hashcat(self, cap_file):
        """Convert .cap file to hashcat format (hc22000)"""
        self.cap_file = cap_file
        self.hash_file = cap_file.replace('.cap', '.hc22000')
        
        console.print("[cyan][*] Converting to hashcat format...[/cyan]")
        
        try:
            result = subprocess.run(
                ['hcxpcapngtool', '-o', self.hash_file, cap_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if os.path.exists(self.hash_file) and os.path.getsize(self.hash_file) > 0:
                # Parse output for info
                pmkid_found = 'PMKID' in result.stdout
                eapol_found = 'EAPOL' in result.stdout
                
                console.print(f"[green][✓] Converted successfully[/green]")
                if pmkid_found:
                    console.print("[dim]  - PMKID found[/dim]")
                if eapol_found:
                    console.print("[dim]  - EAPOL frames found[/dim]")
                
                return True
            else:
                console.print("[red][✗] Conversion failed[/red]")
                if result.stdout:
                    console.print(f"[dim]{result.stdout[:500]}[/dim]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print("[red][✗] Conversion timeout[/red]")
            return False
        except Exception as e:
            console.print(f"[red][✗] Conversion error: {e}[/red]")
            return False
    
    def get_wordlist(self, custom_wordlist=None):
        """Get wordlist path with multiple fallbacks"""
        wordlist = custom_wordlist or self.config.get('DEFAULT', 'wordlist_path')
        
        # Common wordlist paths
        common_paths = [
            wordlist,
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/fasttrack.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
            '/usr/share/wordlists/nmap.lst',
            './wordlists/custom.txt'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                # Check if rockyou needs unzipping
                if 'rockyou.txt' in path and not os.path.exists(path):
                    rockyou_gz = path + '.gz'
                    if os.path.exists(rockyou_gz):
                        console.print("[yellow][!] Unzipping rockyou.txt...[/yellow]")
                        subprocess.run(f'gunzip {rockyou_gz}', shell=True)
                        if os.path.exists(path):
                            return path
                return path
        
        return None
    
    def get_hashcat_options(self, wordlist, rules=None, attack_mode='straight'):
        """Build hashcat command with optimal options"""
        cmd = ['hashcat', '-m', '22000', self.hash_file, wordlist]
        
        if attack_mode == 'straight':
            cmd.extend(['-a', '0'])
        elif attack_mode == 'combinator':
            cmd.extend(['-a', '1'])
        elif attack_mode == 'mask':
            cmd.extend(['-a', '3'])
        
        if rules:
            if os.path.exists(rules):
                cmd.extend(['-r', rules])
            else:
                console.print(f"[yellow][!] Rules file not found: {rules}[/yellow]")
        
        cmd.extend([
            '--force',
            '--status',
            '--status-timer=1',
            '--potfile-path', '/tmp/hashcat.potfile',
            '-O',
            '-w', '3'
        ])
        
        return cmd

    def crack_with_hashcat(self, wordlist, rules=None, timeout=None):
        """Crack handshake using hashcat"""
        global running
        
        # Build command
        hashcat_cmd = self.get_hashcat_options(wordlist, rules)
        
        console.print(f"\n[bold cyan][*] Starting hashcat cracking...[/bold cyan]")
        console.print(f"[dim]Hash: {self.hash_file}[/dim]")
        console.print(f"[dim]Wordlist: {wordlist}[/dim]")
        console.print(f"[dim]Attack mode: Dictionary[/dim]")
        
        if rules:
            console.print(f"[dim]Rules: {rules}[/dim]")
        
        console.print("[yellow]Press Ctrl+C to stop cracking[/yellow]\n")
        
        start_time = time.time()
        
        try:
            # Run hashcat
            process = subprocess.Popen(
                hashcat_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Monitor progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Cracking...", total=None)
                
                while process.poll() is None:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        
                        # Parse hashcat status
                        if 'Status' in line:
                            if 'Running' in line:
                                progress.update(task, description="[cyan]Cracking in progress...")
                            elif 'Cracked' in line:
                                progress.update(task, description="[green]Password found!")
                            elif 'Exhausted' in line:
                                progress.update(task, description="[yellow]Wordlist exhausted")
                            console.print(f"[dim]{line}[/dim]")
                        
                        elif 'Recovered' in line and ':' in line:
                            console.print(f"[yellow]{line}[/yellow]")
                        
                        elif 'TIME' in line and 'SPEED' in line:
                            # Update speed
                            pass
                        
                        # Check for timeout
                        if timeout and (time.time() - start_time) > timeout:
                            process.terminate()
                            console.print(f"\n[yellow][!] Timeout reached ({timeout}s)[/yellow]")
                            break
                    
                    time.sleep(0.1)
            
            process.wait()
            
            # Check result
            return self.check_hashcat_result()
            
        except KeyboardInterrupt:
            if process and process.poll() is None:
                process.terminate()
                process.wait()
            console.print("\n[yellow][!] Cracking interrupted[/yellow]")
            return False
        except Exception as e:
            console.print(f"[red][✗] Hashcat error: {e}[/red]")
            return False
    
    def check_hashcat_result(self):
        """Check if hashcat found the password"""
        try:
            result = subprocess.run(
                ['hashcat', '-m', '22000', '--show', self.hash_file,
                 '--potfile-path', '/tmp/hashcat.potfile'],   # <-- AGGIUNTO
                capture_output=True,
                text=True
            )
            
            if result.stdout.strip():
                parts = result.stdout.strip().split(':')
                if len(parts) >= 2:
                    self.cracked_password = ':'.join(parts[1:])
                    return True
            
            return False
            
        except Exception:
            return False
    
    def crack_with_aircrack(self, cap_file, wordlist):
        """Fallback method using aircrack-ng"""
        console.print("\n[bold cyan][*] Trying aircrack-ng...[/bold cyan]")
        
        try:
            cmd = ['aircrack-ng', '-w', wordlist, cap_file]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            for line in process.stdout:
                line = line.strip()
                if 'KEY FOUND' in line:
                    # Extract password
                    match = re.search(r'\[(.*?)\]', line)
                    if match:
                        self.cracked_password = match.group(1)
                        return True
                console.print(f"[dim]{line}[/dim]")
            
            process.wait()
            return False
            
        except Exception as e:
            console.print(f"[red][✗] Aircrack-ng error: {e}[/red]")
            return False
    
    def save_results(self):
        """Save cracking results to files"""
        if not self.cracked_password:
            return
        
        # Save to file
        result_file = os.path.join(os.path.dirname(self.cap_file), 'cracked_password.txt')
        with open(result_file, 'w') as f:
            f.write(f"Password: {self.cracked_password}\n")
            f.write(f"Hash file: {self.hash_file}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        console.print(f"[green][✓] Password saved to {result_file}[/green]")
        
        # Also save to main results file
        master_results = './cracked_passwords.txt'
        with open(master_results, 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {self.cap_file}: {self.cracked_password}\n")
    
    def display_result(self):
        """Display cracking results in a nice panel"""
        if self.cracked_password:
            result_text = f"""
[bold green]╔══════════════════════════════════════════════════════════════╗
║                     🔑 PASSWORD FOUND! 🔑                       ║
╠══════════════════════════════════════════════════════════════════╣
║  Password: [bold yellow]{self.cracked_password}[/bold yellow]
║  Method: {self.cracking_method}
║  File: {os.path.basename(self.cap_file)}
╚══════════════════════════════════════════════════════════════════╝[/bold green]
"""
            console.print(result_text)
            self.save_results()
        else:
            console.print(Panel(
                "[yellow]Password not found with current wordlist[/yellow]\n"
                "[dim]Try:[/dim]\n"
                "[dim]  - Using a larger wordlist[/dim]\n"
                "[dim]  - Adding rules (-r best64.rule)[/dim]\n"
                "[dim]  - Mask attack with --mask[/dim]",
                title="[yellow]Cracking Failed[/yellow]",
                border_style="yellow"
            ))
    
    def crack(self, cap_file, wordlist=None, rules=None, method='auto', timeout=None):
        """Main cracking function"""
        
        # Validate input file
        if not os.path.exists(cap_file):
            console.print(f"[red][✗] File not found: {cap_file}[/red]")
            return False
        
        self.cap_file = cap_file
        
        # Convert to hashcat format
        if not self.convert_to_hashcat(cap_file):
            return False
        
        # Get wordlist
        wordlist = self.get_wordlist(wordlist)
        if not wordlist:
            console.print("[red][✗] No wordlist found![/red]")
            console.print("[yellow]Please install wordlists:[/yellow]")
            console.print("  sudo apt install wordlists")
            console.print("  sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
            return False
        
        # Check available tools
        tools = self.check_cracking_tools()
        
        # Choose method
        if method == 'auto':
            if tools['hashcat']:
                method = 'hashcat'
            elif tools['aircrack-ng']:
                method = 'aircrack'
            else:
                console.print("[red][✗] No cracking tools available![/red]")
                return False
        
        self.cracking_method = method
        
        # Execute cracking
        if method == 'hashcat' and tools['hashcat']:
            success = self.crack_with_hashcat(wordlist, rules, timeout)
        elif method == 'aircrack' and tools['aircrack-ng']:
            success = self.crack_with_aircrack(cap_file, wordlist)
        else:
            console.print(f"[red][✗] Method {method} not available[/red]")
            return False
        
        # Display result
        self.display_result()
        
        return success

class AdvancedCracker(HandshakeCracker):
    """Extended cracker with advanced features"""
    
    def __init__(self, config):
        super().__init__(config)
        self.rule_files = self.find_rule_files()
        # Dictionary of descriptions for Hashcat rules
        self.rule_descriptions = {
            "Incisive-leetspeak.rule": "Applies leetspeak transformations (e.g., e->3, a->@, s->$)",
            "InsidePro-HashManager.rule": "Alteration rules, reversals, and case toggling (PasswordsPro)",
            "InsidePro-PasswordsPro.rule": "Standard transformation set optimized for fast cracking",
            "T0XlC-insert_00-99_1950-2050_toprules_0_F.rule": "Injects numbers 00-99 and years 1950-2050 (dates/birthyears)",
            "T0XlC-insert_space_and_special_0_F.rule": "Inserts spaces and special characters/punctuation",
            "T0XlC-insert_top_100_passwords_1_G.rule": "Pads words by inserting the top 100 most common passwords",
            "T0XlC.rule": "Massive and aggressive set of advanced mutation rules",
            "T0XlC_3_rule.rule": "Streamlined version focused on fast rule combinations",
            "T0XlC_insert_HTML_entities_0_Z.rule": "Inserts HTML entities and web-derived special symbols",
            "T0XlCv2.rule": "Updated and revised version with modern, effective patterns"
        }
    
    def find_rule_files(self):
        """Find hashcat rule files"""
        rule_paths = [
            '/usr/share/hashcat/rules/',
            '/usr/share/hashcat/rules',
            './rules/'
        ]
        
        rules = []
        for path in rule_paths:
            if os.path.exists(path):
                for file in os.listdir(path):
                    if file.endswith('.rule'):
                        rules.append(os.path.join(path, file))
        
        return rules
    
    def list_available_wordlists(self):
        """List all available wordlists on the system"""
        wordlist_paths = [
            '/usr/share/wordlists/',
            '/usr/share/seclists/Passwords/',
            './wordlists/'
        ]
        
        wordlists = []
        for path in wordlist_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith('.txt') or file.endswith('.lst'):
                            full_path = os.path.join(root, file)
                            size = os.path.getsize(full_path) / (1024 * 1024)  # MB
                            wordlists.append({
                                'path': full_path,
                                'name': file,
                                'size': f"{size:.1f} MB"
                            })
        
        return wordlists
    
    def mask_attack(self, cap_file, mask='?d?d?d?d?d?d?d?d'):
        """Perform mask attack (brute force pattern)"""
        console.print(f"\n[bold cyan][*] Starting mask attack with pattern: {mask}[/bold cyan]")
        
        # Convert to hashcat format first
        if not self.convert_to_hashcat(cap_file):
            return False
        
        # Build mask attack command
        cmd = [
            'hashcat', '-m', '22000', '-a', '3',
            self.hash_file, mask,
            '--force', '--status', '--status-timer=1', '--potfile-path', '/tmp/hashcat.potfile'
        ]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            for line in process.stdout:
                line = line.strip()
                if 'Status' in line or 'Recovered' in line:
                    console.print(f"[cyan]{line}[/cyan]")
            
            process.wait()
            return self.check_hashcat_result()
            
        except Exception as e:
            console.print(f"[red][✗] Mask attack error: {e}[/red]")
            return False
    
    def show_statistics(self, cap_file):
        """Show handshake statistics"""
        console.print("\n[bold cyan][*] Handshake Statistics[/bold cyan]")
        
        try:
            # Mostra le informazioni di base del file e la dimensione
            file_size = os.path.getsize(cap_file) / 1024
            hash_file = cap_file.replace('.cap', '.hc22000')
            has_hash = os.path.exists(hash_file)
            
            info_text = f"Capture File: {os.path.basename(cap_file)}\n" \
                        f"Size: {file_size:.2f} KB\n" \
                        f"Hashcat Format (.hc22000): {'Available' if has_hash else 'Not generated'}\n"
            
            if has_hash:
                hash_size = os.path.getsize(hash_file)
                info_text += f"Hash File Size: {hash_size} bytes\n"
            
            console.print(Panel(info_text, title="[cyan]Capture Summary[/cyan]", border_style="cyan"))
                    
        except Exception as e:
            console.print(f"[red][✗] Could not parse statistics: {e}[/red]")