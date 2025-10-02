#!/usr/bin/env python3
"""
Ultimate IP Lookup Tool - The most comprehensive IP intelligence CLI
Features: Multi-source aggregation, security analysis, performance testing, export capabilities
"""

import requests
import json
import sys
import time
import socket
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import concurrent.futures
from urllib.parse import urlparse

# Try to import optional dependencies
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    from rich.tree import Tree
    from rich import box
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Install 'rich' for enhanced UI: pip install rich")

console = Console() if RICH_AVAILABLE else None


class IPLookup:
    """Advanced IP Lookup with multiple data sources and analysis"""
    
    def __init__(self, verbose=False, timeout=10):
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Ultimate-IP-Lookup-Tool/2.0'
        })
    
    def print_banner(self):
        """Display awesome ASCII banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗██████╗     ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗  ║
║   ██║██╔══██╗    ██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗ ║
║   ██║██████╔╝    ██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝ ║
║   ██║██╔═══╝     ██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝  ║
║   ██║██║         ███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║      ║
║   ╚═╝╚═╝         ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝      ║
║                                                               ║
║              Ultimate IP Intelligence & Analysis              ║
║                        v2.0.0 - 2025                         ║
╚═══════════════════════════════════════════════════════════════╝
        """
        if RICH_AVAILABLE:
            console.print(banner, style="bold cyan")
        else:
            print(banner)
    
    def get_public_ip(self) -> Optional[str]:
        """Get public IP with fallback sources"""
        sources = [
            'https://api.ipify.org?format=json',
            'https://api64.ipify.org?format=json',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ident.me'
        ]
        
        for source in sources:
            try:
                response = self.session.get(source, timeout=self.timeout)
                response.raise_for_status()
                
                if 'json' in source:
                    return response.json().get('ip')
                else:
                    return response.text.strip()
            except Exception as e:
                if self.verbose:
                    print(f"Failed to get IP from {source}: {e}")
                continue
        
        return None
    
    def get_ip_api_data(self, ip: str) -> Dict:
        """Get data from ip-api.com"""
        url = f'http://ip-api.com/json/{ip}?fields=66846719'
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_ipinfo_data(self, ip: str) -> Dict:
        """Get data from ipinfo.io"""
        url = f'https://ipinfo.io/{ip}/json'
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_ipwhois_data(self, ip: str) -> Dict:
        """Get WHOIS data from ipwhois.app"""
        url = f'https://ipwhois.app/json/{ip}'
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_abuse_ipdb_data(self, ip: str, api_key: Optional[str] = None) -> Dict:
        """Check IP reputation on AbuseIPDB (requires API key)"""
        if not api_key:
            return {'error': 'API key required'}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json().get('data', {})
        except Exception as e:
            return {'error': str(e)}
    
    def reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except socket.herror:
            return "No PTR record"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def ping_test(self, ip: str, count: int = 4) -> Dict:
        """Perform ping test (HTTP-based)"""
        results = []
        for _ in range(count):
            try:
                start = time.time()
                response = self.session.get(f'http://{ip}', timeout=2)
                latency = (time.time() - start) * 1000
                results.append(latency)
            except:
                results.append(None)
        
        valid_results = [r for r in results if r is not None]
        if valid_results:
            return {
                'sent': count,
                'received': len(valid_results),
                'lost': count - len(valid_results),
                'min': min(valid_results),
                'max': max(valid_results),
                'avg': sum(valid_results) / len(valid_results)
            }
        return {'error': 'All pings failed'}
    
    def check_ports(self, ip: str, ports: List[int] = None) -> Dict[int, bool]:
        """Check common ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        
        results = {}
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                result = sock.connect_ex((ip, port))
                results[port] = result == 0
            except:
                results[port] = False
            finally:
                sock.close()
        
        return results
    
    def aggregate_data(self, ip: str, abuse_api_key: Optional[str] = None) -> Dict:
        """Aggregate data from multiple sources"""
        aggregated = {'ip': ip, 'timestamp': datetime.now().isoformat()}
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Gathering intelligence...", total=None)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {
                        'ip_api': executor.submit(self.get_ip_api_data, ip),
                        'ipinfo': executor.submit(self.get_ipinfo_data, ip),
                        'ipwhois': executor.submit(self.get_ipwhois_data, ip),
                        'reverse_dns': executor.submit(self.reverse_dns_lookup, ip),
                    }
                    
                    if abuse_api_key:
                        futures['abuse_ipdb'] = executor.submit(self.get_abuse_ipdb_data, ip, abuse_api_key)
                    
                    for key, future in futures.items():
                        aggregated[key] = future.result()
        else:
            print("Gathering data from multiple sources...")
            aggregated['ip_api'] = self.get_ip_api_data(ip)
            aggregated['ipinfo'] = self.get_ipinfo_data(ip)
            aggregated['ipwhois'] = self.get_ipwhois_data(ip)
            aggregated['reverse_dns'] = self.reverse_dns_lookup(ip)
            
            if abuse_api_key:
                aggregated['abuse_ipdb'] = self.get_abuse_ipdb_data(ip, abuse_api_key)
        
        return aggregated
    
    def display_results(self, data: Dict, show_ports: bool = False, show_ping: bool = False):
        """Display results with rich formatting"""
        if not RICH_AVAILABLE:
            self._display_results_plain(data, show_ports, show_ping)
            return
        
        ip = data.get('ip')
        
        # Main Info Panel
        ip_api = data.get('ip_api', {})
        if ip_api.get('status') == 'success':
            info_text = f"""
[bold cyan]IP Address:[/bold cyan] {ip}
[bold cyan]Hostname:[/bold cyan] {data.get('reverse_dns', 'N/A')}
[bold cyan]Type:[/bold cyan] {ip_api.get('query', 'N/A')}

[bold yellow]📍 Location[/bold yellow]
  Country: {ip_api.get('country', 'N/A')} ({ip_api.get('countryCode', 'N/A')})
  Region: {ip_api.get('regionName', 'N/A')}
  City: {ip_api.get('city', 'N/A')}
  ZIP: {ip_api.get('zip', 'N/A')}
  Timezone: {ip_api.get('timezone', 'N/A')}
  Coordinates: {ip_api.get('lat', 'N/A')}, {ip_api.get('lon', 'N/A')}

[bold green]🌐 Network[/bold green]
  ISP: {ip_api.get('isp', 'N/A')}
  Organization: {ip_api.get('org', 'N/A')}
  AS: {ip_api.get('as', 'N/A')}
  Mobile: {ip_api.get('mobile', False)}
  Proxy: {ip_api.get('proxy', False)}
  Hosting: {ip_api.get('hosting', False)}
            """
            console.print(Panel(info_text, title="[bold]IP Intelligence Report[/bold]", border_style="cyan"))
        
        # Security Analysis
        abuse_data = data.get('abuse_ipdb', {})
        if abuse_data and 'error' not in abuse_data:
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            is_whitelisted = abuse_data.get('isWhitelisted', False)
            total_reports = abuse_data.get('totalReports', 0)
            
            if abuse_score > 75:
                risk_level = "[bold red]HIGH RISK ⚠️[/bold red]"
                style = "red"
            elif abuse_score > 25:
                risk_level = "[bold yellow]MODERATE RISK ⚡[/bold yellow]"
                style = "yellow"
            else:
                risk_level = "[bold green]LOW RISK ✓[/bold green]"
                style = "green"
            
            security_text = f"""
{risk_level}

Abuse Confidence Score: {abuse_score}%
Total Reports: {total_reports}
Whitelisted: {is_whitelisted}
Last Reported: {abuse_data.get('lastReportedAt', 'Never')}
            """
            console.print(Panel(security_text, title="[bold]🔒 Security Analysis[/bold]", border_style=style))
        
        # Additional Data Sources
        ipinfo = data.get('ipinfo', {})
        if ipinfo and 'error' not in ipinfo:
            table = Table(title="Additional Information", box=box.ROUNDED)
            table.add_column("Source", style="cyan")
            table.add_column("Data", style="white")
            
            if ipinfo.get('hostname'):
                table.add_row("IPInfo Hostname", ipinfo.get('hostname'))
            if ipinfo.get('org'):
                table.add_row("IPInfo Org", ipinfo.get('org'))
            if ipinfo.get('postal'):
                table.add_row("Postal Code", ipinfo.get('postal'))
            
            console.print(table)
        
        # Port Scan Results
        if show_ports:
            ip_str = data.get('ip')
            if ip_str:
                console.print("\n[bold cyan]Scanning common ports...[/bold cyan]")
                ports = self.check_ports(ip_str)
                
                port_table = Table(title="🔍 Port Scan Results", box=box.ROUNDED)
                port_table.add_column("Port", style="cyan")
                port_table.add_column("Service", style="yellow")
                port_table.add_column("Status", style="white")
                
                port_services = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
                    5432: "PostgreSQL", 8080: "HTTP-Alt"
                }
                
                for port, is_open in ports.items():
                    service = port_services.get(port, "Unknown")
                    status = "[green]OPEN[/green]" if is_open else "[red]CLOSED[/red]"
                    port_table.add_row(str(port), service, status)
                
                console.print(port_table)
        
        # Ping Test
        if show_ping:
            ip_str = data.get('ip')
            if ip_str:
                console.print("\n[bold cyan]Performing connectivity test...[/bold cyan]")
                ping_results = self.ping_test(ip_str)
                
                if 'error' not in ping_results:
                    ping_text = f"""
Packets: Sent = {ping_results['sent']}, Received = {ping_results['received']}, Lost = {ping_results['lost']}
Approximate round trip times:
  Minimum = {ping_results['min']:.2f}ms
  Maximum = {ping_results['max']:.2f}ms
  Average = {ping_results['avg']:.2f}ms
                    """
                    console.print(Panel(ping_text, title="[bold]📡 Connectivity Test[/bold]", border_style="green"))
    
    def _display_results_plain(self, data: Dict, show_ports: bool, show_ping: bool):
        """Display results in plain text format"""
        print("\n" + "="*60)
        print("IP INTELLIGENCE REPORT")
        print("="*60)
        
        ip_api = data.get('ip_api', {})
        if ip_api.get('status') == 'success':
            print(f"\nIP Address: {data.get('ip')}")
            print(f"Hostname: {data.get('reverse_dns', 'N/A')}")
            print(f"\n📍 LOCATION")
            print(f"  Country: {ip_api.get('country')} ({ip_api.get('countryCode')})")
            print(f"  Region: {ip_api.get('regionName')}")
            print(f"  City: {ip_api.get('city')}")
            print(f"  ZIP: {ip_api.get('zip')}")
            print(f"  Timezone: {ip_api.get('timezone')}")
            print(f"  Coordinates: {ip_api.get('lat')}, {ip_api.get('lon')}")
            
            print(f"\n🌐 NETWORK")
            print(f"  ISP: {ip_api.get('isp')}")
            print(f"  Organization: {ip_api.get('org')}")
            print(f"  AS: {ip_api.get('as')}")
        
        if show_ports:
            print("\n🔍 PORT SCAN")
            ports = self.check_ports(data.get('ip'))
            for port, is_open in ports.items():
                status = "OPEN" if is_open else "CLOSED"
                print(f"  Port {port}: {status}")
        
        if show_ping:
            print("\n📡 CONNECTIVITY TEST")
            ping_results = self.ping_test(data.get('ip'))
            if 'error' not in ping_results:
                print(f"  Sent: {ping_results['sent']}, Received: {ping_results['received']}")
                print(f"  Avg latency: {ping_results['avg']:.2f}ms")
        
        print("\n" + "="*60)
    
    def export_json(self, data: Dict, filename: str):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Data exported to {filename}")
    
    def export_csv(self, data: Dict, filename: str):
        """Export results to CSV"""
        import csv
        
        ip_api = data.get('ip_api', {})
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Field', 'Value'])
            writer.writerow(['IP', data.get('ip')])
            writer.writerow(['Hostname', data.get('reverse_dns')])
            writer.writerow(['Country', ip_api.get('country')])
            writer.writerow(['City', ip_api.get('city')])
            writer.writerow(['ISP', ip_api.get('isp')])
            writer.writerow(['Latitude', ip_api.get('lat')])
            writer.writerow(['Longitude', ip_api.get('lon')])
        
        print(f"✓ Data exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Ultimate IP Lookup Tool - Comprehensive IP Intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('ip', nargs='?', help='IP address to lookup (leave empty for your public IP)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-p', '--ports', action='store_true', help='Scan common ports')
    parser.add_argument('-t', '--ping', action='store_true', help='Perform ping test')
    parser.add_argument('-a', '--abuse-key', help='AbuseIPDB API key for security analysis')
    parser.add_argument('-e', '--export', choices=['json', 'csv'], help='Export format')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    
    args = parser.parse_args()
    
    lookup = IPLookup(verbose=args.verbose, timeout=args.timeout)
    
    if not args.no_banner:
        lookup.print_banner()
    
    # Get IP address
    if args.ip:
        ip = args.ip
        if RICH_AVAILABLE:
            console.print(f"\n[bold cyan]Analyzing IP:[/bold cyan] {ip}\n")
        else:
            print(f"\nAnalyzing IP: {ip}\n")
    else:
        if RICH_AVAILABLE:
            with Progress(SpinnerColumn(), TextColumn("[cyan]Detecting your public IP..."), console=console) as progress:
                progress.add_task("", total=None)
                ip = lookup.get_public_ip()
        else:
            print("Detecting your public IP...")
            ip = lookup.get_public_ip()
        
        if not ip:
            print("❌ Failed to detect public IP address")
            sys.exit(1)
        
        if RICH_AVAILABLE:
            console.print(f"\n[bold green]✓ Your Public IP:[/bold green] {ip}\n")
        else:
            print(f"\n✓ Your Public IP: {ip}\n")
    
    # Gather and display data
    data = lookup.aggregate_data(ip, args.abuse_key)
    lookup.display_results(data, show_ports=args.ports, show_ping=args.ping)
    
    # Export if requested
    if args.export:
        output_file = args.output or f"ip_lookup_{ip.replace('.', '_')}_{int(time.time())}.{args.export}"
        if args.export == 'json':
            lookup.export_json(data, output_file)
        elif args.export == 'csv':
            lookup.export_csv(data, output_file)
    
    if RICH_AVAILABLE:
        console.print("\n[dim]Thank you for using Ultimate IP Lookup Tool![/dim]")


if __name__ == "__main__":
    main()