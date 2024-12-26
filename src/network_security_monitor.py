import warnings
warnings.filterwarnings('ignore')

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import urllib3
warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)

import psutil
import requests
import logging
from datetime import datetime, timedelta
import pymongo
from typing import Dict, Any, List
import time
import ipaddress
import os
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import tabulate

class NetworkSecurityMonitor:
    def __init__(self, mongodb_uri: str = 'mongodb://localhost:27017/'):
        """
        Consolidated Network Security Monitor
        Combines intrusion detection, geolocation tracking, and Nmap scanning
        
        :param mongodb_uri: MongoDB connection URI
        """
        # Store MongoDB URI
        self.mongodb_uri = mongodb_uri
        
        # Initialize colorama for cross-platform colored output
        init()
        # MongoDB Connection
        self.mongo_client = pymongo.MongoClient(mongodb_uri)
        self.db = self.mongo_client['network_monitor']
        # Single collection for all security events
        self.security_events = self.db['security_events']

        # Create indexes for efficient querying
        self.security_events.create_index([
            ('timestamp', pymongo.DESCENDING),
            ('ip_address', pymongo.ASCENDING),
            ('security_analysis.threat_level', pymongo.ASCENDING)
        ])

        # Logging setup
        self._file_handler = logging.FileHandler('network_security.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                self._file_handler,
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Initialize Nmap scanner with error handling
        try:
            self.nmap_scanner = nmap.PortScanner()
        except nmap.PortScannerError:
            self.logger.error("Nmap not found. Please install nmap using 'brew install nmap' on macOS")
            raise SystemExit("Nmap installation required. Exiting...")

        # Tracked connections
        self.known_connections = set()

        # VPN Detection Lists
        self.vpn_indicator_keywords = [
            'vpn', 'tunnel', 'private', 'secure', 'proxy', 
            'anonymizer', 'cloudflare', 'tor', 'nordvpn'
        ]

        # Add API rate limiting
        self.last_api_call = {}
        self.api_rate_limit = {
            'ipapi.co': 1,    # 1 second between calls
            'ipinfo.io': 1    # 1 second between calls
        }

    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'mongo_client'):
            self.mongo_client.close()
        if hasattr(self, '_file_handler'):
            self._file_handler.close()

    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()

    def get_detailed_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Retrieve comprehensive geolocation information"""
        try:
            apis = [
                ('ipapi.co', f'https://ipapi.co/{ip_address}/json/'),
                ('ipinfo.io', f'https://ipinfo.io/{ip_address}/json')
            ]
            
            geolocation_data = {}
            current_time = time.time()
            
            for api_name, api_url in apis:
                # Check if we need to wait due to rate limiting
                if api_name in self.last_api_call:
                    time_since_last_call = current_time - self.last_api_call[api_name]
                    if time_since_last_call < self.api_rate_limit[api_name]:
                        time.sleep(self.api_rate_limit[api_name] - time_since_last_call)
                
                try:
                    response = requests.get(api_url)
                    self.last_api_call[api_name] = time.time()
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        if api_name == 'ipapi.co':
                            geolocation_data.update({
                                'country': data.get('country_name'),
                                'city': data.get('city'),
                                'latitude': data.get('latitude'),
                                'longitude': data.get('longitude'),
                                'org': data.get('org'),
                                'region': data.get('region')
                            })
                        else:  # ipinfo.io
                            geolocation_data.update({
                                'postal_code': data.get('postal'),
                                'timezone': data.get('timezone')
                            })
                except Exception as e:
                    self.logger.warning(f"API request error for {api_name}: {str(e)}")
            
            return geolocation_data
            
        except Exception as e:
            self.logger.error(f"Geolocation error for {ip_address}: {str(e)}")
            return {}

    def perform_deep_nmap_scan(self, ip_address: str) -> Dict[str, Any]:
        """Perform comprehensive Nmap scan"""
        try:
            print(f"\n{Fore.CYAN}Starting Nmap scan for {ip_address}...{Style.RESET_ALL}")
            print("[" + " " * 50 + "]", end="\r")
            
            # Remove the -oX parameter since it's causing issues
            scan_arguments = '-sV -sC -O -p- --max-retries 3 --reason'
            
            # Start the scan
            scan_results = self.nmap_scanner.scan(
                hosts=ip_address, 
                arguments=scan_arguments
            )
            
            # Show completed progress bar
            print("[" + "=" * 50 + "]")
            
            if not scan_results.get('scan') or ip_address not in scan_results.get('scan', {}):
                return {
                    'ip_address': ip_address,
                    'scan_error': 'No scan results available'
                }
            
            detailed_results = {
                'ip_address': ip_address,
                'timestamp': datetime.now(),
                'host_status': scan_results['scan'][ip_address].get('status', {}).get('state', 'unknown'),
                'open_ports': [],
                'os_detection': []
            }
            
            # Process ports and OS detection
            if 'tcp' in scan_results['scan'][ip_address]:
                for port, port_info in scan_results['scan'][ip_address]['tcp'].items():
                    detailed_results['open_ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', '')
                    })
            
            if 'osmatch' in scan_results['scan'][ip_address]:
                detailed_results['os_detection'] = [
                    {
                        'name': match.get('name', 'Unknown'),
                        'accuracy': match.get('accuracy', 0)
                    } for match in scan_results['scan'][ip_address]['osmatch']
                ]
            
            return detailed_results
        
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {ip_address}: {str(e)}")
            return {'ip_address': ip_address, 'scan_error': str(e)}

    def analyze_security_data(self, 
                            geo_data: Dict[str, Any],
                            nmap_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Consolidated security analysis"""
        threat_score = 0
        security_risks = []

        # Analyze geolocation first
        risk_countries = ['RU', 'CN', 'IR', 'KP', 'SY']
        if geo_data.get('country_code') in risk_countries:
            threat_score += 3
            security_risks.append("High-risk country origin")

        # VPN/Proxy detection
        if any(keyword in geo_data.get('org', '').lower() 
               for keyword in self.vpn_indicator_keywords):
            threat_score += 2
            security_risks.append("Potential VPN/Proxy detected")

        # Initial threat classification before Nmap
        initial_threat_level = 'HIGH' if threat_score > 5 else 'MEDIUM' if threat_score > 2 else 'LOW'

        # Only analyze Nmap results if they exist (for HIGH threat level)
        if nmap_data:
            suspicious_ports = [21, 22, 23, 3389, 5900, 8080, 6667]
            open_suspicious_ports = [
                port for port in nmap_data.get('open_ports', [])
                if port['port'] in suspicious_ports
            ]
            
            if open_suspicious_ports:
                threat_score += len(open_suspicious_ports) * 2
                security_risks.extend([
                    f"Suspicious port: {port['port']}" 
                    for port in open_suspicious_ports
                ])

        # Final threat classification
        threat_level = 'HIGH' if threat_score > 5 else 'MEDIUM' if threat_score > 2 else 'LOW'

        return {
            'threat_score': threat_score,
            'threat_level': threat_level,
            'security_risks': security_risks,
            'initial_threat_level': initial_threat_level
        }

    def display_monitoring_stats(self, security_event: Dict[str, Any]) -> None:
        """
        Display formatted monitoring statistics with color coding
        """
        try:
            # Clear screen (optional)
            print("\033[H\033[J")
            
            # Header
            print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
            print(f"║ Network Security Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ║")
            print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")

            # Connection Details
            print(f"{Fore.YELLOW} Connection Details:{Style.RESET_ALL}")
            conn_details = security_event['connection_details']
            conn_table = [
                ["IP Address", conn_details['ip_address']],
                ["Port", conn_details['port']],
                ["Status", conn_details['status']],
                ["Protocol", conn_details['protocol']],
                ["Process ID", conn_details['process_id']]
            ]
            print(tabulate.tabulate(conn_table, tablefmt="simple"))

            # Geolocation Information
            print(f"\n{Fore.YELLOW}🌍 Geolocation Information:{Style.RESET_ALL}")
            geo = security_event['geolocation']
            geo_table = [
                ["Country", geo.get('country', 'Unknown')],
                ["City", geo.get('city', 'Unknown')],
                ["Region", geo.get('region', 'Unknown')],
                ["Organization", geo.get('organization', 'Unknown')],
                ["Coordinates", f"{geo.get('coordinates', {}).get('latitude', 'N/A')}, "
                              f"{geo.get('coordinates', {}).get('longitude', 'N/A')}"]
            ]
            print(tabulate.tabulate(geo_table, tablefmt="simple"))

            # Security Analysis
            security = security_event['security_analysis']
            threat_level = security['threat_level']
            threat_color = {
                'LOW': Fore.GREEN,
                'MEDIUM': Fore.YELLOW,
                'HIGH': Fore.RED
            }.get(threat_level, Fore.WHITE)
            
            print(f"\n{Fore.YELLOW}🔒 Security Analysis:{Style.RESET_ALL}")
            print(f"Threat Level: {threat_color}{threat_level}{Style.RESET_ALL}")
            print(f"Threat Score: {security['threat_score']}")
            
            if security['security_risks']:
                print("\nIdentified Risks:")
                for risk in security['security_risks']:
                    print(f"  • {Fore.RED}{risk}{Style.RESET_ALL}")

            # Open Ports
            print(f"\n{Fore.YELLOW}🔌 Open Ports:{Style.RESET_ALL}")
            if security_event['nmap_scan']['open_ports']:
                ports_table = []
                for port in security_event['nmap_scan']['open_ports']:
                    ports_table.append([
                        port['port'],
                        port['service'],
                        port['version'],
                        port['state']
                    ])
                print(tabulate.tabulate(
                    ports_table,
                    headers=['Port', 'Service', 'Version', 'State'],
                    tablefmt="simple"
                ))
            else:
                print("No open ports detected")

            # VPN Indicators
            print(f"\n{Fore.YELLOW}🔐 VPN Indicators:{Style.RESET_ALL}")
            vpn_indicators = security['vpn_indicators']
            if vpn_indicators:
                print(f"{Fore.RED}VPN/Proxy detected:{Style.RESET_ALL}")
                for indicator in vpn_indicators:
                    print(f"  • {indicator}")
            else:
                print(f"{Fore.GREEN}No VPN/Proxy indicators detected{Style.RESET_ALL}")

            print(f"\n{Fore.CYAN}════════════════════════════════════════════════{Style.RESET_ALL}")

        except Exception as e:
            self.logger.error(f"Error displaying monitoring stats: {str(e)}")
            print(f"{Fore.RED}Error displaying monitoring statistics{Style.RESET_ALL}")

    def monitor_connections(self, interface: str = None):
        """Main monitoring loop"""
        # Check for root privileges at start
        if os.geteuid() != 0:
            self.logger.error(
                "Root privileges required to monitor network connections.\n"
                "Please run the script with sudo, e.g.:\n"
                "sudo python3 network_security_monitor.py"
            )
            raise SystemExit("Root privileges required. Exiting...")

        print(f"\n{Fore.CYAN}Monitoring network traffic on {interface}...{Style.RESET_ALL}\n")

        while True:
            try:
                connections = psutil.net_connections()
                
                for conn in connections:
                    # Skip connections not on the selected interface if specified
                    if interface and hasattr(conn, 'interface') and conn.interface != interface:
                        continue
                        
                    if conn.status == psutil.CONN_ESTABLISHED:
                        remote_address = conn.raddr.ip if conn.raddr else None
                        remote_port = conn.raddr.port if conn.raddr else None
                        
                        if not remote_address or ipaddress.ip_address(remote_address).is_private:
                            continue
                        
                        try:
                            # First get geolocation and do initial analysis
                            geo_results = self.get_detailed_geolocation(remote_address)
                            initial_security_analysis = self.analyze_security_data(
                                geo_results
                            )
                            
                            # Only perform Nmap scan if initial threat level is HIGH
                            nmap_results = None
                            if initial_security_analysis['initial_threat_level'] == 'HIGH':
                                nmap_results = self.perform_deep_nmap_scan(remote_address)
                                # Update security analysis with Nmap results
                                security_analysis = self.analyze_security_data(
                                    geo_results, nmap_results
                                )
                            else:
                                security_analysis = initial_security_analysis
                                nmap_results = {
                                    'timestamp': datetime.now(),
                                    'host_status': 'not_scanned',
                                    'open_ports': [],
                                    'os_detection': [],
                                    'scan_error': None
                                }

                            # Create unified security event document
                            security_event = {
                                'timestamp': datetime.now(),
                                'event_type': 'connection_detected',
                                'connection_details': {
                                    'ip_address': remote_address,
                                    'port': remote_port,
                                    'status': 'ESTABLISHED',
                                    'protocol': 'TCP',  # Could be enhanced to detect UDP
                                    'process_id': conn.pid if hasattr(conn, 'pid') else None
                                },
                                'geolocation': {
                                    'country': geo_results.get('country'),
                                    'city': geo_results.get('city'),
                                    'coordinates': {
                                        'latitude': geo_results.get('latitude'),
                                        'longitude': geo_results.get('longitude')
                                    },
                                    'organization': geo_results.get('org'),
                                    'region': geo_results.get('region'),
                                    'timezone': geo_results.get('timezone'),
                                    'postal_code': geo_results.get('postal_code')
                                },
                                'nmap_scan': {
                                    'timestamp': nmap_results.get('timestamp'),
                                    'host_status': nmap_results.get('host_status'),
                                    'open_ports': nmap_results.get('open_ports', []),
                                    'os_detection': nmap_results.get('os_detection', []),
                                    'scan_errors': nmap_results.get('scan_error')
                                },
                                'security_analysis': {
                                    'threat_level': security_analysis.get('threat_level'),
                                    'threat_score': security_analysis.get('threat_score'),
                                    'security_risks': security_analysis.get('security_risks', []),
                                    'vpn_indicators': [
                                        keyword for keyword in self.vpn_indicator_keywords
                                        if keyword in geo_results.get('org', '').lower()
                                    ]
                                },
                                'metadata': {
                                    'monitor_version': '1.0',
                                    'detection_method': 'active_monitoring',
                                    'analysis_modules': ['nmap', 'geolocation', 'security_analysis']
                                }
                            }
                            
                            # Only store and log medium to high threats
                            if security_analysis['threat_level'] in ['MEDIUM', 'HIGH']:
                                # Log significant threats
                                self.logger.warning(
                                    f"SECURITY ALERT:\n"
                                    f"IP: {remote_address}\n"
                                    f"Threat Level: {security_analysis['threat_level']}\n"
                                    f"Risks: {', '.join(security_analysis['security_risks'])}\n"
                                    f"Location: {geo_results.get('country')}, {geo_results.get('city')}"
                                )
                                
                                # Store comprehensive data
                                self.security_events.insert_one(security_event)
                                
                                # Display the monitoring stats
                                self.display_monitoring_stats(security_event)
                        
                        except Exception:
                            import traceback
                            self.logger.error(f"Error processing connection {remote_address}:{remote_port} "
                                            f"(pid={conn.pid}):\n{traceback.format_exc()}")
                            continue
            
            except psutil.AccessDenied as e:
                self.logger.error(
                    "Access denied when trying to monitor connections. "
                    "Please run with sudo privileges."
                )
                raise SystemExit("Access denied. Exiting...")
                
            except Exception as e:
                import traceback
                self.logger.error(f"Monitoring error: {str(e)}\n"
                                f"Traceback:\n{traceback.format_exc()}")
                time.sleep(1)
            
            time.sleep(5)

    def display_live_stats(self, previous_stats=None):
        """Display live network and system statistics"""
        net_io = psutil.net_io_counters()
        current_time = time.time()
        
        # Get CPU and memory info
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used = memory.used / (1024 * 1024 * 1024)
        memory_total = memory.total / (1024 * 1024 * 1024)
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used = disk.used / (1024 * 1024 * 1024)
        disk_total = disk.total / (1024 * 1024 * 1024)
        
        # Get CPU temperature
        try:
            temps = psutil.sensors_temperatures()
            cpu_temp = temps['coretemp'][0].current if temps and 'coretemp' in temps else None
        except (AttributeError, KeyError):
            cpu_temp = None

        if previous_stats:
            time_delta = current_time - previous_stats['time']
            bytes_sent_sec = (net_io.bytes_sent - previous_stats['bytes_sent']) / time_delta
            bytes_recv_sec = (net_io.bytes_recv - previous_stats['bytes_recv']) / time_delta
            
            # Move cursor up to first stat line (8 lines up)
            print('\033[8A', end='')
            
            # Update only the values, keeping headers in place
            print(f"\r  • Transfer Rate ↑: {bytes_sent_sec / 1024 / 1024:>6.2f} MB/s\033[K")
            print(f"  • Transfer Rate ↓: {bytes_recv_sec / 1024 / 1024:>6.2f} MB/s\033[K")
            print(f"  • Total Sent    : {net_io.bytes_sent / 1024 / 1024:>6.2f} MB\033[K")
            print(f"  • Total Received: {net_io.bytes_recv / 1024 / 1024:>6.2f} MB\033[K")
            
            # Update System Stats
            print(f"  • CPU Usage     : {cpu_percent:>6.1f}%\033[K")
            print(f"  • Memory Usage  : {memory_percent:>6.1f}% ({memory_used:.1f}GB / {memory_total:.1f}GB)\033[K")
            print(f"  • Disk Usage    : {disk_percent:>6.1f}% ({disk_used:.1f}GB / {disk_total:.1f}GB)\033[K")
            print(f"  • CPU Temp      : {cpu_temp:>6.1f}°C\033[K" if cpu_temp else f"  • CPU Temp      : N/A\033[K")
        
        return {
            'time': current_time,
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }

    def display_network_info(self, selected_interface: str):
        """Display information about the network being monitored"""
        try:
            print(f"\n{Fore.CYAN}═══════════════════════════════════════════")
            print(f"║     Network Security Monitor Started     ║")
            print(f"══════════════════════════════════════════════{Style.RESET_ALL}\n")

            # Get active connections
            connections = psutil.net_connections()
            active_ports = set(conn.laddr.port for conn in connections if conn.laddr)
            
            # Show port count and get user input
            print(f"{Fore.YELLOW}Active Ports:{Style.RESET_ALL}")
            port_count = len(active_ports)
            print(f"  • {port_count} active ports detected")
            
            if port_count > 0:
                show_ports = input(f"\n{Fore.CYAN}Would you like to see the list of active ports? (y/N): {Style.RESET_ALL}").lower()
                if show_ports == 'y':
                    print(f"\n{Fore.YELLOW}Active Ports List:{Style.RESET_ALL}")
                    for port in sorted(active_ports):
                        print(f"  • {port}")

            # After user input, show the detailed information
            print("\n" + "=" * 50)  # Separator
            
            # Display all monitoring information
            print(f"\n{Fore.YELLOW}Selected Interface:{Style.RESET_ALL}")
            addrs = psutil.net_if_addrs()[selected_interface]
            print(f"\n► {Fore.GREEN}{selected_interface}{Style.RESET_ALL}")
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    print(f"  • IPv4: {addr.address}")
                elif addr.family == 30:  # AF_INET6 (IPv6)
                    print(f"  • IPv6: {addr.address}")

            print(f"\n{Fore.YELLOW}Monitor Settings:{Style.RESET_ALL}")
            print(f"  • Database: MongoDB ({self.mongodb_uri})")
            print(f"  • Log File: network_security.log")
            print(f"  • Scan Mode: {'Active' if os.geteuid() == 0 else 'Limited'}")

            print(f"\n{Fore.YELLOW}Network Statistics:{Style.RESET_ALL}")

            print(f"\n{Fore.CYAN}═══════════════════════════════════════════")
            print(f"║        Starting Network Monitoring       ║")
            print(f"═══════════════════════════════════════════{Style.RESET_ALL}")

            # Start live stats updates
            previous_stats = None
            try:
                while True:
                    previous_stats = self.display_live_stats(previous_stats)
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nContinuing with network monitoring...")

        except Exception as e:
            self.logger.error(f"Error displaying network information: {str(e)}")

    def select_interface(self) -> str:
        """Allow user to select network interface to monitor"""
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        print(f"\n{Fore.YELLOW}Available Network Interfaces:{Style.RESET_ALL}")
        interface_list = list(interfaces.keys())
        
        # Find default interface (first 'en' interface that's up)
        default_idx = 0
        for idx, interface in enumerate(interface_list):
            if interface.startswith("en") and stats[interface].isup:
                default_idx = idx
                break
        
        for idx, interface in enumerate(interface_list, 1):
            # Get interface status
            is_up = stats[interface].isup
            status_color = Fore.GREEN if is_up else Fore.RED
            status = "UP" if is_up else "DOWN"
            
            # Get interface description
            description = ""
            if interface.startswith("en"):
                description = "Ethernet/WiFi Interface"
            elif interface.startswith("lo"):
                description = "Loopback Interface (Local)"
            elif interface.startswith("utun") or interface.startswith("tun"):
                description = "VPN/Tunnel Interface"
            elif interface.startswith("bridge"):
                description = "Network Bridge"
            elif interface.startswith("awdl"):
                description = "Apple Wireless Direct Link"
            elif interface.startswith("llw"):
                description = "Low Latency WLAN Interface"
            
            # Mark default interface
            default_marker = f" {Fore.CYAN}(default){Style.RESET_ALL}" if idx-1 == default_idx else ""
            print(f"\n{idx}. {Fore.GREEN}{interface}{Style.RESET_ALL}{default_marker}")
            print(f"   • Description: {description}")
            print(f"   • Status: {status_color}{status}{Style.RESET_ALL}")
            
            for addr in interfaces[interface]:
                if addr.family == 2:  # AF_INET (IPv4)
                    print(f"   • IPv4: {addr.address}")
                elif addr.family == 30:  # AF_INET6 (IPv6)
                    print(f"   • IPv6: {addr.address}")
        
        while True:
            try:
                choice = input(f"\n{Fore.CYAN}Select interface to monitor (1-{len(interface_list)}) [{default_idx + 1}]: {Style.RESET_ALL}")
                if not choice:  # User pressed enter, use default
                    idx = default_idx
                else:
                    idx = int(choice) - 1
                if 0 <= idx < len(interface_list):
                    selected = interface_list[idx]
                    print(f"\n{Fore.GREEN}Selected interface: {selected}{Style.RESET_ALL}")
                    return selected
                else:
                    print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

def main():
    monitor = NetworkSecurityMonitor()
    try:
        interface = monitor.select_interface()
        monitor.display_network_info(interface)
        monitor.monitor_connections(interface)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()