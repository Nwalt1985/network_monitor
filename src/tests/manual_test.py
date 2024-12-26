import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.network_security_monitor import NetworkSecurityMonitor
import time
from unittest.mock import patch, MagicMock

def get_mock_nmap_results(ip):
    """Return mock nmap scan results"""
    return {
        'scan': {
            ip: {
                'status': {'state': 'up'},
                'tcp': {
                    80: {
                        'state': 'open',
                        'name': 'http',
                        'version': 'nginx 1.18.0'
                    },
                    443: {
                        'state': 'open',
                        'name': 'https',
                        'version': 'nginx 1.18.0'
                    }
                },
                'osmatch': [
                    {
                        'name': 'Linux 4.15',
                        'accuracy': 95
                    }
                ]
            }
        }
    }

def get_mock_geo_results(ip):
    """Return mock geolocation results"""
    mock_data = {
        '8.8.8.8': {
            'country': 'United States',
            'city': 'Mountain View',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'org': 'Google LLC',
            'region': 'California',
            'postal_code': '94043',
            'timezone': 'America/Los_Angeles'
        },
        '1.1.1.1': {
            'country': 'Australia',
            'city': 'Brisbane',
            'latitude': -27.4766,
            'longitude': 153.0166,
            'org': 'Cloudflare Inc',
            'region': 'Queensland',
            'postal_code': '4101',
            'timezone': 'Australia/Brisbane'
        },
        '140.82.121.4': {
            'country': 'United States',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'org': 'GitHub, Inc.',
            'region': 'California',
            'postal_code': '94107',
            'timezone': 'America/Los_Angeles'
        }
    }
    return mock_data.get(ip, {})

def test_monitor():
    monitor = NetworkSecurityMonitor()
    
    # Test known IP addresses
    test_ips = [
        '8.8.8.8',      # Google DNS
        '1.1.1.1',      # Cloudflare DNS
        '140.82.121.4'  # GitHub
    ]
    
    print("Testing individual components...")
    
    # Mock both nmap scanner and geolocation
    with patch.object(monitor.nmap_scanner, 'scan') as mock_scan, \
         patch.object(monitor, 'get_detailed_geolocation') as mock_geo:
        
        # Configure mocks
        mock_scan.side_effect = lambda hosts, arguments: get_mock_nmap_results(hosts)
        mock_geo.side_effect = get_mock_geo_results
        
        for ip in test_ips:
            print(f"\nTesting IP: {ip}")
            
            print("1. Testing geolocation...")
            geo_result = monitor.get_detailed_geolocation(ip)
            print(f"Geolocation result: {geo_result}")
            
            print("\n2. Testing nmap scan...")
            nmap_result = monitor.perform_deep_nmap_scan(ip)
            print(f"Nmap result: {nmap_result}")
            
            print("\n3. Testing security analysis...")
            security_result = monitor.analyze_security_data(ip, nmap_result, geo_result)
            print(f"Security analysis result: {security_result}")
            
            # No need for sleep anymore since we're not making API calls
            # time.sleep(2)

if __name__ == "__main__":
    test_monitor()