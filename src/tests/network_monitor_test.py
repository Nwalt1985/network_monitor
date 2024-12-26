import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.network_security_monitor import NetworkSecurityMonitor
from unittest.mock import patch

class TestNetworkSecurityMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = NetworkSecurityMonitor()

    def tearDown(self):
        """Clean up resources after each test"""
        # Close MongoDB connection
        if hasattr(self, 'monitor') and hasattr(self.monitor, 'mongo_client'):
            self.monitor.mongo_client.close()
        
        # Close any logging handlers
        import logging
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)

        self.monitor.cleanup()

    def test_geolocation(self):
        """Test geolocation functionality with known IPs"""
        # Add retry logic or mock the API call
        mock_geo_data = {
            'country': 'US',
            'city': 'Mountain View'
        }
        with patch.object(self.monitor, 'get_detailed_geolocation', return_value=mock_geo_data):
            result = self.monitor.get_detailed_geolocation('8.8.8.8')
            self.assertIsInstance(result, dict)
            self.assertTrue('country' in result or 'city' in result)

    def test_nmap_scan(self):
        """Test nmap scanning with localhost"""
        # Mock the nmap scan to avoid requiring root privileges
        mock_scan_data = {
            'ip_address': '127.0.0.1',
            'open_ports': [
                {'port': 80, 'state': 'open', 'service': 'http'}
            ]
        }
        with patch.object(self.monitor, 'perform_deep_nmap_scan', return_value=mock_scan_data):
            result = self.monitor.perform_deep_nmap_scan('127.0.0.1')
            self.assertIsInstance(result, dict)
            self.assertTrue('ip_address' in result)
            self.assertTrue('open_ports' in result)

    def test_security_analysis(self):
        """Test security analysis logic"""
        nmap_data = {
            'open_ports': [
                {'port': 22, 'state': 'open', 'service': 'ssh'},
                {'port': 80, 'state': 'open', 'service': 'http'}
            ]
        }
        geo_data = {
            'country_code': 'US',
            'org': 'Some Organization'
        }
        
        result = self.monitor.analyze_security_data('8.8.8.8', nmap_data, geo_data)
        self.assertIsInstance(result, dict)
        self.assertTrue('threat_level' in result)
        self.assertTrue('security_risks' in result)

if __name__ == '__main__':
    unittest.main()