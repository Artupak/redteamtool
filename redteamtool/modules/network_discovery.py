from typing import List, Dict, Any
import nmap
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from core.base_module import BaseModule
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import ipaddress

class NetworkDiscoveryModule(BaseModule):
    def __init__(self, name: str, description: str):
        super().__init__(name, description or "Network reconnaissance and mapping module")
        self.author = "ARTUPAK"
        self.description = "Performs comprehensive network discovery and enumeration"
        self.options = {
            'target': {
                'value': None,
                'required': True,
                'description': 'Target network (CIDR notation) or hostname'
            },
            'scan_type': {
                'value': 'full',
                'required': False,
                'description': 'Type of scan (quick/full)'
            },
            'ports': {
                'value': '1-1000',
                'required': False,
                'description': 'Port range to scan'
            },
            'dns_lookup': {
                'value': True,
                'required': False,
                'description': 'Perform reverse DNS lookups'
            }
        }

    def get_required_options(self) -> List[str]:
        return ['target']

    def _perform_arp_scan(self, network: str) -> List[Dict[str, str]]:
        """Perform ARP scan to discover live hosts."""
        self.logger.info(f"Starting ARP scan on network {network}")
        
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            return devices
        except Exception as e:
            self.logger.error(f"Error during ARP scan: {str(e)}")
            return []

    def _perform_port_scan(self, target: str, ports: str) -> Dict[str, List[int]]:
        """Perform port scan using nmap."""
        self.logger.info(f"Starting port scan on target {target}")
        
        nm = nmap.PortScanner()
        try:
            nm.scan(target, ports, arguments='-sS -sV -n -Pn')
            results = {}
            for host in nm.all_hosts():
                open_ports = []
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': nm[host][proto][port]['name'],
                                'version': nm[host][proto][port]['version']
                            })
                results[host] = open_ports
            return results
        except Exception as e:
            self.logger.error(f"Error during port scan: {str(e)}")
            return {}

    def _perform_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            resolver = dns.resolver.Resolver()
            
            # Try to get additional DNS records
            records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = resolver.resolve(hostname, record_type)
                    records[record_type] = [str(answer) for answer in answers]
                except Exception:
                    continue
                    
            return {
                'hostname': hostname,
                'records': records
            }
        except Exception as e:
            self.logger.debug(f"DNS lookup failed for {ip}: {str(e)}")
            return {}

    def run(self) -> bool:
        """Execute network discovery module."""
        try:
            target = self.get_option('target')
            scan_type = self.get_option('scan_type', 'full')
            ports = self.get_option('ports', '1-1000')
            do_dns = self.get_option('dns_lookup', True)

            # Initialize results
            self.results = {
                'live_hosts': [],
                'port_scan': {},
                'dns_info': {}
            }

            # Determine if target is a network or single host
            try:
                network = ipaddress.ip_network(target)
                is_network = True
            except ValueError:
                is_network = False

            # Perform ARP scan if target is a network
            if is_network:
                self.logger.info("Performing ARP scan...")
                live_hosts = self._perform_arp_scan(str(network))
                self.results['live_hosts'] = live_hosts
                scan_targets = [host['ip'] for host in live_hosts]
            else:
                scan_targets = [target]

            # Perform port scan
            self.logger.info("Performing port scan...")
            for target_ip in scan_targets:
                port_results = self._perform_port_scan(target_ip, ports)
                self.results['port_scan'].update(port_results)

            # Perform DNS lookups if enabled
            if do_dns:
                self.logger.info("Performing DNS lookups...")
                with ThreadPoolExecutor(max_workers=10) as executor:
                    dns_results = {
                        ip: self._perform_dns_lookup(ip)
                        for ip in scan_targets
                    }
                    self.results['dns_info'] = dns_results

            return True

        except Exception as e:
            self.logger.error(f"Error during network discovery: {str(e)}")
            return False

    def cleanup(self) -> None:
        """Clean up any resources."""
        # Nothing to clean up for this module
        pass
