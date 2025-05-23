from core.base_module import BaseModule
import nmap
from typing import Dict, Any
from rich.progress import Progress
import socket
import concurrent.futures
from datetime import datetime

class NetworkDiscoveryModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "NetworkDiscovery"
        self.description = "Performs network reconnaissance using Nmap and custom port scanning"
        self.author = "ARTUPAK"
        self.references = [
            "https://nmap.org/book/man.html",
            "https://attack.mitre.org/techniques/T1046/"
        ]
        
        # Define module options
        self.options = {
            'target': {
                'value': None,
                'required': True,
                'description': 'Target IP address or network range (e.g. 192.168.1.0/24)'
            },
            'ports': {
                'value': '1-1000',
                'required': False,
                'description': 'Port range to scan'
            },
            'scan_type': {
                'value': 'syn',
                'required': False,
                'description': 'Scan type (syn/tcp/udp)'
            }
        }

    def run(self, target: str, **kwargs) -> bool:
        """
        Execute the network discovery module.
        """
        try:
            # Set target
            self.set_option('target', target)
            
            # Update options from kwargs
            for key, value in kwargs.items():
                if key in self.options:
                    self.set_option(key, value)

            # Validate options
            if not self.validate_options():
                return False

            # Start module execution
            self.pre_run()

            # Perform network scanning
            with Progress() as progress:
                task1 = progress.add_task("[cyan]Running Nmap scan...", total=100)
                nmap_results = self._run_nmap_scan()
                progress.update(task1, completed=100)

                task2 = progress.add_task("[cyan]Running custom port scan...", total=100)
                custom_results = self._run_custom_scan()
                progress.update(task2, completed=100)

            # Combine and store results
            self.results = {
                'nmap_scan': nmap_results,
                'custom_scan': custom_results,
                'timestamp': datetime.now().isoformat()
            }

            # Save results
            self.save_results()
            
            # Cleanup
            self.post_run()
            
            return True

        except Exception as e:
            self.add_result('error', str(e))
            return False

    def _run_nmap_scan(self) -> Dict[str, Any]:
        """
        Perform Nmap scan on target.
        """
        nm = nmap.PortScanner()
        target = self.get_option('target')
        ports = self.get_option('ports')
        scan_type = self.get_option('scan_type')

        # Configure scan arguments
        args = f'-p{ports} '
        if scan_type == 'syn':
            args += '-sS'
        elif scan_type == 'udp':
            args += '-sU'
        else:
            args += '-sT'

        # Run scan
        nm.scan(target, arguments=args)
        
        results = {}
        for host in nm.all_hosts():
            results[host] = {
                'state': nm[host].state(),
                'protocols': {}
            }
            
            for proto in nm[host].all_protocols():
                results[host]['protocols'][proto] = {}
                ports = nm[host][proto].keys()
                
                for port in ports:
                    results[host]['protocols'][proto][port] = {
                        'state': nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port].get('version', '')
                    }

        return results

    def _run_custom_scan(self) -> Dict[str, Any]:
        """
        Perform custom TCP connect scan.
        """
        target = self.get_option('target')
        ports = self.get_option('ports')
        
        # Parse port range
        if '-' in ports:
            start_port, end_port = map(int, ports.split('-'))
            port_list = range(start_port, end_port + 1)
        else:
            port_list = map(int, ports.split(','))

        results = {}
        
        def scan_port(port: int) -> Dict[str, Any]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                    
                return {
                    'port': port,
                    'state': 'open',
                    'service': service
                }
            return None

        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in port_list}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results[result['port']] = {
                        'state': result['state'],
                        'service': result['service']
                    }

        return results 