from typing import List, Dict, Any
import paramiko
import os
import json
from pathlib import Path
from core.base_module import BaseModule
import subprocess
import pwd
import grp
from datetime import datetime

class LinuxPrivescModule(BaseModule):
    def __init__(self, name: str, description: str):
        super().__init__(name, description or "Linux privilege escalation module")
        self.author = "ARTUPAK"
        self.description = "Performs comprehensive Linux privilege escalation checks and exploits"
        self.options = {
            'target': {
                'value': None,
                'required': True,
                'description': 'Target host (ssh://user@host:port)'
            },
            'password': {
                'value': None,
                'required': False,
                'description': 'SSH password (if not using key-based auth)'
            },
            'key_file': {
                'value': None,
                'required': False,
                'description': 'SSH private key file'
            },
            'techniques': {
                'value': ['all'],
                'required': False,
                'description': 'Specific techniques to try (comma-separated)'
            },
            'timeout': {
                'value': 30,
                'required': False,
                'description': 'Timeout for operations in seconds'
            }
        }
        
        # Define privilege escalation techniques
        self.techniques = {
            'suid_binaries': self._check_suid_binaries,
            'sudo_rights': self._check_sudo_rights,
            'cron_jobs': self._check_cron_jobs,
            'weak_permissions': self._check_weak_permissions,
            'kernel_exploits': self._check_kernel_exploits,
            'docker_escape': self._check_docker_escape,
            'capabilities': self._check_capabilities,
            'path_hijacking': self._check_path_hijacking,
            'ld_preload': self._check_ld_preload,
            'world_writable': self._check_world_writable
        }

    def get_required_options(self) -> List[str]:
        return ['target']

    def _parse_ssh_url(self, url: str) -> Dict[str, Any]:
        """Parse SSH URL into components."""
        # Format: ssh://user@host:port
        try:
            if not url.startswith('ssh://'):
                raise ValueError("URL must start with ssh://")
            
            url = url[6:]  # Remove ssh://
            user_host = url.split('@')
            if len(user_host) != 2:
                raise ValueError("Invalid SSH URL format")
                
            user = user_host[0]
            host_port = user_host[1].split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 22
            
            return {
                'user': user,
                'host': host,
                'port': port
            }
        except Exception as e:
            self.logger.error(f"Error parsing SSH URL: {str(e)}")
            raise

    def _establish_ssh_connection(self) -> paramiko.SSHClient:
        """Establish SSH connection to target."""
        target = self.get_option('target')
        password = self.get_option('password')
        key_file = self.get_option('key_file')
        timeout = self.get_option('timeout', 30)

        ssh_info = self._parse_ssh_url(target)
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if key_file:
                key = paramiko.RSAKey.from_private_key_file(key_file)
                ssh.connect(
                    ssh_info['host'],
                    port=ssh_info['port'],
                    username=ssh_info['user'],
                    pkey=key,
                    timeout=timeout
                )
            else:
                ssh.connect(
                    ssh_info['host'],
                    port=ssh_info['port'],
                    username=ssh_info['user'],
                    password=password,
                    timeout=timeout
                )
            return ssh
        except Exception as e:
            self.logger.error(f"SSH connection failed: {str(e)}")
            raise

    def _execute_command(self, ssh: paramiko.SSHClient, command: str) -> Dict[str, str]:
        """Execute command on remote host."""
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            return {
                'stdout': stdout.read().decode('utf-8'),
                'stderr': stderr.read().decode('utf-8'),
                'status': stdout.channel.recv_exit_status()
            }
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return {'stdout': '', 'stderr': str(e), 'status': -1}

    def _check_suid_binaries(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for SUID binaries that could be exploited."""
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        result = self._execute_command(ssh, cmd)
        
        suid_bins = []
        if result['status'] == 0:
            for binary in result['stdout'].splitlines():
                # Check if binary is known to be exploitable
                check_cmd = f"ls -l {binary}"
                binary_info = self._execute_command(ssh, check_cmd)
                suid_bins.append({
                    'path': binary,
                    'info': binary_info['stdout'].strip()
                })
                
        return {
            'technique': 'suid_binaries',
            'findings': suid_bins
        }

    def _check_sudo_rights(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check sudo rights and configuration."""
        commands = [
            "sudo -l",
            "cat /etc/sudoers 2>/dev/null",
            "ls -l /etc/sudoers.d/ 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'sudo_rights',
            'findings': findings
        }

    def _check_cron_jobs(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for exploitable cron jobs."""
        commands = [
            "ls -la /etc/cron*",
            "cat /etc/crontab",
            "ls -la /var/spool/cron/crontabs/ 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'cron_jobs',
            'findings': findings
        }

    def _check_weak_permissions(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for files/directories with weak permissions."""
        commands = [
            "find / -type f -perm -o+w 2>/dev/null",
            "find / -type d -perm -o+w 2>/dev/null",
            "ls -la /etc/passwd /etc/shadow 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'weak_permissions',
            'findings': findings
        }

    def _check_kernel_exploits(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for kernel vulnerabilities."""
        commands = [
            "uname -a",
            "cat /proc/version",
            "cat /etc/*-release",
            "lsb_release -a 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'kernel_exploits',
            'findings': findings
        }

    def _check_docker_escape(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for Docker escape possibilities."""
        commands = [
            "id | grep docker",
            "ls -l /var/run/docker.sock 2>/dev/null",
            "docker info 2>/dev/null",
            "find / -name docker.sock 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'docker_escape',
            'findings': findings
        }

    def _check_capabilities(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for Linux capabilities that could be exploited."""
        commands = [
            "getcap -r / 2>/dev/null",
            "capsh --print"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'capabilities',
            'findings': findings
        }

    def _check_path_hijacking(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for PATH hijacking opportunities."""
        commands = [
            "echo $PATH",
            "find / -writable -type d 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'path_hijacking',
            'findings': findings
        }

    def _check_ld_preload(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for LD_PRELOAD opportunities."""
        commands = [
            "env | grep LD_PRELOAD",
            "cat /etc/ld.so.preload 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'ld_preload',
            'findings': findings
        }

    def _check_world_writable(self, ssh: paramiko.SSHClient) -> Dict[str, Any]:
        """Check for world-writable files and directories."""
        commands = [
            "find / -perm -2 -type f -exec ls -la {} \; 2>/dev/null",
            "find / -perm -2 -type d -exec ls -ld {} \; 2>/dev/null"
        ]
        
        findings = []
        for cmd in commands:
            result = self._execute_command(ssh, cmd)
            if result['status'] == 0:
                findings.append({
                    'command': cmd,
                    'output': result['stdout']
                })
                
        return {
            'technique': 'world_writable',
            'findings': findings
        }

    def run(self) -> bool:
        """Execute Linux privilege escalation checks."""
        try:
            # Establish SSH connection
            ssh = self._establish_ssh_connection()
            
            # Get techniques to run
            techniques = self.get_option('techniques', ['all'])
            if 'all' in techniques:
                techniques = list(self.techniques.keys())
            
            # Initialize results
            self.results = {
                'timestamp': datetime.now().isoformat(),
                'target': self.get_option('target'),
                'techniques': {}
            }
            
            # Run selected techniques
            for technique in techniques:
                if technique in self.techniques:
                    self.logger.info(f"Running technique: {technique}")
                    result = self.techniques[technique](ssh)
                    self.results['techniques'][technique] = result
            
            # Close SSH connection
            ssh.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error during privilege escalation checks: {str(e)}")
            return False

    def cleanup(self) -> None:
        """Clean up any resources or artifacts."""
        # Nothing to clean up for this module
        pass 