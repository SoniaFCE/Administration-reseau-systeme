#!/usr/bin/env python3
"""
NetGuard - Gestionnaire de pare-feu
Fonctionnalités: Lister/Ajouter/Supprimer des règles, activer/désactiver le pare-feu
Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import json
import time
import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from ..utils import logger, helpers

log = logger.setup_logger(__name__)


class FirewallManager:
    """Gestion du pare-feu système"""
    
    def __init__(self, config=None):
        self.config = config or {'timeout': 5, 'log_level': 'INFO'}
        self.firewall_type = self._detect_firewall()
        self.rules = []
        self.status = None
    
    def _detect_firewall(self):
        system = platform.system()
        if system == "Windows":
            return "windows"
        if helpers.check_command_exists("ufw"):
            return "ufw"
        if helpers.check_command_exists("firewall-cmd"):
            return "firewalld"
        if helpers.check_command_exists("nft"):
            return "nftables"
        if helpers.check_command_exists("iptables"):
            return "iptables"
        return "unknown"
    
    def get_status(self):
        status = {'enabled': False, 'running': False, 'type': self.firewall_type}
        try:
            if self.firewall_type == "windows":
                out = helpers.execute_command("netsh advfirewall show allprofiles state", True)
                if out['success']:
                    status['enabled'] = 'ON' in out['stdout']
                    status['running'] = status['enabled']
            elif self.firewall_type == "ufw":
                out = helpers.execute_command("ufw status verbose", True)
                if out['success']:
                    status['enabled'] = 'active' in out['stdout'].lower()
                    status['running'] = status['enabled']
            elif self.firewall_type == "firewalld":
                out = helpers.execute_command("firewall-cmd --state", True)
                if out['success']:
                    status['running'] = 'running' in out['stdout'].lower()
            elif self.firewall_type in ["iptables", "nftables"]:
                out = helpers.execute_command(f"{self.firewall_type} -L -n", True)
                status['running'] = out['success']
        except Exception as e:
            status['error'] = str(e)
        return status
    
    def list_rules(self):
        try:
            if self.firewall_type == "windows":
                out = helpers.execute_command("netsh advfirewall firewall show rule name=all", True)
                return self._parse_windows_rules(out['stdout']) if out['success'] else []
            elif self.firewall_type == "ufw":
                out = helpers.execute_command("ufw status numbered", True)
                return self._parse_ufw_rules(out['stdout']) if out['success'] else []
            elif self.firewall_type == "firewalld":
                out = helpers.execute_command("firewall-cmd --list-all", True)
                return self._parse_firewalld_rules(out['stdout']) if out['success'] else []
            elif self.firewall_type == "iptables":
                out = helpers.execute_command("iptables -L -n -v", True)
                return self._parse_iptables_rules(out['stdout']) if out['success'] else []
            elif self.firewall_type == "nftables":
                out = helpers.execute_command("nft list ruleset", True)
                return self._parse_nftables_rules(out['stdout']) if out['success'] else []
        except Exception as e:
            log.error(f"Erreur list_rules: {e}")
        return []
    
    def _parse_windows_rules(self, output):
        rules = []
        current = None
        for line in output.split('\n'):
            if line.startswith('Rule Name:'):
                if current:
                    rules.append(current)
                current = {'name': line.split(':')[1].strip()}
            elif current and ':' in line:
                key = line.split(':')[0].strip().lower()
                value = line.split(':')[1].strip()
                current[key] = value
        if current:
            rules.append(current)
        return rules
    
    def _parse_ufw_rules(self, output):
        rules = []
        for line in output.split('\n'):
            parts = line.strip().split()
            if parts and parts[0].isdigit():
                rules.append({
                    'id': parts[0],
                    'action': parts[1].upper(),
                    'from': parts[3] if len(parts) > 3 else 'Anywhere',
                    'to': parts[5] if len(parts) > 5 else 'Anywhere'
                })
        return rules
    
    def _parse_firewalld_rules(self, output):
        rules = []
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                rules.append({'type': key.strip(), 'values': value.strip().split()})
        return rules
    
    def _parse_iptables_rules(self, output):
        rules = []
        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 7 and parts[0].isdigit():
                rules.append({
                    'chain': parts[0],
                    'pkts': parts[1],
                    'bytes': parts[2],
                    'target': parts[3],
                    'protocol': parts[4],
                    'in': parts[5],
                    'out': parts[6]
                })
        return rules
    
    def _parse_nftables_rules(self, output):
        rules = []
        for line in output.split('\n'):
            if line.strip().startswith('rule'):
                rules.append({'raw': line.strip()})
        return rules
    
    def add_rule(self, rule):
        result = {'success': False, 'message': '', 'rule': rule}
        try:
            if self.firewall_type == "windows":
                cmd = f'netsh advfirewall firewall add rule name="{rule.get("name", "Rule")}" '
                cmd += f'dir={rule.get("direction", "in")} action={rule.get("action", "allow").lower()}'
                if rule.get('protocol'):
                    cmd += f' protocol={rule["protocol"]}'
                if rule.get('port'):
                    cmd += f' localport={rule["port"]}'
                if rule.get('source'):
                    cmd += f' remoteip={rule["source"]}'
                out = helpers.execute_command(cmd, True)
                result['success'] = out['success']
            elif self.firewall_type == "ufw":
                cmd = f"ufw {rule.get('direction', 'in')} {rule.get('action', 'allow').lower()}"
                if rule.get('port'):
                    cmd += f" {rule['port']}"
                if rule.get('protocol'):
                    cmd += f" proto {rule['protocol']}"
                out = helpers.execute_command(cmd, True)
                result['success'] = out['success']
            elif self.firewall_type == "firewalld":
                cmd = f"firewall-cmd --add-{rule.get('type', 'port')}=*"