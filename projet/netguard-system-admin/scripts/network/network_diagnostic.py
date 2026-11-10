#!/usr/bin/env python3
"""
NetGuard - Module de diagnostic réseau

Ce module permet de diagnostiquer les problèmes réseau.

Fonctionnalités:
- Test de connectivité (ping)
- Traceroute
- Test de ports
- Test de résolution DNS
- Vérification des services
- Diagnostic complet

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import json
import time
import socket
import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from collections import OrderedDict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class NetworkDiagnostic:
    """Classe pour le diagnostic réseau"""
    
    def __init__(self, config=None):
        """
        Initialiser le diagnostic réseau
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or self._load_default_config()
        self.results = []
        
        log.info("NetworkDiagnostic initialisé")
    
    def _load_default_config(self):
        """Charger la configuration par défaut"""
        return {
            'timeout': 5,
            'max_hops': 30,
            'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'ports_to_check': [22, 80, 443, 3306, 5432, 6379, 8080]
        }
    
    def check_internet(self, timeout=None):
        """
        Vérifier la connectivité Internet
        
        Args:
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'internet_connectivity',
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            # Tester avec plusieurs hôtes connus
            test_hosts = ['8.8.8.8', '1.1.1.1', 'www.google.com']
            
            for host in test_hosts:
                start_time = time.time()
                
                # Essayer de se connecter sur le port 53 (DNS) ou 80 (HTTP)
                try:
                    port = 53 if '.' in host and not any(c.isalpha() for c in host) else 80
                    socket.create_connection((host, port), timeout=timeout)
                    result['success'] = True
                    result['details']['response_time'] = round((time.time() - start_time) * 1000, 2)
                    result['details']['host'] = host
                    result['details']['port'] = port
                    break
                except Exception as e:
                    result['details'][host] = str(e)
            
            if not result['success']:
                result['error'] = "Impossible de se connecter à Internet"
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_dns(self, timeout=None):
        """
        Vérifier la résolution DNS
        
        Args:
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'dns_resolution',
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            # Tester avec plusieurs domaines
            test_domains = ['google.com', 'github.com', 'example.com']
            
            for domain in test_domains:
                try:
                    if HAS_DNSPYTHON:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = self.config.get('dns_servers', ['8.8.8.8'])
                        resolver.lifetime = timeout
                        
                        answer = resolver.resolve(domain, 'A')
                        ip_addresses = [str(r) for r in answer]
                        result['details'][domain] = ip_addresses
                        result['success'] = True
                    else:
                        # Utiliser socket.gethostbyname
                        start_time = time.time()
                        ip = socket.gethostbyname(domain)
                        result['details'][domain] = [ip]
                        result['details']['response_time'] = round((time.time() - start_time) * 1000, 2)
                        result['success'] = True
                        
                except Exception as e:
                    result['details'][domain] = f"Erreur: {str(e)}"
            
            if not result['success']:
                result['error'] = "Échec de la résolution DNS"
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_dns_server(self, server, domain='google.com', timeout=None):
        """
        Vérifier un serveur DNS spécifique
        
        Args:
            server: Adresse du serveur DNS
            domain: Domaine à résoudre
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'dns_server_check',
            'server': server,
            'domain': domain,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            if HAS_DNSPYTHON:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.lifetime = timeout
                
                answer = resolver.resolve(domain, 'A')
                result['details']['ip_addresses'] = [str(r) for r in answer]
                result['success'] = True
            else:
                # Méthode alternative avec dig
                try:
                    command = f"dig @{server} {domain} +short"
                    output = helpers.execute_command(command, timeout=timeout, capture_output=True)
                    
                    if output['success']:
                        result['details']['ip_addresses'] = output['stdout'].strip().split('\n')
                        result['success'] = True
                except:
                    result['error'] = "dig non disponible"
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def ping(self, host, timeout=None, count=1):
        """
        Effectuer un ping
        
        Args:
            host: Hôte ou IP à ping
            timeout: Timeout en secondes
            count: Nombre de pings
        
        Returns:
            dict: Résultat du ping
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'ping',
            'host': host,
            'count': count,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            if platform.system() == "Windows":
                command = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), host]
            else:
                command = ['ping', '-c', str(count), '-W', str(timeout), host]
            
            start_time = time.time()
            output = helpers.execute_command(command, timeout=timeout + 1, capture_output=True)
            end_time = time.time()
            
            result['details']['response_time_ms'] = round((end_time - start_time) * 1000 / count, 2)
            
            if output['success']:
                # Parser la sortie pour obtenir les statistiques
                lines = output['stdout'].split('\n')
                for line in lines:
                    if 'packet loss' in line.lower():
                        parts = line.split(',')
                        for part in parts:
                            if 'packet loss' in part.lower():
                                loss = part.split()[-1].rstrip('%')
                                result['details']['packet_loss'] = float(loss) if loss.isdigit() else 0
                    elif 'rtt' in line.lower():
                        parts = line.split('=')
                        if len(parts) > 1:
                            rtt_info = parts[1].strip().split('/')
                            if len(rtt_info) >= 3:
                                result['details']['rtt_min'] = float(rtt_info[0])
                                result['details']['rtt_avg'] = float(rtt_info[1])
                                result['details']['rtt_max'] = float(rtt_info[2])
                
                # Vérifier si le ping a réussi
                if 'ttl=' in output['stdout'].lower() or 'time=' in output['stdout'].lower():
                    result['success'] = True
                else:
                    result['error'] = "Aucune réponse du ping"
            else:
                result['error'] = output['stderr']
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def traceroute(self, host, timeout=None, max_hops=None):
        """
        Effectuer un traceroute
        
        Args:
            host: Hôte ou IP de destination
            timeout: Timeout en secondes
            max_hops: Nombre maximum de sauts
        
        Returns:
            dict: Résultat du traceroute
        """
        timeout = timeout or self.config.get('timeout', 5)
        max_hops = max_hops or self.config.get('max_hops', 30)
        
        result = {
            'test': 'traceroute',
            'host': host,
            'max_hops': max_hops,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'hops': []
            },
            'error': None
        }
        
        try:
            # Utiliser la commande traceroute ou tracert
            if platform.system() == "Windows":
                command = ['tracert', '-h', str(max_hops), '-w', str(int(timeout * 1000)), host]
            else:
                command = ['traceroute', '-m', str(max_hops), '-w', str(timeout), host]
            
            output = helpers.execute_command(command, timeout=max_hops * timeout + 5, capture_output=True)
            
            if output['success']:
                result['success'] = True
                
                # Parser la sortie du traceroute
                lines = output['stdout'].split('\n')
                
                # Windows
                if platform.system() == "Windows":
                    for line in lines[1:]:
                        if not line.strip():
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 4:
                            hop_num = parts[0]
                            hostname = parts[1]
                            ip = parts[2]
                            times = ' '.join(parts[3:])
                            
                            result['details']['hops'].append({
                                'hop': int(hop_num),
                                'hostname': hostname,
                                'ip': ip,
                                'times': times
                            })
                
                # Linux/macOS
                else:
                    for line in lines:
                        if not line.strip() or 'traceroute' in line:
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 2:
                            hop_num = parts[0]
                            times = []
                            ip = None
                            hostname = None
                            
                            for part in parts[1:]:
                                if part.startswith('(') and part.endswith(')'):
                                    ip = part[1:-1]
                                elif '.' in part and part.count('.') == 3:
                                    ip = part
                                elif part.startswith('*'):
                                    times.append(None)
                                else:
                                    # Essayer de parser comme un temps
                                    try:
                                        times.append(float(part.replace('ms', '').strip()))
                                    except:
                                        hostname = part
                            
                            result['details']['hops'].append({
                                'hop': int(hop_num),
                                'hostname': hostname,
                                'ip': ip,
                                'times': times
                            })
            else:
                result['error'] = output['stderr']
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_port(self, host, port, timeout=None, protocol='tcp'):
        """
        Vérifier si un port est ouvert
        
        Args:
            host: Hôte ou IP
            port: Numéro de port
            timeout: Timeout en secondes
            protocol: Protocole (tcp ou udp)
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'port_check',
            'host': host,
            'port': port,
            'protocol': protocol,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            if protocol == 'tcp':
                start_time = time.time()
                socket.create_connection((host, port), timeout=timeout)
                end_time = time.time()
                result['success'] = True
                result['details']['response_time_ms'] = round((end_time - start_time) * 1000, 2)
                
                # Essayer d'obtenir le banner
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((host, port))
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    result['details']['banner'] = banner.strip() if banner else None
                    s.close()
                except:
                    pass
            
            elif protocol == 'udp':
                # UDP est plus complexe à tester (pas de connexion)
                # On envoie juste un paquet vide et on attend une réponse
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(timeout)
                    s.connect((host, port))
                    s.send(b'')
                    data = s.recv(1024)
                    result['success'] = True
                    result['details']['response'] = data.hex() if data else None
                    s.close()
                except socket.timeout:
                    # Pas de réponse, mais le port pourrait être ouvert
                    result['details']['note'] = "Pas de réponse UDP (le port pourrait être ouvert)"
                except:
                    result['error'] = "Port UDP fermé ou filtré"
            
            else:
                result['error'] = f"Protocole non supporté: {protocol}"
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_ports(self, host, ports=None, timeout=None, protocol='tcp'):
        """
        Vérifier plusieurs ports
        
        Args:
            host: Hôte ou IP
            ports: Liste de ports (ou None pour les ports par défaut)
            timeout: Timeout en secondes
            protocol: Protocole (tcp ou udp)
        
        Returns:
            dict: Résultats des tests
        """
        timeout = timeout or self.config.get('timeout', 5)
        ports = ports or self.config.get('ports_to_check', [22, 80, 443])
        
        results = {
            'test': 'ports_check',
            'host': host,
            'ports': ports,
            'protocol': protocol,
            'timestamp': datetime.now().isoformat(),
            'results': [],
            'open_ports': [],
            'closed_ports': [],
            'error': None
        }
        
        try:
            for port in ports:
                port_result = self.check_port(host, port, timeout, protocol)
                results['results'].append(port_result)
                
                if port_result['success']:
                    results['open_ports'].append(port)
                else:
                    results['closed_ports'].append(port)
            
            self.results.append(results)
            return results
            
        except Exception as e:
            results['error'] = str(e)
            self.results.append(results)
            return results
    
    def check_service(self, host, port, service_name=None, timeout=None):
        """
        Vérifier un service spécifique
        
        Args:
            host: Hôte ou IP
            port: Numéro de port
            service_name: Nom du service
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'service_check',
            'host': host,
            'port': port,
            'service': service_name or self._get_service_name(port),
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            # Vérifier si le port est ouvert
            port_result = self.check_port(host, port, timeout)
            
            if port_result['success']:
                result['success'] = True
                result['details'] = port_result['details']
                
                # Vérifications spécifiques selon le service
                if result['service'] in ['http', 'https', 'nginx', 'apache2', 'httpd']:
                    http_result = self.check_http(host, port, timeout)
                    result['details']['http'] = http_result['details']
                
                elif result['service'] in ['smtp', '25']:
                    smtp_result = self.check_smtp(host, port, timeout)
                    result['details']['smtp'] = smtp_result['details']
                
                elif result['service'] in ['ftp', '21']:
                    ftp_result = self.check_ftp(host, port, timeout)
                    result['details']['ftp'] = ftp_result['details']
                
            else:
                result['error'] = f"Port {port} fermé"
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_http(self, host, port=80, timeout=None, https=False):
        """
        Vérifier un serveur HTTP/HTTPS
        
        Args:
            host: Hôte ou IP
            port: Numéro de port
            timeout: Timeout en secondes
            https: Utiliser HTTPS
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'http_check',
            'host': host,
            'port': port,
            'protocol': 'https' if https else 'http',
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            import requests
            
            url = f"{'https' if https else 'http'}://{host}:{port}" if port != (443 if https else 80) else f"{'https' if https else 'http'}://{host}"
            
            start_time = time.time()
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            end_time = time.time()
            
            result['success'] = True
            result['details']['status_code'] = response.status_code
            result['details']['response_time_ms'] = round((end_time - start_time) * 1000, 2)
            result['details']['headers'] = dict(response.headers)
            result['details']['content_length'] = len(response.content)
            
            # Vérifier le contenu
            content_type = response.headers.get('content-type', '')
            result['details']['content_type'] = content_type
            
            # Vérifier si c'est un redirect
            if response.is_redirect:
                result['details']['redirect_url'] = response.headers.get('location')
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_smtp(self, host, port=25, timeout=None):
        """
        Vérifier un serveur SMTP
        
        Args:
            host: Hôte ou IP
            port: Numéro de port
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'smtp_check',
            'host': host,
            'port': port,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            import smtplib
            
            start_time = time.time()
            
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                # Obtenir le banner
                code, message = smtp.ehlo()
                result['success'] = True
                result['details']['banner'] = message.decode('utf-8', errors='ignore') if isinstance(message, bytes) else message
                result['details']['response_time_ms'] = round((time.time() - start_time) * 1000, 2)
                
                # Vérifier si l'authentification est supportée
                if 'AUTH' in message:
                    result['details']['auth_supported'] = True
                
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def check_ftp(self, host, port=21, timeout=None):
        """
        Vérifier un serveur FTP
        
        Args:
            host: Hôte ou IP
            port: Numéro de port
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        result = {
            'test': 'ftp_check',
            'host': host,
            'port': port,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'error': None
        }
        
        try:
            from ftplib import FTP
            
            start_time = time.time()
            
            ftp = FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login()  # Connexion anonyme
            
            end_time = time.time()
            result['success'] = True
            result['details']['banner'] = ftp.welcome
            result['details']['response_time_ms'] = round((end_time - start_time) * 1000, 2)
            
            # Obtenir la liste des fichiers
            try:
                files = []
                ftp.dir(files.append)
                result['details']['file_count'] = len(files)
            except:
                pass
            
            ftp.quit()
            
        except Exception as e:
            result['error'] = str(e)
        
        self.results.append(result)
        return result
    
    def _get_service_name(self, port):
        """
        Obtenir le nom du service pour un port
        
        Args:
            port: Numéro de port
        
        Returns:
            str: Nom du service
        """
        common_ports = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'domain', 80: 'http', 110: 'pop3', 119: 'nntp', 123: 'ntp',
            135: 'msrpc', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp',
            162: 'snmptrap', 389: 'ldap', 443: 'https', 445: 'microsoft-ds',
            465: 'smtps', 514: 'syslog', 515: 'printer', 546: 'dhcpv6-client',
            547: 'dhcpv6-server', 587: 'submission', 636: 'ldaps', 993: 'imaps',
            995: 'pop3s', 1080: 'socks', 11211: 'memcached', 1433: 'ms-sql-s',
            1434: 'ms-sql-m', 1723: 'pptp', 2049: 'nfs', 2082: 'cpanel',
            2083: 'cpanel-ssl', 2086: 'whm', 2087: 'whm-ssl', 27017: 'mongodb',
            3306: 'mysql', 3389: 'rdp', 3690: 'svn', 5060: 'sip', 5061: 'sips',
            5432: 'postgresql', 5900: 'vnc', 5901: 'vnc-1', 6379: 'redis',
            8000: 'http-alt', 8080: 'http-proxy', 8081: 'http-proxy-alt',
            8443: 'https-alt', 8888: 'http-alt-2'
        }
        
        return common_ports.get(port, 'unknown')
    
    def run_full_diagnostic(self, host, timeout=None):
        """
        Exécuter un diagnostic complet
        
        Args:
            host: Hôte ou IP à diagnostiquer
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultats du diagnostic
        """
        timeout = timeout or self.config.get('timeout', 5)
        
        results = {
            'diagnostic': {
                'host': host,
                'timestamp': datetime.now().isoformat(),
                'tests': []
            },
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'errors': 0
            }
        }
        
        try:
            # Test de connectivité
            ping_result = self.ping(host, timeout)
            results['diagnostic']['tests'].append(ping_result)
            results['summary']['total_tests'] += 1
            if ping_result['success']:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
            
            # Test DNS (si l'hôte est un nom de domaine)
            if not helpers.validate_ip(host):
                dns_result = self.check_dns(timeout)
                results['diagnostic']['tests'].append(dns_result)
                results['summary']['total_tests'] += 1
                if dns_result['success']:
                    results['summary']['passed'] += 1
                else:
                    results['summary']['failed'] += 1
            
            # Traceroute (seulement si ping réussit)
            if ping_result['success']:
                traceroute_result = self.traceroute(host, timeout)
                results['diagnostic']['tests'].append(traceroute_result)
                results['summary']['total_tests'] += 1
                if traceroute_result['success']:
                    results['summary']['passed'] += 1
                else:
                    results['summary']['failed'] += 1
            
            # Test des ports courants
            ports_result = self.check_ports(host, self.config.get('ports_to_check', [22, 80, 443]), timeout)
            results['diagnostic']['tests'].append(ports_result)
            results['summary']['total_tests'] += 1
            if ports_result['open_ports']:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
            
            # Test HTTP (port 80 et 443)
            http_result = self.check_http(host, 80, timeout)
            results['diagnostic']['tests'].append(http_result)
            results['summary']['total_tests'] += 1
            if http_result['success']:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
            
            https_result = self.check_http(host, 443, timeout, https=True)
            results['diagnostic']['tests'].append(https_result)
            results['summary']['total_tests'] += 1
            if https_result['success']:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
            
        except Exception as e:
            results['diagnostic']['error'] = str(e)
            results['summary']['errors'] += 1
        
        self.results.append(results)
        return results
    
    def display_results(self, results):
        """
        Afficher les résultats des tests
        
        Args:
            results: Résultats à afficher
        """
        if isinstance(results, list):
            for result in results:
                self._display_single_result(result)
        else:
            self._display_single_result(results)
    
    def _display_single_result(self, result):
        """
        Afficher un seul résultat
        
        Args:
            result: Résultat à afficher
        """
        test_type = result.get('test', 'unknown')
        
        # Couleurs
        green = '\033[92m' if helpers.USE_COLORS else ''
        red = '\033[91m' if helpers.USE_COLORS else ''
        yellow = '\033[93m' if helpers.USE_COLORS else ''
        reset = '\033[0m' if helpers.USE_COLORS else ''
        
        # Déterminer le statut
        if result.get('success', False):
            status = f"{green}✓ SUCCESS{reset}"
        else:
            status = f"{red}✗ FAILED{reset}"
        
        print(f"\n{'='*60}")
        print(f"Test: {test_type}")
        print(f"Statut: {status}")
        print(f"Date: {result.get('timestamp', 'N/A')}")
        
        # Afficher les détails spécifiques
        if test_type == 'ping':
            print(f"Hôte: {result.get('host', 'N/A')}")
            print(f"Paquets: {result.get('count', 'N/A')}")
            if 'response_time_ms' in result.get('details', {}):
                print(f"Temps de réponse: {result['details']['response_time_ms']} ms")
            if 'packet_loss' in result.get('details', {}):
                print(f"Perte de paquets: {result['details']['packet_loss']}%")
            if 'rtt_avg' in result.get('details', {}):
                print(f"RTT moyen: {result['details']['rtt_avg']} ms")
        
        elif test_type == 'traceroute':
            print(f"Hôte: {result.get('host', 'N/A')}")
            print(f"Nombre max de sauts: {result.get('max_hops', 'N/A')}")
            
            if 'hops' in result.get('details', {}):
                print("\nSauts:")
                for hop in result['details']['hops']:
                    hop_num = hop.get('hop', '?')
                    hostname = hop.get('hostname', '?')
                    ip = hop.get('ip', '?')
                    times = hop.get('times', [])
                    
                    # Formater les temps
                    times_str = " ".join(str(t) + "ms" if t else "*" for t in times[:3])
                    
                    print(f"  {hop_num:2d}: {hostname:20} ({ip:15}) {times_str}")
        
        elif test_type == 'port_check' or test_type == 'ports_check':
            print(f"Hôte: {result.get('host', 'N/A')}")
            print(f"Port: {result.get('port', 'N/A')}")
            print(f"Protocole: {result.get('protocol', 'N/A')}")
            
            if test_type == 'ports_check':
                print(f"Ports ouverts: {', '.join(map(str, result.get('open_ports', [])))}")
                print(f"Ports fermés: {', '.join(map(str, result.get('closed_ports', [])))}")
            
            if 'banner' in result.get('details', {}):
                banner = result['details']['banner']
                if banner:
                    print(f"Banner: {banner[:100]}...")
        
        elif test_type == 'dns_resolution':
            print("Résolution DNS:")
            for domain, ips in result.get('details', {}).items():
                if isinstance(ips, list):
                    print(f"  {domain}: {', '.join(ips)}")
                else:
                    print(f"  {domain}: {ips}")
        
        elif test_type == 'http_check':
            print(f"URL: {result.get('protocol', 'http')}://{result.get('host', 'N/A')}:{result.get('port', 80)}")
            if 'status_code' in result.get('details', {}):
                print(f"Code HTTP: {result['details']['status_code']}")
            if 'response_time_ms' in result.get('details', {}):
                print(f"Temps de réponse: {result['details']['response_time_ms']} ms")
            if 'content_type' in result.get('details', {}):
                print(f"Type de contenu: {result['details']['content_type']}")
        
        elif test_type == 'diagnostic':
            # Afficher le résumé
            summary = result.get('summary', {})
            print(f"Total des tests: {summary.get('total_tests', 0)}")
            print(f"Réussis: {summary.get('passed', 0)}")
            print(f"Échoués: {summary.get('failed', 0)}")
            print(f"Erreurs: {summary.get('errors', 0)}")
            
            # Afficher chaque test
            print("\nDétails des tests:")
            for test in result.get('diagnostic', {}).get('tests', []):
                test_type = test.get('test', 'unknown')
                status = "✓" if test.get('success', False) else "✗"
                print(f"  {status} {test_type}: {test.get('host', 'N/A')}")
        
        # Afficher l'erreur si elle existe
        if result.get('error'):
            print(f"\nErreur: {result['error']}")
        
        print(f"{'='*60}")


def main(args=None):
    """
    Fonction principale pour le module de diagnostic réseau
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Diagnostiquer les problèmes réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python network_diagnostic.py --ping google.com
  python network_diagnostic.py --traceroute google.com --max-hops 20
  python network_diagnostic.py --check-ports google.com 80,443,22
  python network_diagnostic.py --check-service google.com 443 https
  python network_diagnostic.py --full google.com
  python network_diagnostic.py --check-internet
  python network_diagnostic.py --check-dns
  python network_diagnostic.py --check-dns-server 8.8.8.8 google.com
        """
    )
    
    # Arguments pour les tests individuels
    parser.add_argument('--ping', type=str, metavar='HOST',
                        help='Effectuer un ping')
    parser.add_argument('--traceroute', type=str, metavar='HOST',
                        help='Effectuer un traceroute')
    parser.add_argument('--check-ports', type=str, nargs='+',
                        metavar=('HOST', 'PORTS'),
                        help='Vérifier des ports (ex: --check-ports google.com 80,443,22)')
    parser.add_argument('--check-port', type=str, nargs=2,
                        metavar=('HOST', 'PORT'),
                        help='Vérifier un port spécifique')
    parser.add_argument('--check-service', type=str, nargs=3,
                        metavar=('HOST', 'PORT', 'SERVICE'),
                        help='Vérifier un service spécifique')
    parser.add_argument('--check-http', type=str, nargs='?', const='80',
                        metavar='HOST [PORT]',
                        help='Vérifier un serveur HTTP')
    parser.add_argument('--check-https', type=str, nargs='?', const='443',
                        metavar='HOST [PORT]',
                        help='Vérifier un serveur HTTPS')
    
    # Arguments pour les tests globaux
    parser.add_argument('--full', type=str, metavar='HOST',
                        help='Exécuter un diagnostic complet')
    parser.add_argument('--check-internet', action='store_true',
                        help='Vérifier la connectivité Internet')
    parser.add_argument('--check-dns', action='store_true',
                        help='Vérifier la résolution DNS')
    parser.add_argument('--check-dns-server', type=str, nargs='?', const='8.8.8.8',
                        metavar='SERVER [DOMAIN]',
                        help='Vérifier un serveur DNS spécifique')
    
    # Arguments pour la configuration
    parser.add_argument('--timeout', type=int, default=5,
                        help='Timeout pour les tests en secondes (par défaut: 5)')
    parser.add_argument('--max-hops', type=int, default=30,
                        help='Nombre maximum de sauts pour traceroute (par défaut: 30)')
    parser.add_argument('--ports', type=str,
                        help='Ports à vérifier (séparés par des virgules)')
    
    # Arguments divers
    parser.add_argument('--json', action='store_true',
                        help='Afficher les résultats au format JSON')
    parser.add_argument('--display', action='store_true',
                        help='Afficher les résultats')
    parser.add_argument('--verbose', action='store_true',
                        help='Mode verbeux')
    parser.add_argument('--quiet', action='store_true',
                        help='Mode silencieux')
    
    # Parse arguments
    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)
    
    # Configurer le logging
    if args.verbose:
        logger.set_log_level('DEBUG')
    elif args.quiet:
        logger.set_log_level('ERROR')
    
    # Créer le diagnostic réseau
    diagnostic = NetworkDiagnostic({
        'timeout': args.timeout,
        'max_hops': args.max_hops,
        'ports_to_check': list(map(int, args.ports.split(','))) if args.ports else [22, 80, 443]
    })
    
    # Exécuter les tests
    results = None
    
    if args.ping:
        results = diagnostic.ping(args.ping, args.timeout)
    
    elif args.traceroute:
        results = diagnostic.traceroute(args.traceroute, args.timeout, args.max_hops)
    
    elif args.check_ports:
        host = args.check_ports[0]
        ports = list(map(int, args.check_ports[1].split(','))) if len(args.check_ports) > 1 else None
        results = diagnostic.check_ports(host, ports, args.timeout)
    
    elif args.check_port:
        host, port = args.check_port
        results = diagnostic.check_port(host, int(port), args.timeout)
    
    elif args.check_service:
        host, port, service = args.check_service
        results = diagnostic.check_service(host, int(port), service, args.timeout)
    
    elif args.check_http:
        host = args.check_http
        port = 80
        results = diagnostic.check_http(host, port, args.timeout)
    
    elif args.check_https:
        host = args.check_https
        port = 443
        results = diagnostic.check_http(host, port, args.timeout, https=True)
    
    elif args.full:
        results = diagnostic.run_full_diagnostic(args.full, args.timeout)
    
    elif args.check_internet:
        results = diagnostic.check_internet(args.timeout)
    
    elif args.check_dns:
        results = diagnostic.check_dns(args.timeout)
    
    elif args.check_dns_server:
        server = args.check_dns_server
        domain = None
        if len(args.check_dns_server) > 1:
            domain = args.check_dns_server[1]
        results = diagnostic.check_dns_server(server, domain, args.timeout)
    
    else:
        # Par défaut: vérifier Internet
        results = diagnostic.check_internet(args.timeout)
    
    # Afficher les résultats
    if results:
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        elif args.display or not any([args.json, args.quiet]):
            diagnostic.display_results(results)


if __name__ == "__main__":
    main()
