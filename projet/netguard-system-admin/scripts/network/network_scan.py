#!/usr/bin/env python3
"""
NetGuard - Module de scan réseau

Ce module permet de scanner le réseau pour découvrir les hôtes et services.

Fonctionnalités:
- Scan Ping (ICMP)
- Scan de ports TCP
- Scan de ports UDP (limité)
- Découverte de services
- Détection du système d'exploitation

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
import ipaddress
import concurrent.futures
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class NetworkScanner:
    """Classe pour le scan réseau"""
    
    def __init__(self, config=None):
        """
        Initialiser le scanner réseau
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or self._load_default_config()
        self.scan_results = []
        self.hosts_discovered = []
        self.services_discovered = []
        
        log.info("NetworkScanner initialisé")
    
    def _load_default_config(self):
        """Charger la configuration par défaut"""
        return {
            'subnet': '192.168.1.0/24',
            'ports': [22, 80, 443, 3306, 5432, 6379, 11211, 27017, 8080, 8443],
            'scan_type': 'normal',
            'timeout': 5,
            'max_threads': 100,
            'output_file': 'network_scan.json'
        }
    
    def scan_network(self, subnet=None, scan_type=None, ports=None, timeout=None, max_threads=None):
        """
        Scanner le réseau
        
        Args:
            subnet: Sous-réseau à scanner
            scan_type: Type de scan ('quick', 'normal', 'deep')
            ports: Liste des ports à scanner
            timeout: Timeout pour chaque test (en secondes)
            max_threads: Nombre maximum de threads
        
        Returns:
            dict: Résultats du scan
        """
        # Utiliser les valeurs par défaut ou celles fournies
        subnet = subnet or self.config.get('subnet')
        scan_type = scan_type or self.config.get('scan_type')
        ports = ports or self.config.get('ports')
        timeout = timeout or self.config.get('timeout')
        max_threads = max_threads or self.config.get('max_threads')
        
        # Valider le sous-réseau
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            log.error(f"Sous-réseau invalide: {e}")
            return {'error': f"Sous-réseau invalide: {e}"}
        
        log.info(f"Début du scan du réseau: {subnet}")
        
        start_time = time.time()
        results = {
            'scan_start': datetime.now().isoformat(),
            'subnet': str(network),
            'scan_type': scan_type,
            'hosts_found': 0,
            'hosts': [],
            'services_found': 0,
            'services': [],
            'statistics': {
                'total_ips': network.num_addresses,
                'scanned_ips': 0,
                'open_ports': 0
            }
        }
        
        # Obtenir la liste des adresses IP
        all_ips = [str(ip) for ip in network.hosts()]
        results['statistics']['total_ips'] = len(all_ips)
        
        try:
            if scan_type == 'quick':
                # Scan rapide: ping + ports courants
                self._scan_quick(all_ips, ports, timeout, max_threads, results)
            elif scan_type == 'deep':
                # Scan profond: tous les ports
                self._scan_deep(all_ips, timeout, max_threads, results)
            else:
                # Scan normal: ping + ports configurés
                self._scan_normal(all_ips, ports, timeout, max_threads, results)
            
            # Calculer les statistiques
            results['statistics']['scan_duration_seconds'] = round(time.time() - start_time, 2)
            results['statistics']['hosts_found'] = len(results['hosts'])
            results['statistics']['services_found'] = results['services_found']
            results['statistics']['open_ports'] = sum(
                len(host['open_ports']) for host in results['hosts']
            )
            
            # Enregistrer les résultats
            self.scan_results = results
            self.hosts_discovered = results['hosts']
            
            log.info(f"Scan terminé: {results['statistics']['hosts_found']} hôtes trouvés, "
                     f"{results['statistics']['open_ports']} ports ouverts")
            
        except Exception as e:
            log.error(f"Erreur lors du scan réseau: {e}")
            results['error'] = str(e)
        
        return results
    
    def _scan_quick(self, ips, ports, timeout, max_threads, results):
        """
        Effectuer un scan rapide
        
        Args:
            ips: Liste des adresses IP
            ports: Liste des ports à scanner
            timeout: Timeout
            max_threads: Nombre maximum de threads
            results: Dictionnaire pour stocker les résultats
        """
        print(f"Scan rapide: {len(ips)} adresses, {len(ports)} ports")
        
        # Utiliser ThreadPoolExecutor pour paralléliser
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            
            for ip in ips:
                futures.append(executor.submit(
                    self._check_host_quick, ip, ports, timeout
                ))
            
            for future in concurrent.futures.as_completed(futures):
                host_info = future.result()
                if host_info:
                    results['hosts'].append(host_info)
                    results['hosts_found'] += 1
                results['statistics']['scanned_ips'] += 1
    
    def _scan_normal(self, ips, ports, timeout, max_threads, results):
        """
        Effectuer un scan normal
        
        Args:
            ips: Liste des adresses IP
            ports: Liste des ports à scanner
            timeout: Timeout
            max_threads: Nombre maximum de threads
            results: Dictionnaire pour stocker les résultats
        """
        print(f"Scan normal: {len(ips)} adresses, {len(ports)} ports")
        
        # Utiliser ThreadPoolExecutor pour paralléliser
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            
            for ip in ips:
                futures.append(executor.submit(
                    self._check_host_normal, ip, ports, timeout
                ))
            
            for future in concurrent.futures.as_completed(futures):
                host_info = future.result()
                if host_info:
                    results['hosts'].append(host_info)
                    results['hosts_found'] += 1
                    
                    # Compter les services
                    results['services_found'] += len(host_info.get('open_ports', []))
                    
                    # Ajouter les services à la liste
                    for port_info in host_info.get('open_ports', []):
                        service = {
                            'host': host_info['ip'],
                            'port': port_info['port'],
                            'service': port_info.get('service', 'unknown'),
                            'protocol': port_info.get('protocol', 'tcp')
                        }
                        results['services'].append(service)
                results['statistics']['scanned_ips'] += 1
    
    def _scan_deep(self, ips, timeout, max_threads, results):
        """
        Effectuer un scan profond (tous les ports)
        
        Args:
            ips: Liste des adresses IP
            timeout: Timeout
            max_threads: Nombre maximum de threads
            results: Dictionnaire pour stocker les résultats
        """
        print(f"Scan profond: {len(ips)} adresses, tous les ports")
        
        # Scanner tous les ports (1-65535)
        all_ports = list(range(1, 65536))
        
        # Utiliser ThreadPoolExecutor pour paralléliser
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            
            for ip in ips:
                futures.append(executor.submit(
                    self._check_host_deep, ip, all_ports, timeout
                ))
            
            for future in concurrent.futures.as_completed(futures):
                host_info = future.result()
                if host_info:
                    results['hosts'].append(host_info)
                    results['hosts_found'] += 1
                    
                    # Compter les services
                    results['services_found'] += len(host_info.get('open_ports', []))
                    
                    # Ajouter les services à la liste
                    for port_info in host_info.get('open_ports', []):
                        service = {
                            'host': host_info['ip'],
                            'port': port_info['port'],
                            'service': port_info.get('service', 'unknown'),
                            'protocol': port_info.get('protocol', 'tcp')
                        }
                        results['services'].append(service)
                results['statistics']['scanned_ips'] += 1
    
    def _check_host_quick(self, ip, ports, timeout):
        """
        Vérifier un hôte (scan rapide)
        
        Args:
            ip: Adresse IP
            ports: Liste des ports à vérifier
            timeout: Timeout
        
        Returns:
            dict: Informations sur l'hôte
        """
        host_info = {
            'ip': ip,
            'hostname': None,
            'mac': None,
            'os': None,
            'open_ports': [],
            'status': 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Vérifier si l'hôte est en ligne (ping)
            if not self._ping_host(ip, timeout):
                host_info['status'] = 'offline'
                return host_info
            
            host_info['status'] = 'online'
            
            # Essayer d'obtenir le nom d'hôte
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                host_info['hostname'] = hostname
            except:
                pass
            
            # Vérifier les ports (un seul thread pour ce test)
            for port in ports[:5]:  # Limiter à 5 ports pour le scan rapide
                if self._check_port(ip, port, timeout):
                    host_info['open_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': self._get_service_name(port)
                    })
            
        except Exception as e:
            host_info['error'] = str(e)
        
        return host_info
    
    def _check_host_normal(self, ip, ports, timeout):
        """
        Vérifier un hôte (scan normal)
        
        Args:
            ip: Adresse IP
            ports: Liste des ports à vérifier
            timeout: Timeout
        
        Returns:
            dict: Informations sur l'hôte
        """
        host_info = {
            'ip': ip,
            'hostname': None,
            'mac': None,
            'os': None,
            'open_ports': [],
            'status': 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Vérifier si l'hôte est en ligne (ping)
            if not self._ping_host(ip, timeout):
                host_info['status'] = 'offline'
                return host_info
            
            host_info['status'] = 'online'
            
            # Essayer d'obtenir le nom d'hôte
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                host_info['hostname'] = hostname
            except:
                pass
            
            # Vérifier les ports
            for port in ports:
                if self._check_port(ip, port, timeout):
                    host_info['open_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': self._get_service_name(port)
                    })
            
        except Exception as e:
            host_info['error'] = str(e)
        
        return host_info
    
    def _check_host_deep(self, ip, ports, timeout):
        """
        Vérifier un hôte (scan profond)
        
        Args:
            ip: Adresse IP
            ports: Liste des ports à vérifier
            timeout: Timeout
        
        Returns:
            dict: Informations sur l'hôte
        """
        host_info = {
            'ip': ip,
            'hostname': None,
            'mac': None,
            'os': None,
            'open_ports': [],
            'status': 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Vérifier si l'hôte est en ligne (ping)
            if not self._ping_host(ip, timeout):
                host_info['status'] = 'offline'
                return host_info
            
            host_info['status'] = 'online'
            
            # Essayer d'obtenir le nom d'hôte
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                host_info['hostname'] = hostname
            except:
                pass
            
            # Vérifier les ports (en parallèle)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for port in ports:
                    futures.append(executor.submit(self._check_port, ip, port, timeout))
                
                for i, future in enumerate(concurrent.futures.as_completed(futures)):
                    if future.result():
                        host_info['open_ports'].append({
                            'port': ports[i],
                            'protocol': 'tcp',
                            'service': self._get_service_name(ports[i])
                        })
            
        except Exception as e:
            host_info['error'] = str(e)
        
        return host_info
    
    def _ping_host(self, ip, timeout):
        """
        Vérifier si un hôte répond au ping
        
        Args:
            ip: Adresse IP
            timeout: Timeout en secondes
        
        Returns:
            bool: True si l'hôte répond, False sinon
        """
        try:
            # Utiliser la commande ping
            if platform.system() == "Windows":
                command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
            else:
                command = ['ping', '-c', '1', '-W', str(timeout), ip]
            
            result = helpers.execute_command(command, timeout=timeout + 1, capture_output=True)
            
            return result['success'] and 'ttl=' in result['stdout'].lower()
            
        except Exception as e:
            log.debug(f"Erreur lors du ping de {ip}: {e}")
            return False
    
    def _check_port(self, ip, port, timeout):
        """
        Vérifier si un port est ouvert
        
        Args:
            ip: Adresse IP
            port: Numéro de port
            timeout: Timeout en secondes
        
        Returns:
            bool: True si le port est ouvert, False sinon
        """
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except:
            return False
    
    def _get_service_name(self, port):
        """
        Obtenir le nom du service pour un port
        
        Args:
            port: Numéro de port
        
        Returns:
            str: Nom du service
        """
        # Liste des ports courants
        common_ports = {
            20: 'ftp-data',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            80: 'http',
            110: 'pop3',
            119: 'nntp',
            123: 'ntp',
            135: 'msrpc',
            139: 'netbios-ssn',
            143: 'imap',
            161: 'snmp',
            162: 'snmptrap',
            389: 'ldap',
            443: 'https',
            445: 'microsoft-ds',
            465: 'smtps',
            514: 'syslog',
            515: 'printer',
            546: 'dhcpv6-client',
            547: 'dhcpv6-server',
            587: 'submission',
            636: 'ldaps',
            993: 'imaps',
            995: 'pop3s',
            1080: 'socks',
            11211: 'memcached',
            1433: 'ms-sql-s',
            1434: 'ms-sql-m',
            1723: 'pptp',
            2049: 'nfs',
            2082: 'cpanel',
            2083: 'cpanel-ssl',
            2086: 'whm',
            2087: 'whm-ssl',
            27017: 'mongodb',
            3306: 'mysql',
            3389: 'rdp',
            3690: 'svn',
            5060: 'sip',
            5061: 'sips',
            5432: 'postgresql',
            5900: 'vnc',
            5901: 'vnc-1',
            6379: 'redis',
            8000: 'http-alt',
            8080: 'http-proxy',
            8081: 'http-proxy-alt',
            8443: 'https-alt',
            8888: 'http-alt-2'
        }
        
        return common_ports.get(port, 'unknown')
    
    def scan_with_nmap(self, target, ports=None, arguments=None, sudo=False):
        """
        Scanner avec nmap (si disponible)
        
        Args:
            target: Cible à scanner (IP ou sous-réseau)
            ports: Ports à scanner
            arguments: Arguments supplémentaires pour nmap
            sudo: Exécuter avec sudo (pour les scans avancés)
        
        Returns:
            dict: Résultats du scan nmap
        """
        if not HAS_NMAP:
            log.error("nmap non disponible - installez python-nmap")
            return {'error': 'nmap non installé'}
        
        try:
            nm = nmap.PortScanner()
            
            # Construire les arguments
            nmap_args = []
            
            if ports:
                if isinstance(ports, list):
                    port_str = ','.join(map(str, ports))
                else:
                    port_str = str(ports)
                nmap_args.append(f'-p {port_str}')
            
            if arguments:
                if isinstance(arguments, list):
                    nmap_args.extend(arguments)
                else:
                    nmap_args.append(arguments)
            
            # Exécuter le scan
            if sudo:
                log.info(f"Exécution: sudo nmap {target} {' '.join(nmap_args)}")
                # Note: python-nmap ne supporte pas sudo directement
                # Il faut l'exécuter avec des privilèges élevés
            else:
                log.info(f"Exécution: nmap {target} {' '.join(nmap_args)}")
            
            nm.scan(hosts=target, arguments=' '.join(nmap_args))
            
            # Traiter les résultats
            results = {
                'scan': {
                    'type': 'nmap',
                    'target': target,
                    'arguments': ' '.join(nmap_args),
                    'timestamp': datetime.now().isoformat()
                },
                'hosts': []
            }
            
            for host, host_info in nm.all_hosts().items():
                host_data = {
                    'ip': host,
                    'hostname': host_info.hostname() if host_info.hostname() else None,
                    'status': host_info.state(),
                    'ports': []
                }
                
                # Obtenir les informations des ports
                for proto in host_info.all_protocols():
                    for port, port_info in host_info[proto].items():
                        host_data['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', None),
                            'product': port_info.get('product', None)
                        })
                
                results['hosts'].append(host_data)
            
            return results
            
        except Exception as e:
            log.error(f"Erreur lors du scan nmap: {e}")
            return {'error': str(e)}
    
    def scan_with_scapy(self, subnet, timeout=2):
        """
        Scanner avec scapy (si disponible)
        
        Args:
            subnet: Sous-réseau à scanner
            timeout: Timeout pour les réponses
        
        Returns:
            dict: Résultats du scan
        """
        if not HAS_SCAPY:
            log.error("scapy non disponible - installez scapy")
            return {'error': 'scapy non installé'}
        
        if platform.system() == "Windows":
            log.error("Scapy ne fonctionne pas correctement sous Windows")
            return {'error': 'Windows non supporté pour scapy'}
        
        try:
            # Valider le sous-réseau
            network = ipaddress.ip_network(subnet, strict=False)
            
            results = {
                'scan': {
                    'type': 'scapy',
                    'subnet': str(network),
                    'timestamp': datetime.now().isoformat()
                },
                'hosts': []
            }
            
            # Créer un paquet ARP
            broadcast = str(network.broadcast_address)
            
            # Envoyer des requêtes ARP
            log.info(f"Scannage de {subnet} avec scapy...")
            
            ans, unans = scapy.arping(broadcast, timeout=timeout, verbose=0)
            
            # Traiter les réponses
            for sent, received in ans:
                host_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'status': 'online',
                    'timestamp': datetime.now().isoformat()
                }
                results['hosts'].append(host_info)
            
            results['hosts_found'] = len(results['hosts'])
            
            return results
            
        except Exception as e:
            log.error(f"Erreur lors du scan scapy: {e}")
            return {'error': str(e)}
    
    def discover_hosts(self, subnet, method='arp'):
        """
        Découvrir les hôtes sur le réseau
        
        Args:
            subnet: Sous-réseau à scanner
            method: Méthode de découverte ('arp', 'ping', 'nmap')
        
        Returns:
            list: Liste des hôtes découverts
        """
        hosts = []
        
        try:
            if method == 'arp':
                if HAS_SCAPY:
                    result = self.scan_with_scapy(subnet)
                    hosts = result.get('hosts', [])
                else:
                    log.error("scapy requis pour la découverte ARP")
            
            elif method == 'ping':
                network = ipaddress.ip_network(subnet, strict=False)
                all_ips = [str(ip) for ip in network.hosts()]
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = []
                    for ip in all_ips:
                        futures.append(executor.submit(self._ping_host, ip, 1))
                    
                    for future in concurrent.futures.as_completed(futures):
                        if future.result():
                            hosts.append({
                                'ip': future.result(),
                                'status': 'online'
                            })
            
            elif method == 'nmap':
                if HAS_NMAP:
                    result = self.scan_with_nmap(subnet, arguments=['-sn'])
                    hosts = result.get('hosts', [])
                else:
                    log.error("nmap requis pour la découverte nmap")
            
        except Exception as e:
            log.error(f"Erreur lors de la découverte des hôtes: {e}")
        
        return hosts
    
    def save_results(self, results, output_file=None):
        """
        Sauvegarder les résultats du scan
        
        Args:
            results: Résultats à sauvegarder
            output_file: Nom du fichier de sortie
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if not output_file:
                output_file = self.config.get('output_file', 'network_scan.json')
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str, ensure_ascii=False)
            
            log.info(f"Résultats sauvegardés dans {output_file}")
            return True
            
        except Exception as e:
            log.error(f"Erreur lors de la sauvegarde des résultats: {e}")
            return False
    
    def load_results(self, input_file=None):
        """
        Charger les résultats d'un scan précédent
        
        Args:
            input_file: Nom du fichier à charger
        
        Returns:
            dict: Résultats chargés
        """
        try:
            if not input_file:
                input_file = self.config.get('output_file', 'network_scan.json')
            
            with open(input_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
            
            log.info(f"Résultats chargés depuis {input_file}")
            return results
            
        except Exception as e:
            log.error(f"Erreur lors du chargement des résultats: {e}")
            return None
    
    def display_results(self, results):
        """
        Afficher les résultats du scan
        
        Args:
            results: Résultats à afficher
        """
        print(f"\n{'='*70}")
        print(f"RÉSULTATS DU SCAN RÉSEAU - NetGuard")
        print(f"{'='*70}")
        
        print(f"\nInformations générales:")
        print(f"  Sous-réseau: {results.get('subnet', 'N/A')}")
        print(f"  Type de scan: {results.get('scan_type', 'N/A')}")
        print(f"  Début: {results.get('scan_start', 'N/A')}")
        if 'statistics' in results:
            print(f"  Durée: {results['statistics'].get('scan_duration_seconds', 0):.2f}s")
            print(f"  Hôtes trouvés: {results['statistics'].get('hosts_found', 0)}")
            print(f"  Ports ouverts: {results['statistics'].get('open_ports', 0)}")
        
        print(f"\nHôtes découverts:")
        print(f"  {'IP':<15} {'Hostname':<25} {'MAC':<20} {'Ports ouverts':<15} {'OS':<15}")
        print(f"  {'-'*15} {'-'*25} {'-'*20} {'-'*15} {'-'*15}")
        
        for host in results.get('hosts', []):
            ip = host.get('ip', 'N/A')
            hostname = host.get('hostname', 'N/A')
            mac = host.get('mac', 'N/A')
            open_ports = host.get('open_ports', [])
            os_name = host.get('os', 'N/A')
            
            # Formater les ports ouverts
            ports_str = ', '.join(str(p['port']) for p in open_ports[:5])
            if len(open_ports) > 5:
                ports_str += f" (+{len(open_ports) - 5})"
            
            print(f"  {ip:<15} {hostname:<25} {mac:<20} {ports_str:<15} {os_name:<15}")
        
        print(f"\n{'='*70}")


def main(args=None):
    """
    Fonction principale pour le module de scan réseau
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Scanner le réseau pour découvrir les hôtes et services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python network_scan.py --subnet 192.168.1.0/24
  python network_scan.py --subnet 192.168.1.0/24 --scan-type deep --output scan_results.json
  python network_scan.py --discover --method arp --subnet 192.168.1.0/24
  python network_scan.py --nmap --target 192.168.1.1 --ports 1-1000
  python network_scan.py --display-results scan_results.json
        """
    )
    
    # Arguments principaux
    parser.add_argument('--subnet', type=str, default='192.168.1.0/24',
                        help='Sous-réseau à scanner (par défaut: 192.168.1.0/24)')
    parser.add_argument('--target', type=str,
                        help='Cible spécifique à scanner (IP ou nom d\'hôte)')
    
    # Arguments pour le scan
    parser.add_argument('--scan-type', type=str, choices=['quick', 'normal', 'deep'],
                        default='normal', help='Type de scan (par défaut: normal)')
    parser.add_argument('--ports', type=str,
                        help='Ports à scanner (ex: 22,80,443 ou 1-1000)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Timeout pour chaque test en secondes (par défaut: 5)')
    parser.add_argument('--max-threads', type=int, default=100,
                        help='Nombre maximum de threads (par défaut: 100)')
    
    # Arguments pour la découverte
    parser.add_argument('--discover', action='store_true',
                        help='Découvrir les hôtes (sans scan de ports)')
    parser.add_argument('--method', type=str, choices=['arp', 'ping', 'nmap'],
                        default='arp', help='Méthode de découverte (par défaut: arp)')
    
    # Arguments pour nmap
    parser.add_argument('--nmap', action='store_true',
                        help='Utiliser nmap pour le scan')
    parser.add_argument('--nmap-args', type=str,
                        help='Arguments supplémentaires pour nmap')
    parser.add_argument('--sudo', action='store_true',
                        help='Exécuter nmap avec sudo')
    
    # Arguments pour scapy
    parser.add_argument('--scapy', action='store_true',
                        help='Utiliser scapy pour le scan')
    
    # Arguments pour la sauvegarde
    parser.add_argument('--output', type=str,
                        help='Fichier de sortie pour les résultats')
    parser.add_argument('--save', action='store_true',
                        help='Sauvegarder les résultats')
    
    # Arguments pour le chargement
    parser.add_argument('--input', type=str,
                        help='Fichier d\'entrée pour charger les résultats')
    parser.add_argument('--display', action='store_true',
                        help='Afficher les résultats')
    parser.add_argument('--display-results', type=str,
                        help='Fichier de résultats à afficher')
    
    # Arguments de configuration
    parser.add_argument('--config', type=str,
                        help='Fichier de configuration YAML')
    
    # Arguments divers
    parser.add_argument('--json', action='store_true',
                        help='Afficher les résultats au format JSON')
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
    
    # Charger la configuration
    config = {}
    if args.config:
        try:
            import yaml
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f)
                if 'network' in config:
                    config = config['network']
        except Exception as e:
            log.error(f"Erreur lors du chargement de la configuration: {e}")
    
    # Créer le scanner réseau
    scanner = NetworkScanner(config)
    
    # Parser les ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            # Plage de ports
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            # Liste de ports
            ports = list(map(int, args.ports.split(',')))
    
    # Scan réseau
    if not any([args.discover, args.nmap, args.scapy, args.display, args.display_results, args.input]):
        target = args.target or args.subnet
        
        if args.nmap:
            results = scanner.scan_with_nmap(
                target=target,
                ports=ports,
                arguments=args.nmap_args,
                sudo=args.sudo
            )
        elif args.scapy:
            results = scanner.scan_with_scapy(target)
        else:
            results = scanner.scan_network(
                subnet=target,
                scan_type=args.scan_type,
                ports=ports,
                timeout=args.timeout,
                max_threads=args.max_threads
            )
        
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            scanner.display_results(results)
        
        if args.save or args.output:
            output_file = args.output or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            scanner.save_results(results, output_file)
    
    # Découverte des hôtes
    elif args.discover:
        hosts = scanner.discover_hosts(
            subnet=args.subnet,
            method=args.method
        )
        
        if args.json:
            print(json.dumps(hosts, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\nHôtes découverts ({len(hosts)}):")
            for host in hosts:
                print(f"  - {host.get('ip', 'N/A')} ({host.get('hostname', 'N/A')}) "
                      f"MAC: {host.get('mac', 'N/A')} Status: {host.get('status', 'N/A')}")
    
    # Scan avec nmap
    elif args.nmap:
        results = scanner.scan_with_nmap(
            target=args.target or args.subnet,
            ports=ports,
            arguments=args.nmap_args,
            sudo=args.sudo
        )
        
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            scanner.display_results(results)
        
        if args.save or args.output:
            output_file = args.output or f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            scanner.save_results(results, output_file)
    
    # Scan avec scapy
    elif args.scapy:
        results = scanner.scan_with_scapy(args.subnet)
        
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            scanner.display_results(results)
    
    # Afficher les résultats
    elif args.display or args.display_results:
        input_file = args.display_results or args.input
        results = scanner.load_results(input_file)
        
        if results:
            if args.json:
                print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
            else:
                scanner.display_results(results)
        else:
            print("Impossible de charger les résultats")
    
    # Charger les résultats
    elif args.input:
        results = scanner.load_results(args.input)
        
        if results:
            if args.json:
                print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
            else:
                print(f"Résultats chargés: {len(results.get('hosts', []))} hôtes")
        else:
            print("Impossible de charger les résultats")


if __name__ == "__main__":
    main()
