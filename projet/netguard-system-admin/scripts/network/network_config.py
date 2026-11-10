#!/usr/bin/env python3
"""
NetGuard - Module de configuration réseau

Ce module permet de configurer et gérer les interfaces réseau.

Fonctionnalités:
- Afficher la configuration réseau actuelle
- Configurer les interfaces réseau
- Gérer les adresses IP
- Configurer les routes
- Gérer les VLANs
- Configurer le bonding

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import json
import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    import pyroute2
    HAS_PYROUTE2 = True
except ImportError:
    HAS_PYROUTE2 = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class NetworkConfigurator:
    """Classe pour la configuration réseau"""
    
    def __init__(self, config=None):
        """
        Initialiser le configurateur réseau
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or self._load_default_config()
        self.interfaces = {}
        self.routes = {}
        
        # Charger la configuration actuelle
        self._load_current_config()
        
        log.info("NetworkConfigurator initialisé")
    
    def _load_default_config(self):
        """Charger la configuration par défaut"""
        return {
            'primary_interface': 'eth0',
            'dns_servers': ['8.8.8.8', '8.8.4.4'],
            'search_domains': []
        }
    
    def _load_current_config(self):
        """Charger la configuration réseau actuelle"""
        try:
            self.interfaces = self._get_interfaces()
            self.routes = self._get_routes()
        except Exception as e:
            log.error(f"Erreur lors du chargement de la configuration réseau: {e}")
    
    def _get_interfaces(self):
        """
        Obtenir la liste des interfaces réseau
        
        Returns:
            dict: Informations sur les interfaces
        """
        interfaces = {}
        
        if HAS_NETIFACES:
            for iface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if_stat = netifaces.ifaddresses(iface)
                    
                    interface_info = {
                        'name': iface,
                        'addresses': {},
                        'mac': None,
                        'flags': [],
                        'mtu': None,
                        'up': False,
                        'statistics': {}
                    }
                    
                    # Adresses IP
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if 'addr' in addr:
                                interface_info['addresses']['ipv4'] = addr
                    
                    if netifaces.AF_INET6 in addrs:
                        for addr in addrs[netifaces.AF_INET6]:
                            if 'addr' in addr:
                                if 'ipv6' not in interface_info['addresses']:
                                    interface_info['addresses']['ipv6'] = []
                                interface_info['addresses']['ipv6'].append(addr)
                    
                    # Adresse MAC
                    if netifaces.AF_LINK in addrs:
                        for addr in addrs[netifaces.AF_LINK]:
                            if 'addr' in addr:
                                interface_info['mac'] = addr['addr']
                    
                    # Flags
                    interface_info['flags'] = []
                    if netifaces.ifaddresses(iface).get(netifaces.AF_INET):
                        interface_info['flags'].append('IPV4')
                    if netifaces.ifaddresses(iface).get(netifaces.AF_INET6):
                        interface_info['flags'].append('IPV6')
                    if netifaces.ifaddresses(iface).get(netifaces.AF_LINK):
                        interface_info['flags'].append('LINK')
                    
                    # MTU
                    try:
                        import fcntl
                        import struct
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        ifreq = struct.pack('256s', iface[:15].encode('utf-8'))
                        mtu = fcntl.ioctl(s.fileno(), 0x8921, ifreq)[16:20]
                        interface_info['mtu'] = struct.unpack('I', mtu)[0]
                    except:
                        pass
                    
                    # État de l'interface
                    try:
                        if_stat = netifaces.ifaddresses(iface)
                        interface_info['up'] = iface in netifaces.interfaces()
                    except:
                        interface_info['up'] = False
                    
                    interfaces[iface] = interface_info
                    
                except Exception as e:
                    log.warning(f"Impossible de récupérer les informations de l'interface {iface}: {e}")
        
        else:
            # Méthode alternative avec ifconfig
            if platform.system() == "Linux" or platform.system() == "Darwin":
                try:
                    result = helpers.execute_command(['ifconfig', '-a'], capture_output=True)
                    if result['success']:
                        # Parser la sortie ifconfig
                        current_iface = None
                        for line in result['stdout'].split('\n'):
                            line = line.strip()
                            if not line or line.startswith(' ') or line.startswith('\t'):
                                continue
                            
                            # Nouvelle interface
                            if ':' in line and not line.startswith(' '):
                                current_iface = line.split(':')[0]
                                interfaces[current_iface] = {
                                    'name': current_iface,
                                    'addresses': {},
                                    'mac': None,
                                    'flags': [],
                                    'mtu': None,
                                    'up': 'UP' in line,
                                    'statistics': {}
                                }
                            elif current_iface:
                                iface = interfaces[current_iface]
                                
                                # Adresse IP
                                if 'inet ' in line:
                                    parts = line.split()
                                    addr_index = parts.index('inet') + 1
                                    netmask_index = parts.index('netmask') + 1
                                    if addr_index < len(parts):
                                        iface['addresses']['ipv4'] = {
                                            'addr': parts[addr_index].split(':')[0]
                                        }
                                    if netmask_index < len(parts):
                                        iface['addresses']['ipv4']['netmask'] = parts[netmask_index]
                                
                                # Adresse IPv6
                                if 'inet6' in line:
                                    parts = line.split()
                                    addr_index = parts.index('inet6') + 1
                                    if addr_index < len(parts):
                                        if 'ipv6' not in iface['addresses']:
                                            iface['addresses']['ipv6'] = []
                                        iface['addresses']['ipv6'].append({
                                            'addr': parts[addr_index].split('%')[0]
                                        })
                                
                                # Adresse MAC
                                if 'ether' in line:
                                    parts = line.split()
                                    addr_index = parts.index('ether') + 1
                                    if addr_index < len(parts):
                                        iface['mac'] = parts[addr_index]
                                
                                # MTU
                                if 'mtu' in line:
                                    parts = line.split()
                                    mtu_index = parts.index('mtu') + 1
                                    if mtu_index < len(parts):
                                        iface['mtu'] = int(parts[mtu_index])
                except Exception as e:
                    log.error(f"Erreur lors de l'exécution de ifconfig: {e}")
        
        return interfaces
    
    def _get_routes(self):
        """
        Obtenir la table de routage
        
        Returns:
            dict: Table de routage
        """
        routes = {}
        
        try:
            if platform.system() == "Linux" or platform.system() == "Darwin":
                result = helpers.execute_command(['route', '-n'], capture_output=True)
                if result['success']:
                    # Parser la sortie route -n
                    for line in result['stdout'].split('\n')[2:]:
                        parts = line.split()
                        if len(parts) >= 8:
                            route_info = {
                                'destination': parts[0],
                                'gateway': parts[1],
                                'genmask': parts[2],
                                'flags': parts[3],
                                'metric': parts[4],
                                'ref': parts[5],
                                'use': parts[6],
                                'interface': parts[7]
                            }
                            routes[parts[0]] = route_info
            elif platform.system() == "Windows":
                result = helpers.execute_command(['route', 'print'], capture_output=True)
                if result['success']:
                    # Parser la sortie route print sous Windows
                    # (implémentation simplifiée)
                    pass
        except Exception as e:
            log.error(f"Erreur lors de la récupération des routes: {e}")
        
        return routes
    
    def show_config(self):
        """
        Afficher la configuration réseau actuelle
        
        Returns:
            dict: Configuration réseau
        """
        config = {
            'timestamp': datetime.now().isoformat(),
            'hostname': platform.node(),
            'os': f"{platform.system()} {platform.release()}",
            'interfaces': self.interfaces,
            'routes': self.routes,
            'dns': self._get_dns_config()
        }
        
        # Afficher la configuration
        print(f"\n{'='*70}")
        print(f"CONFIGURATION RÉSEAU - {platform.node()}")
        print(f"{'='*70}")
        
        # Informations système
        print(f"\nSystème: {config['os']}")
        print(f"Nom d'hôte: {config['hostname']}")
        print(f"Date: {config['timestamp']}")
        
        # Interfaces réseau
        print(f"\nInterfaces réseau:")
        for name, iface in config['interfaces'].items():
            print(f"\n  {name}:")
            print(f"    État: {'UP' if iface.get('up') else 'DOWN'}")
            if iface.get('mac'):
                print(f"    MAC: {iface['mac']}")
            if iface.get('mtu'):
                print(f"    MTU: {iface['mtu']}")
            if iface.get('flags'):
                print(f"    Flags: {', '.join(iface['flags'])}")
            
            # Adresses IP
            if 'addresses' in iface:
                for addr_type, addr_info in iface['addresses'].items():
                    if addr_type == 'ipv4':
                        ip = addr_info.get('addr', 'N/A')
                        netmask = addr_info.get('netmask', 'N/A')
                        print(f"    IPv4: {ip}")
                        print(f"    Netmask: {netmask}")
                    elif addr_type == 'ipv6':
                        for addr in addr_info:
                            print(f"    IPv6: {addr.get('addr', 'N/A')}")
        
        # Table de routage
        print(f"\nTable de routage:")
        for dest, route in config['routes'].items():
            print(f"  {dest:20} -> {route['gateway']:15} via {route['interface']:10} "
                  f"({route['flags']}) Metric: {route['metric']}")
        
        # Configuration DNS
        print(f"\nConfiguration DNS:")
        dns_config = config['dns']
        if dns_config.get('servers'):
            print(f"  Serveurs: {', '.join(dns_config['servers'])}")
        if dns_config.get('search_domains'):
            print(f"  Domaines de recherche: {', '.join(dns_config['search_domains'])}")
        
        print(f"\n{'='*70}")
        
        return config
    
    def _get_dns_config(self):
        """
        Obtenir la configuration DNS
        
        Returns:
            dict: Configuration DNS
        """
        dns_config = {'servers': [], 'search_domains': []}
        
        try:
            # Lire /etc/resolv.conf sur Linux
            if platform.system() == "Linux":
                resolv_conf = "/etc/resolv.conf"
                if os.path.exists(resolv_conf):
                    with open(resolv_conf, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('nameserver'):
                                dns_config['servers'].append(line.split()[1])
                            elif line.startswith('search'):
                                dns_config['search_domains'] = line.split()[1:]
            
            # Sur Windows
            elif platform.system() == "Windows":
                result = helpers.execute_command(['ipconfig', '/all'], capture_output=True)
                if result['success']:
                    for line in result['stdout'].split('\n'):
                        if 'DNS Servers' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                dns_config['servers'].extend(parts[1].strip().split())
                        elif 'Connection-specific DNS Suffix' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                dns_config['search_domains'].append(parts[1].strip())
        except Exception as e:
            log.error(f"Erreur lors de la récupération de la configuration DNS: {e}")
        
        return dns_config
    
    def set_ip_address(self, interface, ip_address, netmask=None, broadcast=None, gateway=None):
        """
        Configurer une adresse IP sur une interface
        
        Args:
            interface: Nom de l'interface
            ip_address: Adresse IP
            netmask: Masque de sous-réseau
            broadcast: Adresse de broadcast
            gateway: Passerelle par défaut
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                # Utiliser la commande ip
                command = ['ip', 'addr', 'add', f'{ip_address}/{netmask}' if netmask else ip_address, 'dev', interface]
                
                result = helpers.execute_command(command, capture_output=True, shell=False)
                
                if result['success']:
                    # Configurer la passerelle si spécifiée
                    if gateway:
                        self.set_default_gateway(gateway, interface)
                    
                    # Redémarrer l'interface
                    self._restart_interface(interface)
                    
                    log.info(f"Adresse IP configurée: {ip_address} sur {interface}")
                    return True
                else:
                    log.error(f"Échec de la configuration IP: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                # Utiliser netsh sur Windows
                command = f'netsh interface ip set address name="{interface}" static {ip_address} {netmask if netmask else "255.255.255.0"} {gateway if gateway else ""}'
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Adresse IP configurée: {ip_address} sur {interface}")
                    return True
                else:
                    log.error(f"Échec de la configuration IP: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de la configuration de l'adresse IP: {e}")
            return False
    
    def _restart_interface(self, interface):
        """
        Redémarrer une interface
        
        Args:
            interface: Nom de l'interface
        """
        try:
            if platform.system() == "Linux":
                # Désactiver puis activer l'interface
                helpers.execute_command(['ip', 'link', 'set', interface, 'down'], capture_output=True)
                time.sleep(1)
                helpers.execute_command(['ip', 'link', 'set', interface, 'up'], capture_output=True)
                
                log.info(f"Interface {interface} redémarrée")
        except Exception as e:
            log.error(f"Erreur lors du redémarrage de l'interface {interface}: {e}")
    
    def set_default_gateway(self, gateway, interface=None):
        """
        Configurer la passerelle par défaut
        
        Args:
            gateway: Adresse de la passerelle
            interface: Interface à utiliser (optionnel)
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                # Supprimer la passerelle existante
                helpers.execute_command(['ip', 'route', 'del', 'default'], capture_output=True)
                
                # Ajouter la nouvelle passerelle
                command = ['ip', 'route', 'add', 'default', 'via', gateway]
                if interface:
                    command.append('dev')
                    command.append(interface)
                
                result = helpers.execute_command(command, capture_output=True)
                
                if result['success']:
                    log.info(f"Passerelle par défaut configurée: {gateway}")
                    return True
                else:
                    log.error(f"Échec de la configuration de la passerelle: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                command = f'netsh interface ip set address name="{interface}" gateway={gateway}'
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Passerelle par défaut configurée: {gateway}")
                    return True
                else:
                    log.error(f"Échec de la configuration de la passerelle: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de la configuration de la passerelle: {e}")
            return False
    
    def set_dns_servers(self, servers, interface=None):
        """
        Configurer les serveurs DNS
        
        Args:
            servers: Liste des serveurs DNS
            interface: Interface spécifique (optionnel)
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                # Écrire dans /etc/resolv.conf
                with open('/etc/resolv.conf', 'w') as f:
                    f.write("# Généré par NetGuard\n")
                    f.write("# Date: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n\n")
                    
                    for server in servers:
                        f.write(f"nameserver {server}\n")
                    
                    # Ajouter les domaines de recherche si spécifiés
                    if self.config.get('search_domains'):
                        f.write(f"search {' '.join(self.config['search_domains'])}\n")
                
                log.info(f"Serveurs DNS configurés: {', '.join(servers)}")
                return True
            
            elif platform.system() == "Windows":
                for server in servers:
                    command = f'netsh interface ip add dns name="{interface}" {server}'
                    result = helpers.execute_command(command, capture_output=True, shell=True)
                    if not result['success']:
                        log.error(f"Échec de l'ajout du serveur DNS {server}")
                        return False
                
                log.info(f"Serveurs DNS configurés: {', '.join(servers)}")
                return True
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de la configuration des serveurs DNS: {e}")
            return False
    
    def add_route(self, destination, gateway, interface=None, metric=None):
        """
        Ajouter une route
        
        Args:
            destination: Destination de la route
            gateway: Passerelle
            interface: Interface à utiliser (optionnel)
            metric: Métrique (optionnel)
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                command = ['ip', 'route', 'add', destination, 'via', gateway]
                
                if interface:
                    command.append('dev')
                    command.append(interface)
                
                if metric:
                    command.append('metric')
                    command.append(str(metric))
                
                result = helpers.execute_command(command, capture_output=True)
                
                if result['success']:
                    log.info(f"Route ajoutée: {destination} via {gateway}")
                    return True
                else:
                    log.error(f"Échec de l'ajout de la route: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                command = f'netsh interface ipv4 add route {destination} {gateway}'
                if interface:
                    command += f" interface={interface}"
                if metric:
                    command += f" metric={metric}"
                
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Route ajoutée: {destination} via {gateway}")
                    return True
                else:
                    log.error(f"Échec de l'ajout de la route: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de l'ajout de la route: {e}")
            return False
    
    def remove_route(self, destination):
        """
        Supprimer une route
        
        Args:
            destination: Destination de la route
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                command = ['ip', 'route', 'del', destination]
                result = helpers.execute_command(command, capture_output=True)
                
                if result['success']:
                    log.info(f"Route supprimée: {destination}")
                    return True
                else:
                    log.error(f"Échec de la suppression de la route: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                command = f'netsh interface ipv4 delete route {destination}'
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Route supprimée: {destination}")
                    return True
                else:
                    log.error(f"Échec de la suppression de la route: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de la suppression de la route: {e}")
            return False
    
    def interface_up(self, interface):
        """
        Activer une interface
        
        Args:
            interface: Nom de l'interface
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                command = ['ip', 'link', 'set', interface, 'up']
                result = helpers.execute_command(command, capture_output=True)
                
                if result['success']:
                    log.info(f"Interface activée: {interface}")
                    return True
                else:
                    log.error(f"Échec de l'activation de l'interface: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                command = f'netsh interface set interface "{interface}" admin=enable'
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Interface activée: {interface}")
                    return True
                else:
                    log.error(f"Échec de l'activation de l'interface: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de l'activation de l'interface: {e}")
            return False
    
    def interface_down(self, interface):
        """
        Désactiver une interface
        
        Args:
            interface: Nom de l'interface
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if platform.system() == "Linux":
                command = ['ip', 'link', 'set', interface, 'down']
                result = helpers.execute_command(command, capture_output=True)
                
                if result['success']:
                    log.info(f"Interface désactivée: {interface}")
                    return True
                else:
                    log.error(f"Échec de la désactivation de l'interface: {result['stderr']}")
                    return False
            
            elif platform.system() == "Windows":
                command = f'netsh interface set interface "{interface}" admin=disable'
                result = helpers.execute_command(command, capture_output=True, shell=True)
                
                if result['success']:
                    log.info(f"Interface désactivée: {interface}")
                    return True
                else:
                    log.error(f"Échec de la désactivation de l'interface: {result['stderr']}")
                    return False
            
            else:
                log.error(f"Système non supporté: {platform.system()}")
                return False
                
        except Exception as e:
            log.error(f"Erreur lors de la désactivation de l'interface: {e}")
            return False
    
    def check_connectivity(self, host, timeout=5):
        """
        Vérifier la connectivité avec un hôte
        
        Args:
            host: Hôte ou IP à vérifier
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultat du test de connectivité
        """
        result = {
            'host': host,
            'success': False,
            'type': 'unknown',
            'latency': None,
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Vérifier avec ping
            start_time = time.time()
            
            if platform.system() == "Windows":
                command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), host]
            else:
                command = ['ping', '-c', '1', '-W', str(timeout), host]
            
            output = helpers.execute_command(command, timeout=timeout + 1, capture_output=True)
            
            end_time = time.time()
            result['latency'] = end_time - start_time
            result['latency_ms'] = round((end_time - start_time) * 1000, 2)
            
            if output['success'] and 'ttl=' in output['stdout'].lower():
                result['success'] = True
                result['type'] = 'icmp'
            else:
                result['error'] = output['stderr']
            
            # Si ping échoue, essayer TCP
            if not result['success']:
                try:
                    import socket
                    start_time = time.time()
                    socket.create_connection((host, 80), timeout=timeout)
                    end_time = time.time()
                    result['latency'] = end_time - start_time
                    result['latency_ms'] = round((end_time - start_time) * 1000, 2)
                    result['success'] = True
                    result['type'] = 'tcp'
                except Exception as e:
                    result['error'] = str(e)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


import time
import socket

def main(args=None):
    """
    Fonction principale pour le module de configuration réseau
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Configurer et gérer les interfaces réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python network_config.py --show
  python network_config.py --set-ip eth0 192.168.1.100 255.255.255.0 192.168.1.1
  python network_config.py --set-dns 8.8.8.8,8.8.4.4
  python network_config.py --add-route 10.0.0.0/24 192.168.1.1 eth0
  python network_config.py --remove-route 10.0.0.0/24
  python network_config.py --interface-up eth0
  python network_config.py --interface-down eth0
  python network_config.py --set-gateway 192.168.1.1 eth0
  python network_config.py --check google.com
        """
    )
    
    # Arguments pour l'affichage
    parser.add_argument('--show', action='store_true',
                        help='Afficher la configuration réseau actuelle')
    
    # Arguments pour la configuration IP
    parser.add_argument('--set-ip', type=str, nargs=4,
                        metavar=('INTERFACE', 'IP', 'NETMASK', 'GATEWAY'),
                        help='Configurer une adresse IP (set-ip INTERFACE IP NETMASK GATEWAY)')
    parser.add_argument('--remove-ip', type=str, nargs=2,
                        metavar=('INTERFACE', 'IP'),
                        help='Supprimer une adresse IP')
    
    # Arguments pour la passerelle
    parser.add_argument('--set-gateway', type=str, nargs='+',
                        metavar=('GATEWAY', 'INTERFACE'),
                        help='Configurer la passerelle par défaut')
    parser.add_argument('--remove-gateway', action='store_true',
                        help='Supprimer la passerelle par défaut')
    
    # Arguments pour DNS
    parser.add_argument('--set-dns', type=str,
                        help='Configurer les serveurs DNS (séparés par des virgules)')
    parser.add_argument('--add-dns', type=str,
                        help='Ajouter un serveur DNS')
    parser.add_argument('--remove-dns', type=str,
                        help='Supprimer un serveur DNS')
    
    # Arguments pour les routes
    parser.add_argument('--add-route', type=str, nargs=3,
                        metavar=('DESTINATION', 'GATEWAY', 'INTERFACE'),
                        help='Ajouter une route')
    parser.add_argument('--remove-route', type=str,
                        metavar='DESTINATION',
                        help='Supprimer une route')
    
    # Arguments pour les interfaces
    parser.add_argument('--interface-up', type=str,
                        metavar='INTERFACE',
                        help='Activer une interface')
    parser.add_argument('--interface-down', type=str,
                        metavar='INTERFACE',
                        help='Désactiver une interface')
    
    # Arguments pour la connectivité
    parser.add_argument('--check', type=str,
                        metavar='HOST',
                        help='Vérifier la connectivité avec un hôte')
    parser.add_argument('--check-timeout', type=int, default=5,
                        help='Timeout pour le test de connectivité (par défaut: 5)')
    
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
    
    # Créer le configurateur réseau
    configurator = NetworkConfigurator()
    
    # Afficher la configuration
    if args.show:
        config = configurator.show_config()
        
        if args.json:
            # Nettoyer les objets non sérialisables
            import json
            clean_config = json.loads(json.dumps(config, default=str))
            print(json.dumps(clean_config, indent=2, ensure_ascii=False))
    
    # Configurer une adresse IP
    elif args.set_ip:
        interface, ip, netmask, gateway = args.set_ip
        success = configurator.set_ip_address(interface, ip, netmask, None, gateway)
        
        if success:
            print(f"✓ Adresse IP configurée: {ip}/{netmask} sur {interface}")
            if gateway:
                print(f"✓ Passerelle configurée: {gateway}")
        else:
            print(f"✗ Échec de la configuration de l'adresse IP")
            sys.exit(1)
    
    # Supprimer une adresse IP
    elif args.remove_ip:
        interface, ip = args.remove_ip
        # Implémentation simplifiée
        print(f"Suppression de l'adresse IP {ip} sur {interface} (non implémenté)")
    
    # Configurer la passerelle
    elif args.set_gateway:
        if len(args.set_gateway) == 1:
            gateway = args.set_gateway[0]
            success = configurator.set_default_gateway(gateway)
        elif len(args.set_gateway) == 2:
            gateway, interface = args.set_gateway
            success = configurator.set_default_gateway(gateway, interface)
        else:
            print("Erreur: nombre d'arguments incorrect")
            sys.exit(1)
        
        if success:
            print(f"✓ Passerelle configurée: {gateway}")
        else:
            print(f"✗ Échec de la configuration de la passerelle")
            sys.exit(1)
    
    # Configurer DNS
    elif args.set_dns:
        servers = args.set_dns.split(',')
        success = configurator.set_dns_servers(servers)
        
        if success:
            print(f"✓ Serveurs DNS configurés: {', '.join(servers)}")
        else:
            print(f"✗ Échec de la configuration des serveurs DNS")
            sys.exit(1)
    
    # Ajouter une route
    elif args.add_route:
        destination, gateway, interface = args.add_route
        success = configurator.add_route(destination, gateway, interface)
        
        if success:
            print(f"✓ Route ajoutée: {destination} via {gateway} sur {interface}")
        else:
            print(f"✗ Échec de l'ajout de la route")
            sys.exit(1)
    
    # Supprimer une route
    elif args.remove_route:
        success = configurator.remove_route(args.remove_route)
        
        if success:
            print(f"✓ Route supprimée: {args.remove_route}")
        else:
            print(f"✗ Échec de la suppression de la route")
            sys.exit(1)
    
    # Activer une interface
    elif args.interface_up:
        success = configurator.interface_up(args.interface_up)
        
        if success:
            print(f"✓ Interface activée: {args.interface_up}")
        else:
            print(f"✗ Échec de l'activation de l'interface")
            sys.exit(1)
    
    # Désactiver une interface
    elif args.interface_down:
        success = configurator.interface_down(args.interface_down)
        
        if success:
            print(f"✓ Interface désactivée: {args.interface_down}")
        else:
            print(f"✗ Échec de la désactivation de l'interface")
            sys.exit(1)
    
    # Vérifier la connectivité
    elif args.check:
        result = configurator.check_connectivity(args.check, args.check_timeout)
        
        if args.json:
            print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        else:
            if result['success']:
                print(f"✓ {result['host']} est accessible")
                print(f"  Type: {result['type']}")
                print(f"  Latence: {result['latency_ms']} ms")
            else:
                print(f"✗ {result['host']} n'est pas accessible")
                if result['error']:
                    print(f"  Erreur: {result['error']}")
    
    # Par défaut: afficher la configuration
    else:
        configurator.show_config()


if __name__ == "__main__":
    main()
