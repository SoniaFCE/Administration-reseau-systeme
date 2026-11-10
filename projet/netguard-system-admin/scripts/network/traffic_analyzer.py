#!/usr/bin/env python3
"""
NetGuard - Analyseur de trafic réseau

Ce module permet d'analyser le trafic réseau en temps réel.

Fonctionnalités:
- Surveillance du trafic réseau
- Analyse des connexions actives
- Statistiques par protocole
- Analyse des ports
- Détection des anomalies
- Journalisation du trafic
- Analyse des paquets (si supporté)

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
from collections import Counter, defaultdict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class TrafficAnalyzer:
    """Classe pour l'analyse du trafic réseau"""
    
    def __init__(self, config=None):
        """
        Initialiser l'analyseur de trafic
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or self._load_default_config()
        self.results = []
        self.connections = []
        self.statistics = {}
        
        # Historique des analyses
        self.history = []
        
        log.info("TrafficAnalyzer initialisé")
    
    def _load_default_config(self):
        """Charger la configuration par défaut"""
        return {
            'interface': None,  # Interface réseau (None = toutes)
            'duration': 60,     # Durée de capture en secondes
            'top_ports': 10,    # Nombre de ports à afficher
            'top_ips': 10,      # Nombre d'IPs à afficher
            'save_pcap': False,  # Sauvegarder le fichier pcap
            'alerts': {
                'high_traffic': 1000000,  # 1 Mo/s
                'port_scan': True,       # Détection de scan de ports
                'new_service': True     # Détection de nouveaux services
            }
        }
    
    def get_network_interfaces(self):
        """
        Obtenir la liste des interfaces réseau
        
        Returns:
            list: Liste des interfaces réseau
        """
        interfaces = []
        
        if HAS_PSUTIL:
            for interface, addrs in psutil.net_if_addrs().items():
                interfaces.append({
                    'name': interface,
                    'addresses': [{'family': addr.family.name, 'address': addr.address} for addr in addrs]
                })
        else:
            # Méthode alternative
            try:
                if platform.system() == "Windows":
                    output = helpers.execute_command("ipconfig /all", capture_output=True)
                    if output['success']:
                        interfaces = self._parse_windows_interfaces(output['stdout'])
                else:
                    output = helpers.execute_command("ifconfig -a", capture_output=True)
                    if output['success']:
                        interfaces = self._parse_unix_interfaces(output['stdout'])
            except:
                pass
        
        return interfaces
    
    def _parse_windows_interfaces(self, output):
        """Parser la sortie d'ipconfig pour Windows"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Détection d'une nouvelle interface
            if line.endswith(':') or 'Ethernet' in line or 'Wi-Fi' in line:
                if current_interface:
                    interfaces.append(current_interface)
                current_interface = {'name': line.rstrip(':').strip(), 'addresses': []}
            
            # Adresses IPv4
            elif 'Adresse IPv4' in line or 'IPv4 Address' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    ip = parts[1].strip()
                    current_interface['addresses'].append({'family': 'ipv4', 'address': ip})
            
            # Adresses IPv6
            elif 'Adresse IPv6' in line or 'IPv6 Address' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    ip = parts[1].strip()
                    current_interface['addresses'].append({'family': 'ipv6', 'address': ip})
            
            # Adresse MAC
            elif 'Adresse physique' in line or 'Physical Address' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    mac = parts[1].strip()
                    current_interface['addresses'].append({'family': 'mac', 'address': mac})
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_unix_interfaces(self, output):
        """Parser la sortie d'ifconfig pour Unix"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Détection d'une nouvelle interface (ligne sans espace au début)
            if line and not line.startswith(' ') and not line.startswith('\t'):
                if current_interface:
                    interfaces.append(current_interface)
                # Extraire le nom de l'interface
                parts = line.split(':')
                current_interface = {'name': parts[0].strip(), 'addresses': []}
            
            # Adresse IP
            elif line.startswith('inet '):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    current_interface['addresses'].append({'family': 'ipv4', 'address': ip})
            
            # Adresse IPv6
            elif line.startswith('inet6 '):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    current_interface['addresses'].append({'family': 'ipv6', 'address': ip})
            
            # Adresse MAC
            elif 'ether' in line.lower():
                parts = line.split()
                for part in parts:
                    if ':' in part and len(part.split(':')) == 6:
                        current_interface['addresses'].append({'family': 'mac', 'address': part})
                        break
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def get_connections(self, interface=None, protocol=None, state=None):
        """
        Obtenir la liste des connexions réseau actives
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            protocol: Protocole (tcp, udp, etc.)
            state: État de la connexion
        
        Returns:
            list: Liste des connexions
        """
        connections = []
        
        if HAS_PSUTIL:
            for conn in psutil.net_connections():
                # Filtrer par interface
                if interface and conn.nisname != interface:
                    continue
                
                # Filtrer par protocole
                if protocol and conn.type.name.lower() != protocol.lower():
                    continue
                
                # Filtrer par état
                if state and conn.status.lower() != state.lower():
                    continue
                
                connection = {
                    'type': conn.type.name,
                    'laddr': {'ip': conn.laddr.ip, 'port': conn.laddr.port} if conn.laddr else None,
                    'raddr': {'ip': conn.raddr.ip, 'port': conn.raddr.port} if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'nisname': conn.nisname
                }
                
                # Ajouter le nom du processus si disponible
                try:
                    if conn.pid:
                        p = psutil.Process(conn.pid)
                        connection['process_name'] = p.name()
                except:
                    pass
                
                connections.append(connection)
        else:
            # Méthode alternative avec netstat
            try:
                if platform.system() == "Windows":
                    command = "netstat -ano"
                else:
                    command = "netstat -tulnp"
                
                output = helpers.execute_command(command, capture_output=True)
                if output['success']:
                    connections = self._parse_netstat_output(output['stdout'])
            except Exception as e:
                log.error(f"Erreur lors de l'exécution de netstat: {e}")
        
        self.connections = connections
        return connections
    
    def _parse_netstat_output(self, output):
        """Parser la sortie de netstat"""
        connections = []
        lines = output.split('\n')
        
        # Sauter les lignes d'en-tête
        skip_header = True
        
        for line in lines:
            if not line.strip():
                continue
            
            # Sauter l'en-tête
            if skip_header:
                if 'Proto' in line and 'Local Address' in line:
                    skip_header = False
                continue
            
            parts = line.split()
            
            if len(parts) >= 5:
                connection = {
                    'type': parts[0].lower(),
                    'laddr': self._parse_address(parts[3]),
                    'raddr': self._parse_address(parts[4]) if len(parts) > 4 and parts[4] != '*' else None,
                    'status': parts[5] if len(parts) > 5 else 'unknown'
                }
                
                # Ajouter le PID si disponible (Windows)
                if len(parts) >= 6 and parts[5].isdigit():
                    connection['pid'] = int(parts[5])
                
                connections.append(connection)
        
        return connections
    
    def _parse_address(self, address):
        """Parser une adresse au format IP:PORT"""
        if not address or address == '*' or address == '0.0.0.0:*':
            return None
        
        parts = address.split(':')
        if len(parts) >= 2:
            return {
                'ip': parts[0] if parts[0] != '*' and parts[0] != '0.0.0.0' else None,
                'port': int(parts[-1]) if parts[-1].isdigit() else None
            }
        
        return None
    
    def get_traffic_stats(self, interface=None, duration=60):
        """
        Obtenir les statistiques de trafic réseau
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée de mesure en secondes
        
        Returns:
            dict: Statistiques de trafic
        """
        stats = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'interfaces': {},
            'total': {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'errors_in': 0,
                'errors_out': 0
            }
        }
        
        if HAS_PSUTIL:
            # Obtenir les statistiques avant
            start_stats = psutil.net_io_counters(pernic=True)
            
            # Attendre la durée spécifiée
            time.sleep(duration)
            
            # Obtenir les statistiques après
            end_stats = psutil.net_io_counters(pernic=True)
            
            # Calculer les différences
            for interface_name, start in start_stats.items():
                if interface and interface_name != interface:
                    continue
                
                end = end_stats.get(interface_name, psutil._common.snetio())
                
                interface_stats = {
                    'bytes_sent': end.bytes_sent - start.bytes_sent,
                    'bytes_recv': end.bytes_recv - start.bytes_recv,
                    'packets_sent': end.packets_sent - start.packets_sent,
                    'packets_recv': end.packets_recv - start.packets_recv,
                    'errors_in': end.errin - start.errin,
                    'errors_out': end.errout - start.errout,
                    'dropin': end.dropin - start.dropin,
                    'dropout': end.dropout - start.dropout
                }
                
                # Calculer les taux
                interface_stats['rate_sent'] = round(interface_stats['bytes_sent'] / duration, 2)
                interface_stats['rate_recv'] = round(interface_stats['bytes_recv'] / duration, 2)
                interface_stats['rate_sent_mbps'] = round(interface_stats['bytes_sent'] * 8 / duration / 1000000, 2)
                interface_stats['rate_recv_mbps'] = round(interface_stats['bytes_recv'] * 8 / duration / 1000000, 2)
                
                stats['interfaces'][interface_name] = interface_stats
                
                # Ajouter au total
                stats['total']['bytes_sent'] += interface_stats['bytes_sent']
                stats['total']['bytes_recv'] += interface_stats['bytes_recv']
                stats['total']['packets_sent'] += interface_stats['packets_sent']
                stats['total']['packets_recv'] += interface_stats['packets_recv']
                stats['total']['errors_in'] += interface_stats['errors_in']
                stats['total']['errors_out'] += interface_stats['errors_out']
            
            # Calculer les taux totaux
            stats['total']['rate_sent'] = round(stats['total']['bytes_sent'] / duration, 2)
            stats['total']['rate_recv'] = round(stats['total']['bytes_recv'] / duration, 2)
            stats['total']['rate_sent_mbps'] = round(stats['total']['bytes_sent'] * 8 / duration / 1000000, 2)
            stats['total']['rate_recv_mbps'] = round(stats['total']['bytes_recv'] * 8 / duration / 1000000, 2)
        else:
            # Méthode alternative avec ifconfig ou ip
            try:
                if platform.system() == "Windows":
                    command = "wmic path Win32_PerfFormattedData_Tcpip_NetworkInterface get * /format:csv"
                else:
                    command = f"ip -s link show {interface}" if interface else "ip -s link"
                
                output = helpers.execute_command(command, capture_output=True)
                if output['success']:
                    stats = self._parse_traffic_stats_output(output['stdout'], duration)
            except Exception as e:
                log.error(f"Erreur lors de l'exécution de la commande de trafic: {e}")
        
        self.statistics = stats
        return stats
    
    def _parse_traffic_stats_output(self, output, duration):
        """Parser la sortie des commandes de statistiques de trafic"""
        stats = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'interfaces': {},
            'total': {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'errors_in': 0,
                'errors_out': 0
            }
        }
        
        # Linux (ip -s link)
        if 'RX' in output and 'TX' in output:
            lines = output.split('\n')
            current_interface = None
            
            for line in lines:
                line = line.strip()
                
                # Détection d'une interface
                if line and ':' in line and 'RX' not in line and 'TX' not in line:
                    parts = line.split(':')
                    current_interface = parts[1].strip()
                    stats['interfaces'][current_interface] = {
                        'bytes_sent': 0,
                        'bytes_recv': 0,
                        'packets_sent': 0,
                        'packets_recv': 0
                    }
                
                # Lignes RX/TX
                elif 'RX' in line or 'TX' in line:
                    if current_interface and current_interface in stats['interfaces']:
                        parts = line.split()
                        
                        if 'RX' in line:
                            # RX: bytes packets errs drop overrun mcast
                            if len(parts) >= 2:
                                stats['interfaces'][current_interface]['bytes_recv'] = int(parts[1].split(':')[0])
                                stats['interfaces'][current_interface]['packets_recv'] = int(parts[2].split(':')[0])
                                stats['interfaces'][current_interface]['errors_in'] = int(parts[3].split(':')[0])
                        
                        elif 'TX' in line:
                            # TX: bytes packets errs drop carrier collsns
                            if len(parts) >= 2:
                                stats['interfaces'][current_interface]['bytes_sent'] = int(parts[1].split(':')[0])
                                stats['interfaces'][current_interface]['packets_sent'] = int(parts[2].split(':')[0])
                                stats['interfaces'][current_interface]['errors_out'] = int(parts[3].split(':')[0])
        
        # Windows (wmic)
        elif 'Win32_PerfFormattedData_Tcpip_NetworkInterface' in output:
            # Parser le CSV
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                headers = [h.strip() for h in lines[0].split(',')]
                
                for line in lines[1:]:
                    values = [v.strip() for v in line.split(',')]
                    
                    if len(values) == len(headers):
                        interface_name = values[0]
                        interface_stats = {}
                        
                        for header, value in zip(headers, values):
                            if header == 'BytesReceivedPersec':
                                interface_stats['bytes_recv'] = int(value) * duration
                            elif header == 'BytesSentPersec':
                                interface_stats['bytes_sent'] = int(value) * duration
                            elif header == 'PacketsReceivedPersec':
                                interface_stats['packets_recv'] = int(value) * duration
                            elif header == 'PacketsSentPersec':
                                interface_stats['packets_sent'] = int(value) * duration
                        
                        stats['interfaces'][interface_name] = interface_stats
        
        return stats
    
    def get_port_statistics(self, interface=None, duration=60):
        """
        Obtenir les statistiques par port
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée de mesure en secondes
        
        Returns:
            dict: Statistiques par port
        """
        # Obtenir les connexions
        connections = self.get_connections(interface)
        
        port_stats = defaultdict(lambda: {
            'connections': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'ips': Counter()
        })
        
        for conn in connections:
            # Ignorer les connexions sans adresse locale
            if not conn.get('laddr') or not conn['laddr'].get('port'):
                continue
            
            port = conn['laddr']['port']
            port_stats[port]['connections'] += 1
            
            # Compter les adresses distantes
            if conn.get('raddr') and conn['raddr'].get('ip'):
                port_stats[port]['ips'][conn['raddr']['ip']] += 1
        
        # Convertir en liste triée
        stats = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'ports': []
        }
        
        for port, data in port_stats.items():
            stats['ports'].append({
                'port': port,
                'connections': data['connections'],
                'unique_ips': len(data['ips']),
                'top_ips': dict(data['ips'].most_common(5))
            })
        
        # Trier par nombre de connexions
        stats['ports'].sort(key=lambda x: x['connections'], reverse=True)
        
        return stats
    
    def get_protocol_statistics(self, interface=None, duration=60):
        """
        Obtenir les statistiques par protocole
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée de mesure en secondes
        
        Returns:
            dict: Statistiques par protocole
        """
        connections = self.get_connections(interface)
        
        protocol_stats = defaultdict(lambda: {
            'connections': 0,
            'bytes_sent': 0,
            'bytes_recv': 0
        })
        
        for conn in connections:
            protocol = conn.get('type', 'unknown')
            protocol_stats[protocol]['connections'] += 1
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'protocols': []
        }
        
        for protocol, data in protocol_stats.items():
            stats['protocols'].append({
                'protocol': protocol,
                'connections': data['connections']
            })
        
        # Trier par nombre de connexions
        stats['protocols'].sort(key=lambda x: x['connections'], reverse=True)
        
        return stats
    
    def detect_anomalies(self, traffic_stats=None, connections=None):
        """
        Détecter les anomalies dans le trafic réseau
        
        Args:
            traffic_stats: Statistiques de trafic
            connections: Liste des connexions
        
        Returns:
            dict: Anomalies détectées
        """
        anomalies = {
            'timestamp': datetime.now().isoformat(),
            'anomalies': [],
            'alerts': []
        }
        
        if traffic_stats is None:
            traffic_stats = self.get_traffic_stats()
        
        if connections is None:
            connections = self.get_connections()
        
        # Vérifier le trafic élevé
        config = self.config.get('alerts', {})
        high_traffic_threshold = config.get('high_traffic', 1000000)  # 1 Mo/s
        
        total_rate = traffic_stats.get('total', {}).get('rate_sent', 0)
        if total_rate > high_traffic_threshold:
            anomalies['alerts'].append({
                'type': 'high_traffic',
                'message': f"Trafic réseau élevé: {total_rate / 1000000:.2f} Mo/s",
                'severity': 'high',
                'value': total_rate
            })
        
        # Détection de scan de ports
        if config.get('port_scan', True):
            port_scan = self._detect_port_scan(connections)
            if port_scan:
                anomalies['alerts'].extend(port_scan)
        
        # Détection de nouveaux services
        if config.get('new_service', True):
            new_services = self._detect_new_services(connections)
            if new_services:
                anomalies['alerts'].extend(new_services)
        
        # Détection de connexions vers des pays inhabituels
        # (nécessite une base de données GeoIP)
        
        return anomalies
    
    def _detect_port_scan(self, connections):
        """Détecter les tentatives de scan de ports"""
        alerts = []
        
        # Compter les connexions par IP source
        ip_connections = Counter()
        
        for conn in connections:
            if conn.get('raddr') and conn['raddr'].get('ip'):
                ip_connections[conn['raddr']['ip']] += 1
        
        # Détecter les IPs avec beaucoup de connexions vers différents ports
        for ip, count in ip_connections.items():
            # Obtenir toutes les connexions depuis cette IP
            ip_conns = [conn for conn in connections 
                       if conn.get('raddr') and conn['raddr'].get('ip') == ip]
            
            # Compter les ports uniques
            unique_ports = set()
            for conn in ip_conns:
                if conn.get('laddr') and conn['laddr'].get('port'):
                    unique_ports.add(conn['laddr']['port'])
            
            # Si plus de 10 ports différents en peu de temps, c'est suspect
            if len(unique_ports) > 10 and count > 20:
                alerts.append({
                    'type': 'port_scan',
                    'message': f"Tentative de scan de ports détectée depuis {ip}: {len(unique_ports)} ports testés",
                    'severity': 'critical',
                    'ip': ip,
                    'ports': list(unique_ports)[:10]  # Limiter à 10 ports pour l'affichage
                })
        
        return alerts
    
    def _detect_new_services(self, connections):
        """Détecter les nouveaux services ouverts"""
        alerts = []
        
        # Récupérer les services connus (à implémenter avec une base de données)
        # Pour l'instant, on vérifie les ports ouverts
        open_ports = set()
        
        for conn in connections:
            if conn.get('laddr') and conn['laddr'].get('port'):
                open_ports.add(conn['laddr']['port'])
        
        # Comparer avec la liste des services connus
        # (À implémenter avec une base de données des services autorisés)
        known_ports = {22, 80, 443, 3306, 5432}  # Exemple de ports connus
        
        new_ports = open_ports - known_ports
        
        for port in new_ports:
            # Vérifier si le port est utilisé par une application connue
            conn_with_port = [conn for conn in connections 
                            if conn.get('laddr') and conn['laddr'].get('port') == port]
            
            for conn in conn_with_port:
                process_name = conn.get('process_name', 'unknown')
                alerts.append({
                    'type': 'new_service',
                    'message': f"Nouveau service détecté sur le port {port} ({process_name})",
                    'severity': 'medium',
                    'port': port,
                    'process': process_name
                })
        
        return alerts
    
    def capture_packets(self, interface=None, duration=60, count=100, output_file=None):
        """
        Capturer des paquets réseau (nécessite Scapy)
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée de capture en secondes
            count: Nombre de paquets à capturer
            output_file: Fichier pour sauvegarder la capture (pcap)
        
        Returns:
            list: Liste des paquets capturés
        """
        if not HAS_SCAPY:
            log.error("Scapy n'est pas installé. Impossible de capturer des paquets.")
            return []
        
        packets = []
        
        if output_file:
            # Sauvegarder dans un fichier pcap
            result = scapy.sniff(iface=interface, timeout=duration, count=count, prn=lambda x: packets.append(x))
            scapy.wrpcap(output_file, result)
            packets = result
        else:
            # Retourner la liste des paquets
            packets = scapy.sniff(iface=interface, timeout=duration, count=count)
        
        return packets
    
    def analyze_packets(self, packets=None, interface=None, duration=60, count=100):
        """
        Analyser des paquets réseau
        
        Args:
            packets: Liste de paquets à analyser
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée de capture en secondes
            count: Nombre de paquets à capturer
        
        Returns:
            dict: Résultats de l'analyse
        """
        if not HAS_SCAPY:
            log.error("Scapy n'est pas installé. Impossible d'analyser des paquets.")
            return {}
        
        if packets is None:
            packets = self.capture_packets(interface, duration, count)
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': len(packets),
            'protocols': Counter(),
            'sources': Counter(),
            'destinations': Counter(),
            'ports': Counter(),
            'suspicious': []
        }
        
        for packet in packets:
            # Obtenir le protocole
            protocol = None
            
            if hasattr(packet, 'haslayer'):
                if packet.haslayer('IP'):
                    protocol = 'IP'
                    analysis['sources'][packet['IP'].src] += 1
                    analysis['destinations'][packet['IP'].dst] += 1
                    
                    if packet.haslayer('TCP'):
                        protocol = 'TCP'
                        analysis['ports'][packet['TCP'].sport] += 1
                        analysis['ports'][packet['TCP'].dport] += 1
                    
                    elif packet.haslayer('UDP'):
                        protocol = 'UDP'
                        analysis['ports'][packet['UDP'].sport] += 1
                        analysis['ports'][packet['UDP'].dport] += 1
                    
                    elif packet.haslayer('ICMP'):
                        protocol = 'ICMP'
                    
                    # Détection de paquets suspects
                    suspicious = self._detect_suspicious_packet(packet)
                    if suspicious:
                        analysis['suspicious'].append(suspicious)
            
            if protocol:
                analysis['protocols'][protocol] += 1
        
        return analysis
    
    def _detect_suspicious_packet(self, packet):
        """Détecter un paquet suspect"""
        suspicious = None
        
        if hasattr(packet, 'haslayer'):
            # Détection de scan SYN
            if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
                # Vérifier s'il y a beaucoup de SYN sans ACK depuis la même IP
                # (nécessiterait un suivi d'état)
                pass
            
            # Détection de paquets ICMP (ping flood)
            if packet.haslayer('ICMP') and packet['ICMP'].type == 8:  # Echo request
                # Vérifier la fréquence
                pass
            
            # Détection de ports inhabituels
            if packet.haslayer('TCP') or packet.haslayer('UDP'):
                port = packet['TCP'].dport if packet.haslayer('TCP') else packet['UDP'].dport
                if port > 1024 and port < 32768:
                    suspicious = {
                        'type': 'unusual_port',
                        'message': f"Paquet vers un port inhabituel: {port}",
                        'port': port,
                        'protocol': 'TCP' if packet.haslayer('TCP') else 'UDP'
                    }
        
        return suspicious
    
    def monitor_traffic(self, interface=None, duration=60, interval=5, callback=None):
        """
        Surveiller le trafic réseau en temps réel
        
        Args:
            interface: Interface réseau spécifique (None = toutes)
            duration: Durée totale de surveillance en secondes
            interval: Intervalle entre les mesures en secondes
            callback: Fonction de callback appelée à chaque mesure
        
        Returns:
            list: Liste des mesures
        """
        measures = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Obtenir les statistiques
            stats = self.get_traffic_stats(interface, interval)
            connections = self.get_connections(interface)
            anomalies = self.detect_anomalies(stats, connections)
            
            measure = {
                'timestamp': datetime.now().isoformat(),
                'stats': stats,
                'connections': connections,
                'anomalies': anomalies
            }
            
            measures.append(measure)
            
            # Appeler le callback si fourni
            if callback:
                try:
                    callback(measure)
                except Exception as e:
                    log.error(f"Erreur dans le callback: {e}")
            
            # Attendre l'intervalle
            time.sleep(interval)
        
        return measures
    
    def display_stats(self, stats):
        """
        Afficher les statistiques de trafic
        
        Args:
            stats: Statistiques à afficher
        """
        green = '\033[92m' if helpers.USE_COLORS else ''
        red = '\033[91m' if helpers.USE_COLORS else ''
        yellow = '\033[93m' if helpers.USE_COLORS else ''
        reset = '\033[0m' if helpers.USE_COLORS else ''
        
        print(f"\n{'='*60}")
        print(f"Statistiques de trafic réseau - {stats.get('timestamp', 'N/A')}")
        print(f"Durée: {stats.get('duration', 'N/A')} secondes")
        print(f"{'='*60}")
        
        # Afficher les statistiques globales
        total = stats.get('total', {})
        print(f"\nTotal:")
        print(f"  Bytes envoyés: {total.get('bytes_sent', 0):,} ({total.get('rate_sent_mbps', 0):.2f} Mbps)")
        print(f"  Bytes reçus: {total.get('bytes_recv', 0):,} ({total.get('rate_recv_mbps', 0):.2f} Mbps)")
        print(f"  Paquets envoyés: {total.get('packets_sent', 0):,}")
        print(f"  Paquets reçus: {total.get('packets_recv', 0):,}")
        print(f"  Erreurs entrée: {total.get('errors_in', 0):,}")
        print(f"  Erreurs sortie: {total.get('errors_out', 0):,}")
        
        # Afficher les statistiques par interface
        interfaces = stats.get('interfaces', {})
        if interfaces:
            print(f"\nPar interface:")
            for interface, interface_stats in interfaces.items():
                print(f"  {interface}:")
                print(f"    Bytes envoyés: {interface_stats.get('bytes_sent', 0):,} ({interface_stats.get('rate_sent_mbps', 0):.2f} Mbps)")
                print(f"    Bytes reçus: {interface_stats.get('bytes_recv', 0):,} ({interface_stats.get('rate_recv_mbps', 0):.2f} Mbps)")
        
        print(f"{'='*60}")
    
    def display_connections(self, connections, top_n=10):
        """
        Afficher les connexions actives
        
        Args:
            connections: Liste des connexions
            top_n: Nombre de connexions à afficher
        """
        print(f"\n{'='*80}")
        print(f"Connexions réseau actives ({len(connections)} connexions)")
        print(f"{'='*80}")
        
        # Trier par PID
        sorted_connections = sorted(connections, key=lambda x: x.get('pid', 0))
        
        # Afficher l'en-tête
        print(f"{'PID':<8} {'Process':<20} {'Proto':<8} {'Local Address':<25} {'Remote Address':<25} {'Status':<12}")
        print(f"{'-'*8} {'-'*20} {'-'*8} {'-'*25} {'-'*25} {'-'*12}")
        
        # Afficher les connexions
        for conn in sorted_connections[:top_n]:
            pid = conn.get('pid', '?')
            process = conn.get('process_name', '?')
            proto = conn.get('type', '?')
            laddr = self._format_address(conn.get('laddr'))
            raddr = self._format_address(conn.get('raddr'))
            status = conn.get('status', '?')
            
            print(f"{pid:<8} {process:<20} {proto:<8} {laddr:<25} {raddr:<25} {status:<12}")
        
        if len(connections) > top_n:
            print(f"... et {len(connections) - top_n} autres connexions")
        
        print(f"{'='*80}")
    
    def _format_address(self, addr):
        """Formater une adresse IP:PORT"""
        if not addr:
            return '?'
        
        ip = addr.get('ip', '?')
        port = addr.get('port', '?')
        return f"{ip}:{port}" if port else ip


def main(args=None):
    """
    Fonction principale pour le module d'analyse de trafic réseau
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Analyser le trafic réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python traffic_analyzer.py --stats
  python traffic_analyzer.py --stats --interface eth0 --duration 120
  python traffic_analyzer.py --connections
  python traffic_analyzer.py --connections --interface wlan0
  python traffic_analyzer.py --ports
  python traffic_analyzer.py --protocols
  python traffic_analyzer.py --monitor --duration 300 --interval 10
  python traffic_analyzer.py --capture --duration 60 --count 1000 --output capture.pcap
  python traffic_analyzer.py --analyze --duration 60 --count 1000
  python traffic_analyzer.py --anomalies
  python traffic_analyzer.py --interfaces
        """
    )
    
    # Arguments pour les différentes analyses
    parser.add_argument('--stats', action='store_true',
                        help='Obtenir les statistiques de trafic')
    parser.add_argument('--connections', action='store_true',
                        help='Lister les connexions réseau actives')
    parser.add_argument('--ports', action='store_true',
                        help='Obtenir les statistiques par port')
    parser.add_argument('--protocols', action='store_true',
                        help='Obtenir les statistiques par protocole')
    parser.add_argument('--monitor', action='store_true',
                        help='Surveiller le trafic en temps réel')
    parser.add_argument('--capture', action='store_true',
                        help='Capturer des paquets réseau')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyser des paquets réseau')
    parser.add_argument('--anomalies', action='store_true',
                        help='Détecter les anomalies')
    parser.add_argument('--interfaces', action='store_true',
                        help='Lister les interfaces réseau')
    
    # Arguments pour la configuration
    parser.add_argument('--interface', type=str, metavar='INTERFACE',
                        help='Interface réseau à analyser')
    parser.add_argument('--duration', type=int, default=60,
                        metavar='SECONDS',
                        help='Durée de l\'analyse en secondes (par défaut: 60)')
    parser.add_argument('--interval', type=int, default=5,
                        metavar='SECONDS',
                        help='Intervalle entre les mesures en secondes (par défaut: 5)')
    parser.add_argument('--count', type=int, default=100,
                        metavar='NUMBER',
                        help='Nombre de paquets à capturer (par défaut: 100)')
    parser.add_argument('--output', type=str, metavar='FILE',
                        help='Fichier de sortie pour la capture pcap')
    
    # Arguments divers
    parser.add_argument('--json', action='store_true',
                        help='Afficher les résultats au format JSON')
    parser.add_argument('--top', type=int, default=10,
                        metavar='NUMBER',
                        help='Nombre de résultats à afficher (par défaut: 10)')
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
    
    # Créer l'analyseur de trafic
    analyzer = TrafficAnalyzer({
        'interface': args.interface,
        'duration': args.duration
    })
    
    # Exécuter l'analyse
    results = None
    
    if args.interfaces:
        interfaces = analyzer.get_network_interfaces()
        if args.json:
            print(json.dumps(interfaces, indent=2, default=str, ensure_ascii=False))
        else:
            print("Interfaces réseau:")
            for interface in interfaces:
                print(f"  {interface['name']}:")
                for addr in interface.get('addresses', []):
                    print(f"    {addr['family']}: {addr['address']}")
    
    elif args.stats:
        results = analyzer.get_traffic_stats(args.interface, args.duration)
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            analyzer.display_stats(results)
    
    elif args.connections:
        results = analyzer.get_connections(args.interface)
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            analyzer.display_connections(results, args.top)
    
    elif args.ports:
        results = analyzer.get_port_statistics(args.interface, args.duration)
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\nStatistiques par port:")
            for port in results.get('ports', [])[:args.top]:
                print(f"  Port {port['port']}: {port['connections']} connexions, {port['unique_ips']} IPs uniques")
    
    elif args.protocols:
        results = analyzer.get_protocol_statistics(args.interface, args.duration)
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\nStatistiques par protocole:")
            for proto in results.get('protocols', []):
                print(f"  {proto['protocol']}: {proto['connections']} connexions")
    
    elif args.capture:
        if not HAS_SCAPY:
            print("Scapy n'est pas installé. Installez-le avec: pip install scapy")
            sys.exit(1)
        
        packets = analyzer.capture_packets(args.interface, args.duration, args.count, args.output)
        if args.output:
            print(f"Capture sauvegardée dans {args.output}")
        else:
            print(f"Capture terminée: {len(packets)} paquets capturés")
    
    elif args.analyze:
        if not HAS_SCAPY:
            print("Scapy n'est pas installé. Installez-le avec: pip install scapy")
            sys.exit(1)
        
        results = analyzer.analyze_packets(None, args.interface, args.duration, args.count)
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\nAnalyse des paquets:")
            print(f"  Total paquets: {results.get('total_packets', 0)}")
            print(f"\nPar protocole:")
            for proto, count in results.get('protocols', {}).items():
                print(f"  {proto}: {count}")
            print(f"\nIPs sources:")
            for ip, count in results.get('sources', {}).most_common(5):
                print(f"  {ip}: {count}")
            print(f"\nPorts:")
            for port, count in results.get('ports', {}).most_common(5):
                print(f"  {port}: {count}")
    
    elif args.anomalies:
        results = analyzer.detect_anomalies()
        if args.json:
            print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        else:
            if results.get('alerts'):
                print(f"\nAlerte de sécurité:")
                for alert in results['alerts']:
                    severity = alert.get('severity', 'unknown').upper()
                    print(f"  [{severity}] {alert.get('message', 'Alerte non spécifiée')}")
            else:
                print("Aucune anomalie détectée")
    
    elif args.monitor:
        print(f"Surveillance du trafic réseau en cours (durée: {args.duration}s, intervalle: {args.interval}s)...")
        measures = analyzer.monitor_traffic(args.interface, args.duration, args.interval, 
                                            lambda m: print(f"[{m['timestamp']}] Trafic: {m['stats']['total']['rate_recv_mbps']:.2f} Mbps reçu"))
        
        # Afficher le résumé
        if not args.quiet:
            print(f"\nRésumé de la surveillance:")
            for i, measure in enumerate(measures):
                total = measure['stats']['total']
                print(f"  Mesure {i+1}: {total['rate_recv_mbps']:.2f} Mbps reçu, {total['rate_sent_mbps']:.2f} Mbps envoyé")
    
    else:
        # Par défaut: afficher les interfaces et les connexions
        interfaces = analyzer.get_network_interfaces()
        connections = analyzer.get_connections()
        
        if not args.quiet:
            print("Interfaces réseau:")
            for interface in interfaces:
                print(f"  {interface['name']}")
            
            print(f"\nConnexions réseau actives: {len(connections)}")
            analyzer.display_connections(connections, args.top)


if __name__ == "__main__":
    main()
