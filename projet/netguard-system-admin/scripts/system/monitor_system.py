#!/usr/bin/env python3
"""
NetGuard - Module de surveillance système

Ce module permet de surveiller les ressources système:
- CPU (utilisation, température)
- Mémoire (RAM, Swap)
- Disque (utilisation, E/S)
- Réseau (trafic, connexions)
- Services

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import time
import json
import argparse
import platform
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    import GPUtil
    HAS_PSUTIL = True
    HAS_GPUTIL = True
except ImportError:
    HAS_PSUTIL = False
    HAS_GPUTIL = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from ..utils import logger, helpers, notifier

# Configuration du logger
log = logger.setup_logger(__name__)


class SystemMonitor:
    """Classe principale pour la surveillance système"""
    
    def __init__(self, config=None):
        """
        Initialiser le moniteur système
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or self._load_default_config()
        self.history = []
        self.start_time = datetime.now()
        
        # Initialiser les seuils d'alerte
        self.cpu_threshold = self.config.get('cpu_threshold', 90)
        self.memory_threshold = self.config.get('memory_threshold', 85)
        self.disk_threshold = self.config.get('disk_threshold', 90)
        self.temperature_threshold = self.config.get('temperature_threshold', 75)
        
        # Initialiser le notificateur
        self.notifier = notifier.Notifier(self.config.get('alerts', {}))
        
        # Historique des alertes
        self.alert_history = []
        
        log.info("SystemMonitor initialisé")
    
    def _load_default_config(self):
        """Charger la configuration par défaut"""
        return {
            'cpu_threshold': 90,
            'memory_threshold': 85,
            'disk_threshold': 90,
            'temperature_threshold': 75,
            'check_interval': 60,
            'alerts': {}
        }
    
    def check_cpu(self):
        """
        Vérifier l'utilisation du CPU
        
        Returns:
            dict: Informations sur le CPU
        """
        if not HAS_PSUTIL:
            log.warning("psutil non disponible - impossible de vérifier le CPU")
            return {'error': 'psutil non installé'}
        
        cpu_data = {}
        
        try:
            # Utilisation CPU globale
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_data['usage_percent'] = cpu_percent
            cpu_data['usage_percent_rounded'] = round(cpu_percent, 2)
            
            # Nombre de cœurs
            cpu_count = psutil.cpu_count(logical=True)
            cpu_physical = psutil.cpu_count(logical=False)
            cpu_data['cores'] = {
                'logical': cpu_count,
                'physical': cpu_physical
            }
            
            # Fréquence CPU
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                cpu_data['frequency'] = {
                    'current': cpu_freq.current,
                    'min': cpu_freq.min,
                    'max': cpu_freq.max
                }
            
            # Temps CPU par mode
            cpu_times = psutil.cpu_times_percent(interval=1)
            cpu_data['times'] = {
                'user': cpu_times.user,
                'system': cpu_times.system,
                'idle': cpu_times.idle,
                'iowait': getattr(cpu_times, 'iowait', 0),
                'steal': getattr(cpu_times, 'steal', 0)
            }
            
            # Vérifier si seuil dépassé
            if cpu_percent > self.cpu_threshold:
                self._trigger_alert(
                    'CPU',
                    f"Utilisation CPU élevée: {cpu_percent:.1f}% > {self.cpu_threshold}%",
                    'WARNING',
                    cpu_percent
                )
            
            # Vérifier température CPU (si disponible)
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    cpu_data['temperatures'] = {}
                    for name, entries in temps.items():
                        cpu_data['temperatures'][name] = []
                        for entry in entries:
                            if entry.current:
                                cpu_data['temperatures'][name].append({
                                    'label': entry.label or name,
                                    'current': entry.current,
                                    'high': entry.high,
                                    'critical': entry.critical
                                })
                                
                                # Vérifier seuil de température
                                if entry.current and entry.current > self.temperature_threshold:
                                    self._trigger_alert(
                                        'TEMPERATURE',
                                        f"Température élevée: {entry.current}°C > {self.temperature_threshold}°C ({name})",
                                        'CRITICAL',
                                        entry.current
                                    )
            
            # Si GPUtil est disponible, vérifier les GPU
            if HAS_GPUTIL:
                try:
                    gpus = GPUtil.getGPUs()
                    if gpus:
                        cpu_data['gpus'] = []
                        for gpu in gpus:
                            gpu_info = {
                                'id': gpu.id,
                                'name': gpu.name,
                                'load': gpu.load,
                                'memory_total': gpu.memoryTotal,
                                'memory_used': gpu.memoryUsed,
                                'memory_free': gpu.memoryFree,
                                'temperature': gpu.temperature
                            }
                            cpu_data['gpus'].append(gpu_info)
                            
                            # Vérifier seuil GPU
                            if gpu.temperature and gpu.temperature > self.temperature_threshold:
                                self._trigger_alert(
                                    'GPU_TEMPERATURE',
                                    f"Température GPU élevée: {gpu.temperature}°C > {self.temperature_threshold}°C ({gpu.name})",
                                    'WARNING',
                                    gpu.temperature
                                )
                except Exception as e:
                    log.warning(f"Impossible de récupérer les informations GPU: {e}")
            
            cpu_data['status'] = 'OK' if cpu_percent <= self.cpu_threshold else 'WARNING'
            cpu_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification du CPU: {e}")
            cpu_data['error'] = str(e)
        
        return cpu_data
    
    def check_memory(self):
        """
        Vérifier l'utilisation de la mémoire
        
        Returns:
            dict: Informations sur la mémoire
        """
        if not HAS_PSUTIL:
            log.warning("psutil non disponible - impossible de vérifier la mémoire")
            return {'error': 'psutil non installé'}
        
        memory_data = {}
        
        try:
            # Mémoire virtuelle
            mem = psutil.virtual_memory()
            memory_data['virtual'] = {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'free': mem.free,
                'percent': mem.percent,
                'percent_rounded': round(mem.percent, 2),
                'active': getattr(mem, 'active', 0),
                'inactive': getattr(mem, 'inactive', 0)
            }
            
            # Swap
            swap = psutil.swap_memory()
            memory_data['swap'] = {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'percent_rounded': round(swap.percent, 2)
            }
            
            # Vérifier seuils
            if mem.percent > self.memory_threshold:
                self._trigger_alert(
                    'MEMORY',
                    f"Utilisation mémoire élevée: {mem.percent:.1f}% > {self.memory_threshold}%",
                    'WARNING',
                    mem.percent
                )
            
            if swap.percent > 50:
                self._trigger_alert(
                    'SWAP',
                    f"Utilisation swap élevée: {swap.percent:.1f}% > 50%",
                    'WARNING',
                    swap.percent
                )
            
            memory_data['status'] = 'OK' if mem.percent <= self.memory_threshold else 'WARNING'
            memory_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification de la mémoire: {e}")
            memory_data['error'] = str(e)
        
        return memory_data
    
    def check_disk(self):
        """
        Vérifier l'utilisation du disque
        
        Returns:
            dict: Informations sur le disque
        """
        if not HAS_PSUTIL:
            log.warning("psutil non disponible - impossible de vérifier le disque")
            return {'error': 'psutil non installé'}
        
        disk_data = {}
        
        try:
            partitions = psutil.disk_partitions(all=False)
            disk_data['partitions'] = []
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                        'percent_rounded': round(usage.percent, 2)
                    }
                    
                    # Vérifier seuil
                    if usage.percent > self.disk_threshold:
                        self._trigger_alert(
                            'DISK',
                            f"Utilisation disque élevée: {usage.percent:.1f}% > {self.disk_threshold}% ({partition.mountpoint})",
                            'WARNING',
                            usage.percent
                        )
                    
                    partition_info['status'] = 'OK' if usage.percent <= self.disk_threshold else 'WARNING'
                    disk_data['partitions'].append(partition_info)
                    
                except Exception as e:
                    log.warning(f"Impossible de vérifier le disque {partition.mountpoint}: {e}")
            
            # Statistiques globales
            if disk_data['partitions']:
                total_used = sum(p['used'] for p in disk_data['partitions'])
                total_total = sum(p['total'] for p in disk_data['partitions'])
                disk_data['global'] = {
                    'total': total_total,
                    'used': total_used,
                    'free': total_total - total_used,
                    'percent': (total_used / total_total * 100) if total_total > 0 else 0
                }
            
            disk_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification du disque: {e}")
            disk_data['error'] = str(e)
        
        return disk_data
    
    def check_network(self):
        """
        Vérifier les statistiques réseau
        
        Returns:
            dict: Informations sur le réseau
        """
        if not HAS_PSUTIL:
            log.warning("psutil non disponible - impossible de vérifier le réseau")
            return {'error': 'psutil non installé'}
        
        network_data = {}
        
        try:
            # Statistiques par interface
            net_io = psutil.net_io_counters(pernic=True)
            network_data['interfaces'] = {}
            
            for interface, stats in net_io.items():
                network_data['interfaces'][interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
            
            # Adresses IP
            net_addrs = psutil.net_if_addrs()
            network_data['addresses'] = {}
            
            for interface, addrs in net_addrs.items():
                network_data['addresses'][interface] = []
                for addr in addrs:
                    addr_info = {
                        'family': addr.family.name,
                        'address': addr.address
                    }
                    if addr.netmask:
                        addr_info['netmask'] = addr.netmask
                    if addr.broadcast:
                        addr_info['broadcast'] = addr.broadcast
                    if addr.ptp:
                        addr_info['ptp'] = addr.ptp
                    network_data['addresses'][interface].append(addr_info)
            
            # Connexions réseau
            connections = psutil.net_connections()
            network_data['connections'] = []
            
            for conn in connections:
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                network_data['connections'].append(conn_info)
            
            network_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification du réseau: {e}")
            network_data['error'] = str(e)
        
        return network_data
    
    def check_services(self, services=None):
        """
        Vérifier l'état des services
        
        Args:
            services: Liste des services à vérifier (ou None pour tous)
        
        Returns:
            dict: État des services
        """
        service_data = {'services': []}
        
        try:
            if platform.system() == "Linux":
                # Utiliser systemctl sur Linux
                if services is None:
                    # Obtenir tous les services
                    import subprocess
                    result = subprocess.run(
                        ['systemctl', 'list-units', '--type=service', '--no-pager'],
                        capture_output=True, text=True
                    )
                    all_services = []
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                all_services.append(parts[0])
                    services = all_services
                
                for service in services:
                    try:
                        import subprocess
                        result = subprocess.run(
                            ['systemctl', 'is-active', service],
                            capture_output=True, text=True
                        )
                        
                        status = result.stdout.strip()
                        exit_code = result.returncode
                        
                        service_info = {
                            'name': service,
                            'status': status,
                            'active': status == 'active',
                            'enabled': True  # À vérifier
                        }
                        
                        # Vérifier si le service est activé
                        try:
                            result = subprocess.run(
                                ['systemctl', 'is-enabled', service],
                                capture_output=True, text=True
                            )
                            service_info['enabled'] = result.stdout.strip() == 'enabled'
                        except:
                            pass
                        
                        service_data['services'].append(service_info)
                        
                        # Alerte si service critique non actif
                        if service in ['sshd', 'cron', 'docker'] and status != 'active':
                            self._trigger_alert(
                                'SERVICE',
                                f"Service critique non actif: {service}",
                                'CRITICAL',
                                service
                            )
                            
                    except Exception as e:
                        log.warning(f"Impossible de vérifier le service {service}: {e}")
                        service_data['services'].append({
                            'name': service,
                            'status': 'unknown',
                            'active': False,
                            'enabled': False,
                            'error': str(e)
                        })
                        
            elif platform.system() == "Windows":
                # Utiliser sc query sur Windows
                import subprocess
                
                if services is None:
                    services = []
                
                for service in services:
                    try:
                        result = subprocess.run(
                            ['sc', 'query', service],
                            capture_output=True, text=True
                        )
                        
                        # Parser la sortie
                        status = 'unknown'
                        for line in result.stdout.split('\n'):
                            if 'STATE' in line:
                                parts = line.split(':')
                                if len(parts) > 1:
                                    status = parts[1].strip().split()[0]
                        
                        service_info = {
                            'name': service,
                            'status': status,
                            'active': status in ['RUNNING', 'START_PENDING'],
                            'enabled': True
                        }
                        
                        service_data['services'].append(service_info)
                        
                    except Exception as e:
                        log.warning(f"Impossible de vérifier le service {service}: {e}")
                        service_data['services'].append({
                            'name': service,
                            'status': 'unknown',
                            'active': False,
                            'enabled': False,
                            'error': str(e)
                        })
            else:
                log.warning(f"Système non supporté pour la vérification des services: {platform.system()}")
                service_data['error'] = f"Système non supporté: {platform.system()}"
            
            service_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification des services: {e}")
            service_data['error'] = str(e)
        
        return service_data
    
    def check_temperature(self):
        """
        Vérifier la température du système
        
        Returns:
            dict: Informations de température
        """
        temp_data = {'sensors': []}
        
        if not HAS_PSUTIL:
            log.warning("psutil non disponible - impossible de vérifier la température")
            return {'error': 'psutil non installé'}
        
        try:
            temps = psutil.sensors_temperatures()
            
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current:
                            sensor_info = {
                                'name': name,
                                'label': entry.label or name,
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical
                            }
                            temp_data['sensors'].append(sensor_info)
                            
                            # Vérifier seuil
                            if entry.current > self.temperature_threshold:
                                self._trigger_alert(
                                    'TEMPERATURE',
                                    f"Température élevée: {entry.current}°C > {self.temperature_threshold}°C ({sensor_info['label']})",
                                    'CRITICAL',
                                    entry.current
                                )
            else:
                log.warning("Aucun capteur de température trouvé")
            
            temp_data['timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            log.error(f"Erreur lors de la vérification de la température: {e}")
            temp_data['error'] = str(e)
        
        return temp_data
    
    def _trigger_alert(self, alert_type, message, level, value):
        """
        Déclencher une alerte
        
        Args:
            alert_type: Type d'alerte
            message: Message d'alerte
            level: Niveau d'alerte (INFO, WARNING, ERROR, CRITICAL)
            value: Valeur qui a déclenché l'alerte
        """
        alert = {
            'type': alert_type,
            'message': message,
            'level': level,
            'value': value,
            'timestamp': datetime.now().isoformat()
        }
        
        # Ajouter à l'historique
        self.alert_history.append(alert)
        
        # Limiter la taille de l'historique
        if len(self.alert_history) > 100:
            self.alert_history = self.alert_history[-100:]
        
        # Envoyer la notification
        self.notifier.send_alert(alert)
        
        # Logger l'alerte
        log_method = getattr(log, level.lower(), log.warning)
        log_method(f"ALERT: {alert_type} - {message} (valeur: {value})")
    
    def collect_all(self):
        """
        Collecter toutes les métriques système
        
        Returns:
            dict: Toutes les métriques collectées
        """
        data = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'architecture': platform.machine(),
                'processor': platform.processor()
            }
        }
        
        # Collecter toutes les métriques
        data['cpu'] = self.check_cpu()
        data['memory'] = self.check_memory()
        data['disk'] = self.check_disk()
        data['network'] = self.check_network()
        data['temperature'] = self.check_temperature()
        
        # Ajouter à l'historique
        self.history.append(data)
        
        # Limiter la taille de l'historique
        if len(self.history) > self.config.get('history_size', 100):
            self.history = self.history[-self.config.get('history_size', 100):]
        
        return data
    
    def monitor_realtime(self, duration=60, interval=5):
        """
        Surveillance en temps réel
        
        Args:
            duration: Durée totale de la surveillance (en secondes)
            interval: Intervalle entre chaque vérification (en secondes)
        """
        print(f"\n{'='*60}")
        print(f"SURVEILLANCE EN TEMPS RÉEL - Durée: {duration}s, Intervalle: {interval}s")
        print(f"{'='*60}\n")
        
        end_time = datetime.now() + timedelta(seconds=duration)
        
        try:
            while datetime.now() < end_time:
                # Collecter les données
                data = self.collect_all()
                
                # Afficher les informations
                self._display_realtime_data(data)
                
                # Attendre l'intervalle
                time.sleep(interval)
                
                # Effacer la console pour la prochaine itération
                if platform.system() != "Windows":
                    print("\033[H\033[J")  # Effacer la console
                else:
                    os.system('cls')
                
        except KeyboardInterrupt:
            print("\nSurveillance arrêtée par l'utilisateur")
        except Exception as e:
            log.error(f"Erreur dans la surveillance en temps réel: {e}")
    
    def _display_realtime_data(self, data):
        """
        Afficher les données en temps réel
        
        Args:
            data: Données collectées
        """
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
        print(f"{'='*60}")
        
        # CPU
        cpu = data.get('cpu', {})
        if 'usage_percent' in cpu:
            print(f"🔹 CPU: {cpu['usage_percent_rounded']}% | "
                  f"Cœurs: {cpu['cores']['logical']} (physiques: {cpu['cores']['physical']}) | "
                  f"Statut: {cpu.get('status', 'UNKNOWN')}")
        
        # Température CPU
        if 'temperatures' in cpu:
            for sensor_name, sensors in cpu['temperatures'].items():
                for sensor in sensors:
                    if 'current' in sensor:
                        temp_color = "🔴" if sensor['current'] > self.temperature_threshold else "🟢"
                        print(f"   {temp_color} Temp {sensor['label']}: {sensor['current']}°C")
        
        # GPU
        if 'gpus' in cpu:
            for gpu in cpu['gpus']:
                print(f"   🎮 GPU {gpu['name']}: {gpu['load']*100:.1f}% | "
                      f"Temp: {gpu['temperature']}°C | "
                      f"Mémoire: {gpu['memory_used']}MB/{gpu['memory_total']}MB")
        
        # Mémoire
        mem = data.get('memory', {})
        if 'virtual' in mem:
            mem_percent = mem['virtual']['percent_rounded']
            mem_color = "🔴" if mem_percent > self.memory_threshold else "🟢"
            print(f"{mem_color} Mémoire: {mem['virtual']['used'] / (1024 ** 3):.2f}Go / "
                  f"{mem['virtual']['total'] / (1024 ** 3):.2f}Go ({mem_percent}%) | "
                  f"Swap: {mem['swap']['percent_rounded']}%")
        
        # Disque
        disk = data.get('disk', {})
        if 'partitions' in disk:
            for partition in disk['partitions']:
                disk_percent = partition['percent_rounded']
                disk_color = "🔴" if disk_percent > self.disk_threshold else "🟢"
                print(f"{disk_color} Disque {partition['mountpoint']}: "
                      f"{partition['used'] / (1024 ** 3):.2f}Go / "
                      f"{partition['total'] / (1024 ** 3):.2f}Go ({disk_percent}%)")
        
        # Réseau
        net = data.get('network', {})
        if 'interfaces' in net and net['interfaces']:
            first_iface = list(net['interfaces'].keys())[0]
            iface = net['interfaces'][first_iface]
            print(f"🌐 Réseau ({first_iface}): "
                  f"↑{helpers.format_bytes(iface['bytes_sent'])} | "
                  f"↓{helpers.format_bytes(iface['bytes_recv'])}")
        
        # Services critiques
        services = data.get('services', {})
        if 'services' in services:
            critical_services = ['sshd', 'nginx', 'apache2', 'mysql', 'postgresql', 'docker']
            active_services = [s['name'] for s in services['services'] if s['active']]
            inactive_critical = [s for s in critical_services if s in [svc['name'] for svc in services['services']] and s not in active_services]
            
            if inactive_critical:
                print(f"⚠️  Services critiques inactifs: {', '.join(inactive_critical)}")
        
        # Alertes récentes
        if self.alert_history:
            print(f"\n⚠️  Dernières alertes:")
            for alert in self.alert_history[-3:]:
                level_color = {
                    'INFO': '🔵',
                    'WARNING': '🟡',
                    'ERROR': '🟠',
                    'CRITICAL': '🔴'
                }.get(alert['level'], '⚪')
                print(f"   {level_color} [{alert['level']}] {alert['message']}")
        
        print(f"{'='*60}")
    
    def generate_report(self, output_file=None, format='text'):
        """
        Générer un rapport de surveillance
        
        Args:
            output_file: Nom du fichier de sortie
            format: Format du rapport (text, json, html)
        
        Returns:
            str: Contenu du rapport
        """
        if not self.history:
            return "Aucune donnée disponible pour le rapport"
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'system_info': {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'monitoring_duration': str(datetime.now() - self.start_time)
            },
            'statistics': self._calculate_statistics(),
            'alerts': self.alert_history,
            'history': self.history
        }
        
        if format == 'json':
            content = json.dumps(report_data, indent=2, default=str, ensure_ascii=False)
            
        elif format == 'html':
            content = self._generate_html_report(report_data)
            
        else:  # text
            content = self._generate_text_report(report_data)
        
        # Sauvegarder le rapport si un fichier est spécifié
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Rapport généré: {output_file}")
            except Exception as e:
                log.error(f"Erreur lors de la sauvegarde du rapport: {e}")
        
        return content
    
    def _calculate_statistics(self):
        """Calculer les statistiques à partir de l'historique"""
        if not self.history:
            return {}
        
        stats = {
            'cpu': {
                'avg': 0,
                'max': 0,
                'min': 100
            },
            'memory': {
                'avg': 0,
                'max': 0,
                'min': 100
            },
            'disk': {
                'avg': 0,
                'max': 0,
                'min': 100
            },
            'alerts': {
                'total': len(self.alert_history),
                'by_level': defaultdict(int),
                'by_type': defaultdict(int)
            }
        }
        
        # Calculer les statistiques CPU
        cpu_values = []
        for data in self.history:
            if 'cpu' in data and 'usage_percent' in data['cpu']:
                cpu_values.append(data['cpu']['usage_percent'])
        
        if cpu_values:
            stats['cpu']['avg'] = round(sum(cpu_values) / len(cpu_values), 2)
            stats['cpu']['max'] = round(max(cpu_values), 2)
            stats['cpu']['min'] = round(min(cpu_values), 2)
        
        # Calculer les statistiques mémoire
        mem_values = []
        for data in self.history:
            if 'memory' in data and 'virtual' in data['memory']:
                mem_values.append(data['memory']['virtual']['percent'])
        
        if mem_values:
            stats['memory']['avg'] = round(sum(mem_values) / len(mem_values), 2)
            stats['memory']['max'] = round(max(mem_values), 2)
            stats['memory']['min'] = round(min(mem_values), 2)
        
        # Calculer les statistiques disque
        disk_values = []
        for data in self.history:
            if 'disk' in data and 'partitions' in data['disk']:
                for partition in data['disk']['partitions']:
                    disk_values.append(partition['percent'])
        
        if disk_values:
            stats['disk']['avg'] = round(sum(disk_values) / len(disk_values), 2)
            stats['disk']['max'] = round(max(disk_values), 2)
            stats['disk']['min'] = round(min(disk_values), 2)
        
        # Statistiques des alertes
        for alert in self.alert_history:
            stats['alerts']['by_level'][alert['level']] += 1
            stats['alerts']['by_type'][alert['type']] += 1
        
        return stats
    
    def _generate_text_report(self, report_data):
        """Générer un rapport en texte"""
        lines = []
        
        lines.append("=" * 70)
        lines.append("RAPPORT DE SURVEILLANCE SYSTÈME - NetGuard")
        lines.append("=" * 70)
        lines.append("")
        
        # Informations système
        lines.append("INFORMATIONS SYSTÈME")
        lines.append("-" * 70)
        lines.append(f"Nom d'hôte: {report_data['system_info']['hostname']}")
        lines.append(f"Système: {report_data['system_info']['os']}")
        lines.append(f"Durée de surveillance: {report_data['system_info']['monitoring_duration']}")
        lines.append(f"Rapport généré: {report_data['generated_at']}")
        lines.append("")
        
        # Statistiques
        lines.append("STATISTIQUES")
        lines.append("-" * 70)
        stats = report_data['statistics']
        
        lines.append("CPU:")
        lines.append(f"  Moyenne: {stats['cpu']['avg']}%")
        lines.append(f"  Maximum: {stats['cpu']['max']}%")
        lines.append(f"  Minimum: {stats['cpu']['min']}%")
        lines.append("")
        
        lines.append("Mémoire:")
        lines.append(f"  Moyenne: {stats['memory']['avg']}%")
        lines.append(f"  Maximum: {stats['memory']['max']}%")
        lines.append(f"  Minimum: {stats['memory']['min']}%")
        lines.append("")
        
        lines.append("Disque:")
        lines.append(f"  Moyenne: {stats['disk']['avg']}%")
        lines.append(f"  Maximum: {stats['disk']['max']}%")
        lines.append(f"  Minimum: {stats['disk']['min']}%")
        lines.append("")
        
        # Alertes
        lines.append("ALERTES")
        lines.append("-" * 70)
        alerts = report_data['alerts']
        lines.append(f"Total: {stats['alerts']['total']}")
        
        for level, count in stats['alerts']['by_level'].items():
            lines.append(f"  {level}: {count}")
        
        lines.append("")
        lines.append("Dernières alertes:")
        for alert in alerts[-5:]:  # Dernières 5 alertes
            lines.append(f"  [{alert['level']}] {alert['timestamp']}: {alert['message']}")
        lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _generate_html_report(self, report_data):
        """Générer un rapport HTML"""
        stats = report_data['statistics']
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport NetGuard - {report_data['system_info']['hostname']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c3e50;
            margin-top: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .stat-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        .stat-box h3 {{
            margin-top: 0;
            color: #495057;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
        }}
        .stat-value.critical {{
            color: #dc3545;
        }}
        .stat-value.warning {{
            color: #ffc107;
        }}
        .stat-value.good {{
            color: #28a745;
        }}
        .alert {{
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .alert.critical {{
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }}
        .alert.error {{
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }}
        .alert.warning {{
            background: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }}
        .alert.info {{
            background: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        table, th, td {{
            border: 1px solid #dee2e6;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: #f8f9fa;
        }}
        .chart-container {{
            height: 300px;
            margin: 20px 0;
        }}
        footer {{
            text-align: center;
            margin-top: 50px;
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport de Surveillance - NetGuard</h1>
        
        <div class="section">
            <h2>📊 Informations Système</h2>
            <div class="stat-box">
                <p><strong>Nom d'hôte:</strong> {report_data['system_info']['hostname']}</p>
                <p><strong>Système:</strong> {report_data['system_info']['os']}</p>
                <p><strong>Durée de surveillance:</strong> {report_data['system_info']['monitoring_duration']}</p>
                <p><strong>Rapport généré:</strong> {report_data['generated_at']}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📈 Statistiques</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 20px;">
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>CPU</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value {'critical' if stats['cpu']['avg'] > self.cpu_threshold else 'good'}">{stats['cpu']['avg']}%</span></p>
                    <p><strong>Maximum:</strong> <span class="stat-value {'critical' if stats['cpu']['max'] > self.cpu_threshold else 'warning' if stats['cpu']['max'] > self.cpu_threshold - 10 else 'good'}">{stats['cpu']['max']}%</span></p>
                    <p><strong>Minimum:</strong> <span class="stat-value good">{stats['cpu']['min']}%</span></p>
                </div>
                
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>Mémoire</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value {'critical' if stats['memory']['avg'] > self.memory_threshold else 'good'}">{stats['memory']['avg']}%</span></p>
                    <p><strong>Maximum:</strong> <span class="stat-value {'critical' if stats['memory']['max'] > self.memory_threshold else 'warning' if stats['memory']['max'] > self.memory_threshold - 10 else 'good'}">{stats['memory']['max']}%</span></p>
                    <p><strong>Minimum:</strong> <span class="stat-value good">{stats['memory']['min']}%</span></p>
                </div>
                
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>Disque</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value {'critical' if stats['disk']['avg'] > self.disk_threshold else 'good'}">{stats['disk']['avg']}%</span></p>
                    <p><strong>Maximum:</strong> <span class="stat-value {'critical' if stats['disk']['max'] > self.disk_threshold else 'warning' if stats['disk']['max'] > self.disk_threshold - 10 else 'good'}">{stats['disk']['max']}%</span></p>
                    <p><strong>Minimum:</strong> <span class="stat-value good">{stats['disk']['min']}%</span></p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Alertes ({stats['alerts']['total']} total)</h2>
            <p><strong>Par niveau:</strong></p>
            <ul>
                <li>CRITICAL: {stats['alerts']['by_level'].get('CRITICAL', 0)}</li>
                <li>ERROR: {stats['alerts']['by_level'].get('ERROR', 0)}</li>
                <li>WARNING: {stats['alerts']['by_level'].get('WARNING', 0)}</li>
                <li>INFO: {stats['alerts']['by_level'].get('INFO', 0)}</li>
            </ul>
            
            <p><strong>Par type:</strong></p>
            <ul>
                {''.join([f'<li>{type}: {count}</li>' for type, count in stats['alerts']['by_type'].items()])}
            </ul>
            
            <h3>Dernières alertes:</h3>
            {''.join([f'''
                <div class="alert {alert['level'].lower()}">
                    <strong>[{alert['level']}] {alert['type']}:</strong> {alert['message']}<br>
                    <small>Value: {alert['value']} | {alert['timestamp']}</small>
                </div>
            ''' for alert in report_data['alerts'][-10:]])}
        </div>
        
        <footer>
            <p>Généré par NetGuard System Monitor v1.0.0</p>
        </footer>
    </div>
</body>
</html>
"""
        return html


def main(args=None):
    """
    Fonction principale pour le module de surveillance système
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Surveiller les ressources système",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python monitor_system.py --realtime --duration 300 --interval 10
  python monitor_system.py --report --output rapport.html
  python monitor_system.py --check-cpu --check-memory --check-disk
  python monitor_system.py --services nginx,mysql,redis
        """
    )
    
    # Arguments principaux
    parser.add_argument('--realtime', action='store_true', 
                        help='Mode surveillance en temps réel')
    parser.add_argument('--duration', type=int, default=60,
                        help='Durée de la surveillance en secondes (par défaut: 60)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Intervalle entre les vérifications en secondes (par défaut: 5)')
    
    # Arguments pour les checks individuels
    parser.add_argument('--check-cpu', action='store_true',
                        help='Vérifier l\'utilisation du CPU')
    parser.add_argument('--check-memory', action='store_true',
                        help='Vérifier l\'utilisation de la mémoire')
    parser.add_argument('--check-disk', action='store_true',
                        help='Vérifier l\'utilisation du disque')
    parser.add_argument('--check-network', action='store_true',
                        help='Vérifier les statistiques réseau')
    parser.add_argument('--check-temp', action='store_true',
                        help='Vérifier la température')
    
    # Arguments pour les services
    parser.add_argument('--services', type=str, nargs='+',
                        help='Liste des services à vérifier')
    parser.add_argument('--check-services', type=str, nargs='+',
                        help='Vérifier l\'état des services spécifiés')
    
    # Arguments pour le rapport
    parser.add_argument('--report', action='store_true',
                        help='Générer un rapport')
    parser.add_argument('--output', type=str,
                        help='Fichier de sortie pour le rapport')
    parser.add_argument('--format', type=str, choices=['text', 'json', 'html'],
                        default='text', help='Format du rapport (par défaut: text)')
    
    # Arguments de configuration
    parser.add_argument('--config', type=str,
                        help='Fichier de configuration YAML')
    parser.add_argument('--cpu-threshold', type=float, default=90,
                        help='Seuil d\'alerte CPU en pourcentage (par défaut: 90)')
    parser.add_argument('--memory-threshold', type=float, default=85,
                        help='Seuil d\'alerte mémoire en pourcentage (par défaut: 85)')
    parser.add_argument('--disk-threshold', type=float, default=90,
                        help='Seuil d\'alerte disque en pourcentage (par défaut: 90)')
    parser.add_argument('--temp-threshold', type=float, default=75,
                        help='Seuil d\'alerte température en °C (par défaut: 75)')
    
    # Arguments divers
    parser.add_argument('--verbose', action='store_true',
                        help='Mode verbeux')
    parser.add_argument('--quiet', action='store_true',
                        help='Mode silencieux (pas de sortie console)')
    
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
            with open(args.config, 'r') as f:
                if HAS_YAML:
                    config = yaml.safe_load(f)
                else:
                    log.error("PyYAML non installé - impossible de charger le fichier YAML")
        except Exception as e:
            log.error(f"Erreur lors du chargement de la configuration: {e}")
    
    # Créer le moniteur
    monitor = SystemMonitor(config)
    
    # Mettre à jour les seuils si spécifiés
    monitor.cpu_threshold = args.cpu_threshold
    monitor.memory_threshold = args.memory_threshold
    monitor.disk_threshold = args.disk_threshold
    monitor.temperature_threshold = args.temp_threshold
    
    # Mode temps réel
    if args.realtime:
        monitor.monitor_realtime(args.duration, args.interval)
        return
    
    # Vérifications individuelles
    if args.check_cpu or (not any([args.realtime, args.report, args.check_memory, args.check_disk, args.check_network, args.check_temp, args.services, args.check_services])):
        cpu_data = monitor.check_cpu()
        if not args.quiet:
            print(f"\n🔹 CPU:")
            print(f"   Utilisation: {cpu_data.get('usage_percent_rounded', 'N/A')}%")
            print(f"   Cœurs: {cpu_data.get('cores', {}).get('logical', 'N/A')} (physiques: {cpu_data.get('cores', {}).get('physical', 'N/A')})")
            if 'temperatures' in cpu_data:
                for sensor_name, sensors in cpu_data['temperatures'].items():
                    for sensor in sensors:
                        print(f"   Température ({sensor['label']}): {sensor.get('current', 'N/A')}°C")
    
    if args.check_memory:
        mem_data = monitor.check_memory()
        if not args.quiet:
            print(f"\n💾 Mémoire:")
            print(f"   Utilisation: {mem_data.get('virtual', {}).get('percent_rounded', 'N/A')}%")
            print(f"   Utilisée: {mem_data.get('virtual', {}).get('used', 0) / (1024 ** 3):.2f} Go")
            print(f"   Totale: {mem_data.get('virtual', {}).get('total', 0) / (1024 ** 3):.2f} Go")
            print(f"   Swap: {mem_data.get('swap', {}).get('percent_rounded', 'N/A')}%")
    
    if args.check_disk:
        disk_data = monitor.check_disk()
        if not args.quiet:
            print(f"\n💽 Disque:")
            for partition in disk_data.get('partitions', []):
                print(f"   {partition['mountpoint']}: {partition.get('percent_rounded', 'N/A')}% "
                      f"({partition.get('used', 0) / (1024 ** 3):.2f} Go / "
                      f"{partition.get('total', 0) / (1024 ** 3):.2f} Go)")
    
    if args.check_network:
        net_data = monitor.check_network()
        if not args.quiet:
            print(f"\n🌐 Réseau:")
            for iface, stats in net_data.get('interfaces', {}).items():
                print(f"   {iface}:")
                print(f"      ✓ Envoyés: {helpers.format_bytes(stats['bytes_sent'])}")
                print(f"      ✓ Reçus: {helpers.format_bytes(stats['bytes_recv'])}")
    
    if args.check_temp:
        temp_data = monitor.check_temperature()
        if not args.quiet:
            print(f"\n🌡️  Température:")
            for sensor in temp_data.get('sensors', []):
                print(f"   {sensor['label']}: {sensor.get('current', 'N/A')}°C")
    
    # Vérification des services
    if args.services or args.check_services:
        services_to_check = args.services or args.check_services or []
        if services_to_check:
            services_data = monitor.check_services(services_to_check)
            if not args.quiet:
                print(f"\n🔄 Services:")
                for service in services_data.get('services', []):
                    status_color = '🟢' if service.get('active', False) else '🔴'
                    print(f"   {status_color} {service['name']}: {service.get('status', 'unknown')}")
    
    # Génération du rapport
    if args.report:
        report = monitor.generate_report(args.output, args.format)
        if not args.quiet and not args.output:
            print(f"\n{report}")
    elif not any([args.check_cpu, args.check_memory, args.check_disk, args.check_network, args.check_temp, args.services, args.check_services]) and not args.realtime:
        # Si aucun argument spécifique, afficher un rapport par défaut
        data = monitor.collect_all()
        monitor._display_realtime_data(data)
    
    # Afficher les alertes si elles existent
    if monitor.alert_history and not args.quiet:
        print(f"\n⚠️  Alertes détectées ({len(monitor.alert_history)}):")
        for alert in monitor.alert_history:
            level_color = {
                'INFO': '🔵',
                'WARNING': '🟡',
                'ERROR': '🟠',
                'CRITICAL': '🔴'
            }.get(alert['level'], '⚪')
            print(f"   {level_color} [{alert['level']}] {alert['message']}")


if __name__ == "__main__":
    main()
