#!/usr/bin/env python3
"""
NetGuard - Module de gestion des processus

Ce module permet de gérer et surveiller les processus système.

Fonctionnalités:
- Lister les processus en cours
- Surveiller l'utilisation des ressources par processus
- Tuer des processus
- Analyser les processus suspects

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import time
import json
import signal
import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class ProcessManager:
    """Classe pour la gestion des processus"""
    
    def __init__(self, config=None):
        """
        Initialiser le gestionnaire de processus
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or {}
        self.cpu_threshold = self.config.get('cpu_threshold', 80)
        self.memory_threshold = self.config.get('memory_threshold', 70)
        self.max_processes = self.config.get('max_processes', 1000)
        
        log.info("ProcessManager initialisé")
    
    def list_processes(self, sort_by='cpu', top_n=20, filter_name=None, filter_user=None):
        """
        Lister les processus en cours
        
        Args:
            sort_by: Trier par ('cpu', 'memory', 'name', 'pid', 'user')
            top_n: Nombre de processus à afficher
            filter_name: Filtrer par nom de processus
            filter_user: Filtrer par utilisateur
        
        Returns:
            list: Liste des processus
        """
        if not HAS_PSUTIL:
            log.error("psutil non disponible - impossible de lister les processus")
            return []
        
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline', 'create_time', 'status']):
                try:
                    # Convertir create_time en datetime
                    create_time = datetime.fromtimestamp(proc.info['create_time'])
                    
                    # Obtenir plus d'informations
                    try:
                        cpu_times = proc.cpu_times()
                        user_time = cpu_times.user
                        system_time = cpu_times.system
                    except:
                        user_time = 0
                        system_time = 0
                    
                    try:
                        memory_info = proc.memory_info()
                        rss = memory_info.rss
                        vms = memory_info.vms
                    except:
                        rss = 0
                        vms = 0
                    
                    # Filtrer si nécessaire
                    if filter_name and filter_name.lower() not in proc.info['name'].lower():
                        continue
                    if filter_user and filter_user.lower() != proc.info['username'].lower():
                        continue
                    
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'user': proc.info['username'] or 'N/A',
                        'cmd': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else proc.info['name'],
                        'status': proc.info['status'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'rss': rss,  # Memory usage in bytes
                        'vms': vms,
                        'user_time': user_time,
                        'system_time': system_time,
                        'create_time': create_time,
                        'uptime': datetime.now() - create_time
                    }
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Trier les processus
            if sort_by == 'cpu':
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            elif sort_by == 'memory':
                processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            elif sort_by == 'name':
                processes.sort(key=lambda x: x['name'].lower())
            elif sort_by == 'pid':
                processes.sort(key=lambda x: x['pid'])
            elif sort_by == 'user':
                processes.sort(key=lambda x: x['user'].lower())
            
            # Limiter le nombre de processus
            processes = processes[:top_n]
            
        except Exception as e:
            log.error(f"Erreur lors de la liste des processus: {e}")
        
        return processes
    
    def get_process_info(self, pid):
        """
        Obtenir des informations détaillées sur un processus
        
        Args:
            pid: ID du processus
        
        Returns:
            dict: Informations sur le processus
        """
        if not HAS_PSUTIL:
            log.error("psutil non disponible")
            return None
        
        try:
            proc = psutil.Process(pid)
            
            # Informations de base
            info = proc.as_dict(attrs=['pid', 'name', 'ppid', 'username', 'cmdline', 'cwd', 'status', 'create_time'])
            
            # Ajouter des informations supplémentaires
            try:
                info['cpu_percent'] = proc.cpu_percent(interval=0.1)
            except:
                info['cpu_percent'] = 0
            
            try:
                info['memory_percent'] = proc.memory_percent()
            except:
                info['memory_percent'] = 0
            
            try:
                memory_info = proc.memory_info()
                info['rss'] = memory_info.rss  # Memory usage in bytes
                info['vms'] = memory_info.vms
                info['pagefaults'] = memory_info.pagefaults
            except:
                info['rss'] = 0
                info['vms'] = 0
                info['pagefaults'] = 0
            
            try:
                cpu_times = proc.cpu_times()
                info['user_time'] = cpu_times.user
                info['system_time'] = cpu_times.system
                info['num_threads'] = proc.num_threads()
            except:
                info['user_time'] = 0
                info['system_time'] = 0
                info['num_threads'] = 0
            
            try:
                connections = proc.connections()
                info['connections'] = [
                    {
                        'fd': conn.fd,
                        'family': conn.family.name,
                        'type': conn.type.name,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    for conn in connections
                ]
            except:
                info['connections'] = []
            
            try:
                open_files = proc.open_files()
                info['open_files'] = [f.path for f in open_files]
            except:
                info['open_files'] = []
            
            # Convertir create_time en datetime
            info['create_time'] = datetime.fromtimestamp(info['create_time'])
            info['uptime'] = datetime.now() - info['create_time']
            
            return info
            
        except psutil.NoSuchProcess:
            log.error(f"Processus {pid} introuvable")
            return None
        except Exception as e:
            log.error(f"Erreur lors de la récupération des informations du processus {pid}: {e}")
            return None
    
    def kill_process(self, pid, signal_type=signal.SIGTERM, force=False):
        """
        Tuer un processus
        
        Args:
            pid: ID du processus
            signal_type: Type de signal à envoyer
            force: Forcer la terminaison (SIGKILL)
        
        Returns:
            bool: True si succès, False sinon
        """
        if not HAS_PSUTIL:
            log.error("psutil non disponible")
            return False
        
        try:
            proc = psutil.Process(pid)
            
            # Vérifier si le processus existe
            if not proc.is_running():
                log.warning(f"Processus {pid} n'est pas en cours d'exécution")
                return False
            
            # Envoyer le signal
            if force:
                proc.kill()
                action = "forcé (SIGKILL)"
            else:
                proc.send_signal(signal_type)
                action = f"avec signal {signal_type}"
            
            # Attendre que le processus se termine
            try:
                proc.wait(timeout=5)
                log.info(f"Processus {pid} terminé {action}")
                return True
            except psutil.TimeoutExpired:
                log.warning(f"Processus {pid} ne s'est pas terminé après le signal {signal_type}")
                if force:
                    log.info(f"Processus {pid} a été tué")
                    return True
                else:
                    log.info(f"Essayez avec force=True pour forcer la terminaison")
                    return False
            
        except psutil.NoSuchProcess:
            log.error(f"Processus {pid} introuvable")
            return False
        except psutil.AccessDenied:
            log.error(f"Permission refusée pour tuer le processus {pid}")
            return False
        except Exception as e:
            log.error(f"Erreur lors de la terminaison du processus {pid}: {e}")
            return False
    
    def kill_process_by_name(self, name, signal_type=signal.SIGTERM, force=False):
        """
        Tuer des processus par nom
        
        Args:
            name: Nom du processus
            signal_type: Type de signal à envoyer
            force: Forcer la terminaison
        
        Returns:
            dict: Résultats de l'opération
        """
        results = {
            'name': name,
            'killed': [],
            'failed': [],
            'not_found': []
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if name.lower() in proc.info['name'].lower():
                        if self.kill_process(proc.info['pid'], signal_type, force):
                            results['killed'].append(proc.info['pid'])
                        else:
                            results['failed'].append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Vérifier si des processus ont été trouvés
            if not results['killed'] and not results['failed']:
                results['not_found'].append(name)
            
        except Exception as e:
            log.error(f"Erreur lors de la recherche des processus par nom: {e}")
        
        return results
    
    def monitor_processes(self, duration=60, interval=5, sort_by='cpu', top_n=10):
        """
        Surveiller les processus en temps réel
        
        Args:
            duration: Durée de la surveillance en secondes
            interval: Intervalle entre les vérifications en secondes
            sort_by: Trier par ('cpu', 'memory', 'name', 'pid', 'user')
            top_n: Nombre de processus à afficher
        """
        print(f"\n{'='*70}")
        print(f"SURVEILLANCE DES PROCESSUS - Durée: {duration}s, Intervalle: {interval}s")
        print(f"{'='*70}\n")
        
        end_time = time.time() + duration
        
        try:
            while time.time() < end_time:
                # Lister les processus
                processes = self.list_processes(sort_by=sort_by, top_n=top_n)
                
                # Afficher les informations
                self._display_processes(processes)
                
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
            log.error(f"Erreur dans la surveillance des processus: {e}")
    
    def _display_processes(self, processes):
        """
        Afficher les processus
        
        Args:
            processes: Liste des processus à afficher
        """
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
        print(f"{'='*70}")
        
        # En-tête du tableau
        headers = ['PID', 'User', 'Name', 'CPU %', 'Mem %', 'Status', 'Uptime']
        print(f"{headers[0]:<8} {headers[1]:<12} {headers[2]:<20} {headers[3]:>8} {headers[4]:>8} {headers[5]:<10} {headers[6]:<15}")
        print("-" * 70)
        
        # Afficher chaque processus
        for proc in processes:
            # Formater l'uptime
            uptime = proc['uptime']
            if uptime.days > 0:
                uptime_str = f"{uptime.days}d {uptime.seconds//3600}h"
            elif uptime.seconds >= 3600:
                uptime_str = f"{uptime.seconds//3600}h {uptime.seconds%3600//60}m"
            elif uptime.seconds >= 60:
                uptime_str = f"{uptime.seconds//60}m {uptime.seconds%60}s"
            else:
                uptime_str = f"{uptime.seconds}s"
            
            # Limiter le nom à 18 caractères
            name = proc['name'][:18]
            
            print(f"{proc['pid']:<8} {proc['user']:<12} {name:<20} {proc['cpu_percent']:>7.1f}% {proc['memory_percent']:>7.1f}% {proc['status']:<10} {uptime_str:<15}")
        
        print(f"{'='*70}")
        
        # Afficher les processus suspects
        suspicious = self.find_suspicious_processes(processes)
        if suspicious:
            print("\n⚠️  Processus suspects:")
            for proc in suspicious:
                print(f"   🔴 {proc['name']} (PID: {proc['pid']}): "
                      f"CPU: {proc['cpu_percent']:.1f}%, "
                      f"Mem: {proc['memory_percent']:.1f}%")
    
    def find_suspicious_processes(self, processes=None, cpu_threshold=None, memory_threshold=None):
        """
        Trouver les processus suspects
        
        Args:
            processes: Liste des processus à analyser
            cpu_threshold: Seuil CPU pour être suspect
            memory_threshold: Seuil mémoire pour être suspect
        
        Returns:
            list: Liste des processus suspects
        """
        if cpu_threshold is None:
            cpu_threshold = self.cpu_threshold
        if memory_threshold is None:
            memory_threshold = self.memory_threshold
        
        if processes is None:
            processes = self.list_processes()
        
        suspicious = []
        
        for proc in processes:
            if (proc['cpu_percent'] > cpu_threshold or 
                proc['memory_percent'] > memory_threshold):
                suspicious.append(proc)
        
        return suspicious
    
    def find_high_cpu_processes(self, threshold=80, top_n=10):
        """
        Trouver les processus avec une utilisation CPU élevée
        
        Args:
            threshold: Seuil de CPU en pourcentage
            top_n: Nombre de processus à retourner
        
        Returns:
            list: Liste des processus avec CPU élevé
        """
        processes = self.list_processes(sort_by='cpu', top_n=top_n)
        return [p for p in processes if p['cpu_percent'] > threshold]
    
    def find_high_memory_processes(self, threshold=70, top_n=10):
        """
        Trouver les processus avec une utilisation mémoire élevée
        
        Args:
            threshold: Seuil de mémoire en pourcentage
            top_n: Nombre de processus à retourner
        
        Returns:
            list: Liste des processus avec mémoire élevée
        """
        processes = self.list_processes(sort_by='memory', top_n=top_n)
        return [p for p in processes if p['memory_percent'] > threshold]
    
    def analyze_process_tree(self, pid, max_depth=5):
        """
        Analyser l'arborescence des processus
        
        Args:
            pid: ID du processus racine
            max_depth: Profondeur maximale de l'arborescence
        
        Returns:
            dict: Arborescence des processus
        """
        if not HAS_PSUTIL:
            log.error("psutil non disponible")
            return {}
        
        tree = {}
        
        try:
            def build_tree(proc, depth=0):
                if depth > max_depth:
                    return None
                
                node = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'user': proc.username() or 'N/A',
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_percent': proc.memory_percent(),
                    'status': proc.status(),
                    'children': []
                }
                
                try:
                    for child in proc.children(recursive=False):
                        child_node = build_tree(child, depth + 1)
                        if child_node:
                            node['children'].append(child_node)
                except:
                    pass
                
                return node
            
            proc = psutil.Process(pid)
            tree = build_tree(proc)
            
        except psutil.NoSuchProcess:
            log.error(f"Processus {pid} introuvable")
        except Exception as e:
            log.error(f"Erreur lors de l'analyse de l'arborescence: {e}")
        
        return tree
    
    def get_system_load(self):
        """
        Obtenir la charge système
        
        Returns:
            dict: Charge système
        """
        if not HAS_PSUTIL:
            return {'error': 'psutil non disponible'}
        
        try:
            # Charge CPU moyenne
            cpu_load = psutil.cpu_percent(interval=1, percpu=True)
            cpu_count = psutil.cpu_count()
            
            # Load average (Unix-like systems)
            if platform.system() != "Windows":
                try:
                    load_avg = psutil.getloadavg()
                except:
                    load_avg = (0, 0, 0)
            else:
                load_avg = (0, 0, 0)
            
            # Mémoire
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Processus
            pids = psutil.pids()
            
            return {
                'cpu': {
                    'load': cpu_load,
                    'average': sum(cpu_load) / len(cpu_load) if cpu_load else 0,
                    'cores': cpu_count
                },
                'load_avg': {
                    '1min': load_avg[0],
                    '5min': load_avg[1],
                    '15min': load_avg[2]
                },
                'memory': {
                    'total': mem.total,
                    'used': mem.used,
                    'free': mem.free,
                    'percent': mem.percent
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'processes': {
                    'total': len(pids),
                    'running': sum(1 for p in psutil.process_iter() if p.info['status'] == psutil.STATUS_RUNNING),
                    'sleeping': sum(1 for p in psutil.process_iter() if p.info['status'] == psutil.STATUS_SLEEPING),
                    'zombie': sum(1 for p in psutil.process_iter() if p.info['status'] == psutil.STATUS_ZOMBIE)
                },
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            log.error(f"Erreur lors de la récupération de la charge système: {e}")
            return {'error': str(e)}


class ProcessColors:
    """Couleurs pour l'affichage des processus"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main(args=None):
    """
    Fonction principale pour le module de gestion des processus
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Gérer et surveiller les processus système",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python process_manager.py --list
  python process_manager.py --list --sort memory --top 10
  python process_manager.py --list --filter nginx
  python process_manager.py --monitor --duration 300 --interval 5
  python process_manager.py --info 1234
  python process_manager.py --kill 1234
  python process_manager.py --kill-name nginx
  python process_manager.py --suspicious
  python process_manager.py --load
        """
    )
    
    # Arguments pour la liste
    parser.add_argument('--list', action='store_true',
                        help='Lister les processus')
    parser.add_argument('--sort', type=str, choices=['cpu', 'memory', 'name', 'pid', 'user'],
                        default='cpu', help='Trier par (par défaut: cpu)')
    parser.add_argument('--top', type=int, default=20,
                        help='Nombre de processus à afficher (par défaut: 20)')
    parser.add_argument('--filter', type=str,
                        help='Filtrer par nom de processus')
    parser.add_argument('--user', type=str,
                        help='Filtrer par utilisateur')
    
    # Arguments pour la surveillance
    parser.add_argument('--monitor', action='store_true',
                        help='Surveiller les processus en temps réel')
    parser.add_argument('--duration', type=int, default=60,
                        help='Durée de la surveillance en secondes (par défaut: 60)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Intervalle entre les vérifications en secondes (par défaut: 5)')
    
    # Arguments pour les informations
    parser.add_argument('--info', type=int,
                        help='Obtenir des informations détaillées sur un processus (PID)')
    parser.add_argument('--tree', type=int,
                        help='Afficher l\'arborescence des processus pour un PID')
    
    # Arguments pour tuer des processus
    parser.add_argument('--kill', type=int,
                        help='Tuer un processus par PID')
    parser.add_argument('--kill-name', type=str,
                        help='Tuer des processus par nom')
    parser.add_argument('--force', action='store_true',
                        help='Forcer la terminaison (SIGKILL)')
    parser.add_argument('--signal', type=int, default=15,
                        help='Signal à envoyer (par défaut: 15 = SIGTERM)')
    
    # Arguments pour l'analyse
    parser.add_argument('--suspicious', action='store_true',
                        help='Trouver les processus suspects')
    parser.add_argument('--high-cpu', action='store_true',
                        help='Trouver les processus avec CPU élevé')
    parser.add_argument('--high-memory', action='store_true',
                        help='Trouver les processus avec mémoire élevée')
    parser.add_argument('--load', action='store_true',
                        help='Afficher la charge système')
    
    # Arguments pour les seuils
    parser.add_argument('--cpu-threshold', type=float, default=80,
                        help='Seuil CPU pour les processus suspects (par défaut: 80)')
    parser.add_argument('--memory-threshold', type=float, default=70,
                        help='Seuil mémoire pour les processus suspects (par défaut: 70)')
    
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
                if 'system_monitor' in config:
                    config = config['system_monitor']
        except Exception as e:
            log.error(f"Erreur lors du chargement de la configuration: {e}")
    
    # Créer le gestionnaire de processus
    manager = ProcessManager({
        'cpu_threshold': args.cpu_threshold,
        'memory_threshold': args.memory_threshold
    })
    
    # Lister les processus
    if args.list:
        processes = manager.list_processes(
            sort_by=args.sort,
            top_n=args.top,
            filter_name=args.filter,
            filter_user=args.user
        )
        
        if args.json:
            print(json.dumps(processes, indent=2, default=str))
        else:
            manager._display_processes(processes)
        return
    
    # Surveiller les processus
    if args.monitor:
        manager.monitor_processes(
            duration=args.duration,
            interval=args.interval,
            sort_by=args.sort,
            top_n=args.top
        )
        return
    
    # Afficher les informations d'un processus
    if args.info:
        info = manager.get_process_info(args.info)
        
        if args.json:
            print(json.dumps(info, indent=2, default=str))
        else:
            if info:
                print(f"\nInformations sur le processus {args.info}:")
                print(f"{'='*50}")
                print(f"Nom: {info.get('name', 'N/A')}")
                print(f"PID: {info.get('pid', 'N/A')}")
                print(f"PPID: {info.get('ppid', 'N/A')}")
                print(f"Utilisateur: {info.get('user', 'N/A')}")
                print(f"Commande: {info.get('cmd', 'N/A')}")
                print(f"Status: {info.get('status', 'N/A')}")
                print(f"Dossier: {info.get('cwd', 'N/A')}")
                print(f"CPU: {info.get('cpu_percent', 0):.1f}%")
                print(f"Mémoire: {info.get('memory_percent', 0):.1f}% ({helpers.format_bytes(info.get('rss', 0))})")
                print(f"Temps CPU (user): {info.get('user_time', 0):.2f}s")
                print(f"Temps CPU (système): {info.get('system_time', 0):.2f}s")
                print(f"Threads: {info.get('num_threads', 0)}")
                print(f"Créé: {info.get('create_time', 'N/A')}")
                print(f"Uptime: {info.get('uptime', 'N/A')}")
                
                if info.get('connections'):
                    print(f"\nConnexions:")
                    for conn in info['connections']:
                        print(f"  {conn['family']} {conn['type']} {conn.get('laddr', 'N/A')} -> {conn.get('raddr', 'N/A')} ({conn['status']})")
                
                if info.get('open_files'):
                    print(f"\nFichiers ouverts ({len(info['open_files'])}):")
                    for file in info['open_files'][:10]:
                        print(f"  - {file}")
                    if len(info['open_files']) > 10:
                        print(f"  ... et {len(info['open_files']) - 10} de plus")
            else:
                print(f"Processus {args.info} introuvable")
        return
    
    # Afficher l'arborescence des processus
    if args.tree:
        tree = manager.analyze_process_tree(args.tree)
        
        if args.json:
            print(json.dumps(tree, indent=2, default=str))
        else:
            def print_tree(node, prefix=""):
                if not node:
                    return
                
                status_color = ProcessColors.OKGREEN if node['status'] == 'running' else ProcessColors.FAIL
                print(f"{prefix}{status_color}🔹 {node['name']} (PID: {node['pid']}, User: {node['user']}) - "
                      f"CPU: {node['cpu_percent']:.1f}%, Mem: {node['memory_percent']:.1f}%{ProcessColors.ENDC}")
                
                for child in node.get('children', []):
                    print_tree(child, prefix + "  ")
            
            print(f"\nArborescence des processus pour PID {args.tree}:")
            print(f"{'='*60}")
            print_tree(tree)
        return
    
    # Tuer un processus par PID
    if args.kill:
        if args.force:
            signal_type = signal.SIGKILL
        else:
            signal_type = args.signal
        
        success = manager.kill_process(args.kill, signal_type, args.force)
        
        if success:
            print(f"Processus {args.kill} tué avec succès")
        else:
            print(f"Échec de la terminaison du processus {args.kill}")
        return
    
    # Tuer des processus par nom
    if args.kill_name:
        results = manager.kill_process_by_name(args.kill_name, args.signal if not args.force else signal.SIGKILL, args.force)
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print(f"\nRésultats de la terminaison de '{args.kill_name}':")
            if results['killed']:
                print(f"  ✅ Tués: {', '.join(map(str, results['killed']))}")
            if results['failed']:
                print(f"  ❌ Échecs: {', '.join(map(str, results['failed']))}")
            if results['not_found']:
                print(f"  ⚠️  Non trouvés: {', '.join(results['not_found'])}")
        return
    
    # Trouver les processus suspects
    if args.suspicious:
        suspicious = manager.find_suspicious_processes(
            cpu_threshold=args.cpu_threshold,
            memory_threshold=args.memory_threshold
        )
        
        if args.json:
            print(json.dumps(suspicious, indent=2, default=str))
        else:
            print(f"\nProcessus suspects (CPU > {args.cpu_threshold}% ou Mem > {args.memory_threshold}%):")
            print(f"{'='*70}")
            if suspicious:
                headers = ['PID', 'User', 'Name', 'CPU %', 'Mem %', 'Status']
                print(f"{headers[0]:<8} {headers[1]:<12} {headers[2]:<20} {headers[3]:>8} {headers[4]:>8} {headers[5]:<10}")
                print("-" * 70)
                for proc in suspicious:
                    print(f"{proc['pid']:<8} {proc['user']:<12} {proc['name'][:18]:<20} {proc['cpu_percent']:>7.1f}% {proc['memory_percent']:>7.1f}% {proc['status']:<10}")
            else:
                print("Aucun processus suspect trouvé")
        return
    
    # Trouver les processus avec CPU élevé
    if args.high_cpu:
        high_cpu = manager.find_high_cpu_processes(args.cpu_threshold, args.top)
        
        if args.json:
            print(json.dumps(high_cpu, indent=2, default=str))
        else:
            print(f"\nProcessus avec CPU > {args.cpu_threshold}%:")
            manager._display_processes(high_cpu)
        return
    
    # Trouver les processus avec mémoire élevée
    if args.high_memory:
        high_memory = manager.find_high_memory_processes(args.memory_threshold, args.top)
        
        if args.json:
            print(json.dumps(high_memory, indent=2, default=str))
        else:
            print(f"\nProcessus avec mémoire > {args.memory_threshold}%:")
            manager._display_processes(high_memory)
        return
    
    # Afficher la charge système
    if args.load:
        load = manager.get_system_load()
        
        if args.json:
            print(json.dumps(load, indent=2, default=str))
        else:
            print(f"\nCharge système:")
            print(f"{'='*50}")
            
            # CPU
            print(f"\nCPU:")
            print(f"  Moyenne: {load['cpu']['average']:.1f}%")
            for i, percent in enumerate(load['cpu']['load']):
                print(f"  Cœur {i}: {percent:.1f}%")
            print(f"  Nombre de cœurs: {load['cpu']['cores']}")
            
            # Load average
            if platform.system() != "Windows":
                print(f"\nLoad Average:")
                print(f"  1 minute: {load['load_avg']['1min']:.2f}")
                print(f"  5 minutes: {load['load_avg']['5min']:.2f}")
                print(f"  15 minutes: {load['load_avg']['15min']:.2f}")
            
            # Mémoire
            print(f"\nMémoire:")
            print(f"  Totale: {helpers.format_bytes(load['memory']['total'])}")
            print(f"  Utilisée: {helpers.format_bytes(load['memory']['used'])} ({load['memory']['percent']:.1f}%)")
            print(f"  Libre: {helpers.format_bytes(load['memory']['free'])}")
            
            # Swap
            print(f"\nSwap:")
            print(f"  Totale: {helpers.format_bytes(load['swap']['total'])}")
            print(f"  Utilisée: {helpers.format_bytes(load['swap']['used'])} ({load['swap']['percent']:.1f}%)")
            print(f"  Libre: {helpers.format_bytes(load['swap']['free'])}")
            
            # Processus
            print(f"\nProcessus:")
            print(f"  Total: {load['processes']['total']}")
            print(f"  En cours: {load['processes']['running']}")
            print(f"  En veille: {load['processes']['sleeping']}")
            print(f"  Zombie: {load['processes']['zombie']}")
        return
    
    # Si aucun argument n'est fourni, afficher la liste par défaut
    processes = manager.list_processes(sort_by=args.sort, top_n=args.top)
    manager._display_processes(processes)


if __name__ == "__main__":
    main()
