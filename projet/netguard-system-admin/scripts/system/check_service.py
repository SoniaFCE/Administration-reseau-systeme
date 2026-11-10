#!/usr/bin/env python3
"""
NetGuard - Module de vérification des services

Ce module permet de vérifier l'état des services système.

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import time
import json
import argparse
import platform
import subprocess
from pathlib import Path

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from ..utils import logger, helpers, notifier

# Configuration du logger
log = logger.setup_logger(__name__)


class ServiceChecker:
    """Classe pour vérifier l'état des services"""
    
    def __init__(self, config=None):
        """
        Initialiser le vérificateur de services
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or {}
        self.services_to_monitor = self.config.get('services_to_monitor', [])
        self.alert_threshold = self.config.get('alert_threshold', 3)
        self.notifier = notifier.Notifier(self.config.get('alerts', {}))
        self.failed_checks = {}
        
        log.info("ServiceChecker initialisé")
    
    def check_service(self, service_name):
        """
        Vérifier l'état d'un service spécifique
        
        Args:
            service_name: Nom du service à vérifier
        
        Returns:
            dict: État du service
        """
        result = {
            'name': service_name,
            'status': 'unknown',
            'active': False,
            'enabled': False,
            'error': None
        }
        
        try:
            if platform.system() == "Linux":
                result = self._check_service_linux(service_name)
            elif platform.system() == "Windows":
                result = self._check_service_windows(service_name)
            elif platform.system() == "Darwin":  # macOS
                result = self._check_service_macos(service_name)
            else:
                result['error'] = f"Système non supporté: {platform.system()}"
        except Exception as e:
            result['error'] = str(e)
            log.error(f"Erreur lors de la vérification du service {service_name}: {e}")
        
        return result
    
    def _check_service_linux(self, service_name):
        """
        Vérifier un service sur Linux
        
        Args:
            service_name: Nom du service
        
        Returns:
            dict: État du service
        """
        result = {
            'name': service_name,
            'status': 'unknown',
            'active': False,
            'enabled': False,
            'error': None
        }
        
        try:
            # Vérifier si le service existe
            try:
                subprocess.run(
                    ['systemctl', 'cat', f'{service_name}.service'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
            except subprocess.CalledProcessError:
                # Service non trouvé
                result['error'] = f"Service {service_name} non trouvé"
                return result
            
            # Vérifier l'état du service
            try:
                output = subprocess.check_output(
                    ['systemctl', 'is-active', service_name],
                    stderr=subprocess.STDOUT,
                    text=True
                ).strip()
                result['status'] = output
                result['active'] = output == 'active'
            except subprocess.CalledProcessError as e:
                result['status'] = e.output.strip() if e.output else 'unknown'
                result['active'] = False
            
            # Vérifier si le service est activé
            try:
                output = subprocess.check_output(
                    ['systemctl', 'is-enabled', service_name],
                    stderr=subprocess.STDOUT,
                    text=True
                ).strip()
                result['enabled'] = output == 'enabled'
            except subprocess.CalledProcessError:
                result['enabled'] = False
            
            # Obtenir plus de détails
            try:
                output = subprocess.check_output(
                    ['systemctl', 'status', service_name],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                result['details'] = output
                
                # Parser les détails pour obtenir plus d'informations
                for line in output.split('\n'):
                    if 'Main PID' in line:
                        pid = line.split(':')[1].strip().split()[0]
                        result['pid'] = pid
                    if 'Memory' in line and 'Main PID' not in line:
                        memory = line.split(':')[1].strip()
                        result['memory'] = memory
                    if 'CGroup' in line:
                        cgroup = line.split(':')[1].strip()
                        result['cgroup'] = cgroup
                        
            except subprocess.CalledProcessError:
                pass
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_service_windows(self, service_name):
        """
        Vérifier un service sur Windows
        
        Args:
            service_name: Nom du service
        
        Returns:
            dict: État du service
        """
        result = {
            'name': service_name,
            'status': 'unknown',
            'active': False,
            'enabled': False,
            'error': None
        }
        
        try:
            # Vérifier l'état du service
            try:
                output = subprocess.check_output(
                    ['sc', 'query', service_name],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Parser la sortie
                for line in output.split('\n'):
                    if 'STATE' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            status = parts[1].strip().split()[0]
                            result['status'] = status
                            result['active'] = status in ['RUNNING', 'START_PENDING']
                    if 'START_TYPE' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            start_type = parts[1].strip()
                            # 2 = AUTOMATIQUE, 3 = MANUEL, 4 = DÉSACTIVÉ
                            result['enabled'] = start_type == '2' or start_type == 'AUTO_START'
                
                result['details'] = output
                
            except subprocess.CalledProcessError as e:
                result['error'] = f"Service {service_name} non trouvé ou erreur: {e.output}"
                result['status'] = 'not_found'
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_service_macos(self, service_name):
        """
        Vérifier un service sur macOS
        
        Args:
            service_name: Nom du service
        
        Returns:
            dict: État du service
        """
        result = {
            'name': service_name,
            'status': 'unknown',
            'active': False,
            'enabled': False,
            'error': None
        }
        
        try:
            # macOS utilise launchd
            # Vérifier si le service est chargé
            try:
                output = subprocess.check_output(
                    ['launchctl', 'list', service_name],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                result['active'] = True
                result['status'] = 'loaded'
                result['details'] = output
            except subprocess.CalledProcessError:
                # Service non chargé
                result['status'] = 'not_loaded'
                result['active'] = False
                
                # Vérifier si le fichier de configuration existe
                plist_files = [
                    f'/Library/LaunchDaemons/{service_name}.plist',
                    f'/Library/LaunchAgents/{service_name}.plist',
                    f'/System/Library/LaunchDaemons/{service_name}.plist',
                    f'/System/Library/LaunchAgents/{service_name}.plist'
                ]
                
                for plist in plist_files:
                    if os.path.exists(plist):
                        result['enabled'] = True
                        result['status'] = 'configured'
                        break
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_all_services(self, services=None):
        """
        Vérifier tous les services
        
        Args:
            services: Liste des services à vérifier (ou None pour tous les services configurés)
        
        Returns:
            dict: État de tous les services
        """
        if services is None:
            services = self.services_to_monitor
        
        results = {
            'services': [],
            'summary': {
                'total': len(services),
                'active': 0,
                'inactive': 0,
                'unknown': 0,
                'enabled': 0,
                'disabled': 0
            }
        }
        
        for service_name in services:
            result = self.check_service(service_name)
            results['services'].append(result)
            
            # Mettre à jour le résumé
            if result['active']:
                results['summary']['active'] += 1
            elif result['status'] == 'unknown':
                results['summary']['unknown'] += 1
            else:
                results['summary']['inactive'] += 1
            
            if result['enabled']:
                results['summary']['enabled'] += 1
            else:
                results['summary']['disabled'] += 1
            
            # Suivre les échecs
            if not result['active'] and result['status'] != 'unknown':
                if service_name not in self.failed_checks:
                    self.failed_checks[service_name] = 0
                self.failed_checks[service_name] += 1
                
                # Envoyer une alerte après le seuil
                if self.failed_checks[service_name] >= self.alert_threshold:
                    self._trigger_alert(service_name, result)
                    self.failed_checks[service_name] = 0  # Reset le compteur
        
        results['timestamp'] = datetime.datetime.now().isoformat()
        return results
    
    def check_critical_services(self):
        """
        Vérifier les services critiques
        
        Returns:
            dict: État des services critiques
        """
        critical_services = ['sshd', 'cron', 'docker', 'nginx', 'apache2', 'mysql', 'postgresql', 'redis']
        return self.check_all_services(critical_services)
    
    def _trigger_alert(self, service_name, service_result):
        """
        Déclencher une alerte pour un service
        
        Args:
            service_name: Nom du service
            service_result: Résultat de la vérification
        """
        alert = {
            'type': 'SERVICE',
            'message': f"Service {service_name} non actif: {service_result.get('status', 'unknown')}",
            'level': 'CRITICAL',
            'value': service_name,
            'timestamp': datetime.datetime.now().isoformat(),
            'details': service_result
        }
        
        # Envoyer la notification
        self.notifier.send_alert(alert)
        
        # Logger l'alerte
        log.error(f"ALERT: Service {service_name} non actif (status: {service_result.get('status')})")
    
    def start_monitoring(self, services=None, interval=60, duration=None):
        """
        Démarrer la surveillance des services
        
        Args:
            services: Liste des services à surveiller
            interval: Intervalle entre les vérifications (en secondes)
            duration: Durée totale de la surveillance (en secondes, None pour infini)
        """
        print(f"\n{'='*60}")
        print(f"SURVEILLANCE DES SERVICES - Intervalle: {interval}s")
        if duration:
            print(f"Durée: {duration}s")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        try:
            while True:
                # Vérifier les services
                results = self.check_all_services(services)
                
                # Afficher les résultats
                self._display_results(results)
                
                # Vérifier si la durée est dépassée
                if duration and (time.time() - start_time) >= duration:
                    print(f"\nSurveillance terminée après {duration}s")
                    break
                
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
            log.error(f"Erreur dans la surveillance des services: {e}")
    
    def _display_results(self, results):
        """
        Afficher les résultats de la vérification
        
        Args:
            results: Résultats de la vérification
        """
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
        print(f"{'='*60}")
        
        # Résumé
        print(f"Résumé: {results['summary']['active']} actifs, "
              f"{results['summary']['inactive']} inactifs, "
              f"{results['summary']['unknown']} inconnus")
        print()
        
        # Détails par service
        for service in results['services']:
            status_color = '🟢' if service['active'] else '🔴' if service['status'] == 'inactive' else '⚪'
            enabled_str = " (activé)" if service['enabled'] else " (désactivé)"
            
            print(f"{status_color} {service['name']}: {service.get('status', 'unknown')}{enabled_str}")
            
            if service.get('error'):
                print(f"   ⚠️  Erreur: {service['error']}")
        
        print(f"{'='*60}")


def list_all_services():
    """
    Lister tous les services disponibles
    
    Returns:
        list: Liste des services
    """
    services = []
    
    if platform.system() == "Linux":
        try:
            # Utiliser systemctl
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--no-pager', '--no-legend'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        service_name = parts[0].split('.')[0]  # Enlever le .service
                        services.append(service_name)
                        
        except Exception as e:
            log.error(f"Erreur lors de la liste des services: {e}")
    
    elif platform.system() == "Windows":
        try:
            # Utiliser sc query
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if 'SERVICE_NAME:' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        service_name = parts[1].strip()
                        services.append(service_name)
                        
        except Exception as e:
            log.error(f"Erreur lors de la liste des services: {e}")
    
    return services


import datetime

def main(args=None):
    """
    Fonction principale pour le module de vérification des services
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Vérifier l'état des services système",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python check_service.py --list-all
  python check_service.py --services nginx mysql redis
  python check_service.py --critical
  python check_service.py --monitor --services nginx apache2 --interval 30 --duration 3600
  python check_service.py --check nginx --verbose
        """
    )
    
    # Arguments principaux
    parser.add_argument('--list-all', action='store_true',
                        help='Lister tous les services disponibles')
    parser.add_argument('--services', type=str, nargs='+',
                        help='Liste des services à vérifier')
    parser.add_argument('--all', action='store_true',
                        help='Vérifier tous les services configurés')
    parser.add_argument('--critical', action='store_true',
                        help='Vérifier uniquement les services critiques')
    
    # Surveillance
    parser.add_argument('--monitor', action='store_true',
                        help='Mode surveillance continue')
    parser.add_argument('--interval', type=int, default=60,
                        help='Intervalle entre les vérifications en secondes (par défaut: 60)')
    parser.add_argument('--duration', type=int,
                        help='Durée totale de la surveillance en secondes')
    
    # Vérification individuelle
    parser.add_argument('--check', type=str,
                        help='Vérifier un service spécifique')
    
    # Arguments de configuration
    parser.add_argument('--config', type=str,
                        help='Fichier de configuration YAML')
    parser.add_argument('--alert-threshold', type=int, default=3,
                        help='Nombre d\'échecs avant alerte (par défaut: 3)')
    
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
    
    # Créer le vérificateur de services
    checker = ServiceChecker({
        'services_to_monitor': config.get('services_to_monitor', []),
        'alert_threshold': args.alert_threshold,
        'alerts': config.get('alerts', {})
    })
    
    # Lister tous les services
    if args.list_all:
        services = list_all_services()
        print("Services disponibles:")
        for service in sorted(services):
            print(f"  - {service}")
        print(f"\nTotal: {len(services)} services")
        return
    
    # Vérifier un service spécifique
    if args.check:
        result = checker.check_service(args.check)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            status_color = '🟢' if result['active'] else '🔴'
            print(f"{status_color} {result['name']}: {result.get('status', 'unknown')}")
            if result.get('enabled'):
                print(f"   Activé: Oui")
            else:
                print(f"   Activé: Non")
            if result.get('error'):
                print(f"   ⚠️  Erreur: {result['error']}")
            if result.get('details'):
                print(f"\n   Détails:")
                for line in result['details'].split('\n')[:10]:
                    print(f"   {line}")
        return
    
    # Vérifier tous les services configurés
    if args.all or (not any([args.list_all, args.check, args.critical, args.monitor, args.services])):
        services = config.get('services_to_monitor', [])
        if not services:
            services = ['sshd', 'cron', 'docker']  # Services par défaut
        results = checker.check_all_services(services)
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            checker._display_results(results)
            
            # Afficher les alertes
            if checker.failed_checks and not args.quiet:
                print(f"\n⚠️  Services en échec:")
                for service, count in checker.failed_checks.items():
                    print(f"   🔴 {service}: {count} échecs")
        return
    
    # Vérifier les services critiques
    if args.critical:
        results = checker.check_critical_services()
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            checker._display_results(results)
        return
    
    # Vérifier des services spécifiques
    if args.services:
        results = checker.check_all_services(args.services)
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            checker._display_results(results)
            
            # Afficher les alertes
            if checker.failed_checks and not args.quiet:
                print(f"\n⚠️  Services en échec:")
                for service, count in checker.failed_checks.items():
                    print(f"   🔴 {service}: {count} échecs")
        return
    
    # Mode surveillance
    if args.monitor:
        services = args.services if args.services else config.get('services_to_monitor', [])
        if not services:
            services = ['sshd', 'cron', 'docker']  # Services par défaut
        
        checker.start_monitoring(
            services=services,
            interval=args.interval,
            duration=args.duration
        )
        return


if __name__ == "__main__":
    main()
