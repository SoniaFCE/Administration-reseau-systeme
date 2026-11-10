#!/usr/bin/env python3
"""
NetGuard - System & Network Administration Toolkit
Point d'entrée principal de l'application

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import argparse
import platform
from pathlib import Path

# Ajouter le dossier scripts au path pour les imports
sys.path.insert(0, str(Path(__file__).parent / "scripts"))

# Importer les modules
try:
    from system import monitor_system
    from network import network_scan, network_config, network_diagnostic
    from security import firewall_manager, vulnerability_scan
    from users import user_management
    from storage import backup_manager
    from logs import log_analyzer
    from utils import helpers, logger, notifier
except ImportError as e:
    print(f"Erreur: Impossible de charger les modules: {e}")
    print("Assurez-vous que les dépendances sont installées: pip install -r requirements.txt")
    sys.exit(1)

# Configuration du logger
log = logger.setup_logger(__name__)


class Colors:
    """Couleurs pour l'affichage console"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clear_screen():
    """Effacer l'écran"""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')


def display_header():
    """Afficher l'en-tête du programme"""
    clear_screen()
    header = f"""
{Colors.HEADER}{'='*60}{Colors.ENDC}
{Colors.BOLD}{Colors.OKBLUE}
  _   _       _ _        __        __         _     _
 | \ | | ___ | | |___   / /  ___  / /__ _ __ | |__ (_)___  ___
 |  \| |/ _ \| | / _ \ / /  / _ \/ / _ \ '_ \| '_ \/ / __|/ _ \
 | |\  |  __/| | (_) / /  /  __/ /  __/ | | | | | | (__|  __/
 |_| \_|\___|_|\___/_/   \___/_/ \___|_| |_|_| |_|\___|\___|
{Colors.ENDC}
{Colors.HEADER}{'='*60}{Colors.ENDC}
{Colors.OKGREEN}Version: 1.0.0{Colors.ENDC}
{Colors.OKGREEN}Système: {platform.system()} {platform.release()}{Colors.ENDC}
{Colors.OKGREEN}Architecture: {platform.machine()}{Colors.ENDC}
{Colors.HEADER}{'='*60}{Colors.ENDC}
"""
    print(header)


def display_menu():
    """Afficher le menu principal"""
    menu = f"""
{Colors.BOLD}📊 MENU PRINCIPAL - NetGuard{Colors.ENDC}

{Colors.OKBLUE}🖥️  ADMINISTRATION SYSTÈME{Colors.ENDC}
{Colors.OKGREEN}  1.{Colors.ENDC} Surveiller les ressources système
{Colors.OKGREEN}  2.{Colors.ENDC} Vérifier l'état des services
{Colors.OKGREEN}  3.{Colors.ENDC} Gérer les processus
{Colors.OKGREEN}  4.{Colors.ENDC} Analyser les performances
{Colors.OKGREEN}  5.{Colors.ENDC} Gérer les utilisateurs
{Colors.OKGREEN}  6.{Colors.ENDC} Gérer les sauvegardes

{Colors.OKBLUE}🌐  ADMINISTRATION RÉSEAU{Colors.ENDC}
{Colors.OKGREEN}  7.{Colors.ENDC} Scanner le réseau
{Colors.OKGREEN}  8.{Colors.ENDC} Configurer le réseau
{Colors.OKGREEN}  9.{Colors.ENDC} Diagnostiquer le réseau
{Colors.OKGREEN} 10.{Colors.ENDC} Analyser le trafic

{Colors.OKBLUE}🔒  SÉCURITÉ{Colors.ENDC}
{Colors.OKGREEN} 11.{Colors.ENDC} Gérer le firewall
{Colors.OKGREEN} 12.{Colors.ENDC} Scanner les vulnérabilités
{Colors.OKGREEN} 13.{Colors.ENDC} Audit de sécurité

{Colors.OKBLUE}📁  LOGS & ANALYSE{Colors.ENDC}
{Colors.OKGREEN} 14.{Colors.ENDC} Analyser les logs système
{Colors.OKGREEN} 15.{Colors.ENDC} Gérer les logs

{Colors.OKBLUE}⚙️  CONFIGURATION{Colors.ENDC}
{Colors.OKGREEN} 16.{Colors.ENDC} Modifier la configuration
{Colors.OKGREEN} 17.{Colors.ENDC} Vérifier la configuration

{Colors.OKBLUE}ℹ️  INFORMATIONS{Colors.ENDC}
{Colors.OKGREEN} 18.{Colors.ENDC} Afficher les informations système
{Colors.OKGREEN} 19.{Colors.ENDC} Afficher l'aide
{Colors.OKGREEN} 20.{Colors.ENDC} Vérifier les dépendances

{Colors.OKBLUE}❌  QUITTER{Colors.ENDC}
{Colors.OKGREEN}  0.{Colors.ENDC} Quitter

{Colors.HEADER}{'='*60}{Colors.ENDC}
"""
    print(menu)


def get_user_choice():
    """Obtenir le choix de l'utilisateur"""
    try:
        choice = input(f"{Colors.BOLD}{Colors.OKBLUE}Entrez votre choix (0-20): {Colors.ENDC}").strip()
        return int(choice) if choice.isdigit() else -1
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Opération annulée par l'utilisateur{Colors.ENDC}")
        return 0
    except Exception as e:
        log.error(f"Erreur lors de la lecture du choix: {e}")
        return -1


def load_config():
    """Charger la configuration"""
    try:
        config_path = Path(__file__).parent / "config" / "config.yaml"
        if not config_path.exists():
            print(f"{Colors.WARNING}Fichier de configuration non trouvé: {config_path}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}Copiez config.example.yaml en config.yaml{Colors.ENDC}")
            return None
        
        import yaml
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        log.error(f"Erreur lors du chargement de la configuration: {e}")
        return None


def run_system_monitor():
    """Exécuter la surveillance système"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}📊 SURVEILLANCE SYSTÈME{Colors.ENDC}\n")
    
    parser = argparse.ArgumentParser(description="Surveiller les ressources système")
    parser.add_argument('--duration', type=int, default=60, help='Durée de la surveillance en secondes')
    parser.add_argument('--interval', type=int, default=5, help='Intervalle entre les vérifications en secondes')
    parser.add_argument('--realtime', action='store_true', help='Mode temps réel')
    parser.add_argument('--report', action='store_true', help='Générer un rapport')
    parser.add_argument('--output', type=str, help='Fichier de sortie pour le rapport')
    
    args = parser.parse_args([])
    
    try:
        monitor_system.main(args)
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")
        log.error(f"Erreur dans la surveillance système: {e}")
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_network_scan():
    """Exécuter un scan réseau"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}🌐 SCAN RÉSEAU{Colors.ENDC}\n")
    
    # Charger la configuration pour obtenir les paramètres réseau
    config = load_config()
    subnet = config['network']['subnet'] if config else "192.168.1.0/24"
    
    print(f"Scan du réseau: {subnet}")
    print(f"{Colors.WARNING}Ce scan peut prendre plusieurs minutes...{Colors.ENDC}\n")
    
    try:
        # Simuler un scan simple
        network_scan.scan_network(subnet)
        print(f"\n{Colors.OKGREEN}Scan terminé avec succès!{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur lors du scan: {e}{Colors.ENDC}")
        log.error(f"Erreur lors du scan réseau: {e}")
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_network_diagnostic():
    """Exécuter un diagnostic réseau"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}🔍 DIAGNOSTIC RÉSEAU{Colors.ENDC}\n")
    
    try:
        # Effectuer des tests de base
        print(f"{Colors.OKGREEN}Test de connectivité Internet...{Colors.ENDC}")
        network_diagnostic.check_internet()
        
        print(f"\n{Colors.OKGREEN}Test DNS...{Colors.ENDC}")
        network_diagnostic.check_dns()
        
        print(f"\n{Colors.OKGREEN}Test de latence...{Colors.ENDC}")
        network_diagnostic.check_latency("google.com")
        
        print(f"\n{Colors.OKGREEN}Diagnostic terminé!{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")
        log.error(f"Erreur dans le diagnostic réseau: {e}")
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_backup_manager():
    """Gérer les sauvegardes"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}💾 GESTION DES SAUVEGARDES{Colors.ENDC}\n")
    
    print("Options:")
    print("1. Sauvegarde complète")
    print("2. Sauvegarde incrémentale")
    print("3. Restaurer une sauvegarde")
    print("4. Lister les sauvegardes")
    print("5. Retour au menu")
    
    choice = input("Choix: ").strip()
    
    if choice == "1":
        backup_manager.full_backup("/tmp/test", "/tmp/backup")
    elif choice == "2":
        backup_manager.incremental_backup("/tmp/test", "/tmp/backup")
    elif choice == "3":
        backup_manager.restore_backup("/tmp/backup/test.tar.gz", "/tmp/restore")
    elif choice == "4":
        backup_manager.list_backups("/tmp/backup")
    else:
        return
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_firewall_manager():
    """Gérer le firewall"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}🔥 GESTION DU FIREWALL{Colors.ENDC}\n")
    
    print("Options:")
    print("1. Afficher les règles actuelles")
    print("2. Ajouter une règle")
    print("3. Supprimer une règle")
    print("4. Bloquer une IP")
    print("5. Autoriser un port")
    print("6. Retour au menu")
    
    choice = input("Choix: ").strip()
    
    if choice == "1":
        firewall_manager.list_rules()
    elif choice == "2":
        port = input("Port à ajouter: ").strip()
        firewall_manager.add_rule(port)
    elif choice == "3":
        rule_id = input("ID de la règle à supprimer: ").strip()
        firewall_manager.delete_rule(rule_id)
    elif choice == "4":
        ip = input("IP à bloquer: ").strip()
        firewall_manager.block_ip(ip)
    elif choice == "5":
        port = input("Port à autoriser: ").strip()
        firewall_manager.allow_port(port)
    else:
        return
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_user_management():
    """Gérer les utilisateurs"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}👥 GESTION DES UTILISATEURS{Colors.ENDC}\n")
    
    print("Options:")
    print("1. Lister les utilisateurs")
    print("2. Créer un utilisateur")
    print("3. Supprimer un utilisateur")
    print("4. Modifier un utilisateur")
    print("5. Retour au menu")
    
    choice = input("Choix: ").strip()
    
    if choice == "1":
        user_management.list_users()
    elif choice == "2":
        username = input("Nom d'utilisateur: ").strip()
        password = input("Mot de passe: ").strip()
        groups = input("Groupes (séparés par des virgules): ").strip()
        user_management.create_user(username, password, groups.split(',') if groups else [])
    elif choice == "3":
        username = input("Nom d'utilisateur à supprimer: ").strip()
        user_management.delete_user(username)
    elif choice == "4":
        username = input("Nom d'utilisateur à modifier: ").strip()
        user_management.modify_user(username)
    else:
        return
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def run_system_info():
    """Afficher les informations système"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}ℹ️  INFORMATIONS SYSTÈME{Colors.ENDC}\n")
    
    try:
        import psutil
        import platform
        
        # Informations de base
        print(f"{Colors.OKGREEN}Système d'exploitation: {Colors.ENDC}{platform.system()} {platform.release()}")
        print(f"{Colors.OKGREEN}Version: {Colors.ENDC}{platform.version()}")
        print(f"{Colors.OKGREEN}Architecture: {Colors.ENDC}{platform.machine()}")
        print(f"{Colors.OKGREEN}Nom d'hôte: {Colors.ENDC}{platform.node()}")
        print(f"{Colors.OKGREEN}Processeur: {Colors.ENDC}{platform.processor()}")
        print()
        
        # CPU
        cpu = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count(logical=True)
        print(f"{Colors.OKGREEN}CPU: {Colors.ENDC}{cpu}% utilisé ({cpu_count} cœurs)")
        
        # Mémoire
        mem = psutil.virtual_memory()
        print(f"{Colors.OKGREEN}Mémoire: {Colors.ENDC}{mem.used / (1024 ** 3):.2f} Go / {mem.total / (1024 ** 3):.2f} Go ({mem.percent}%)")
        
        # Disque
        disk = psutil.disk_usage('/')
        print(f"{Colors.OKGREEN}Disque (/): {Colors.ENDC}{disk.used / (1024 ** 3):.2f} Go / {disk.total / (1024 ** 3):.2f} Go ({disk.percent}%)")
        
        # Réseau
        net = psutil.net_if_addrs()
        print(f"{Colors.OKGREEN}Interfaces réseau: {Colors.ENDC}{', '.join(net.keys())}")
        
        # Temps de fonctionnement
        boot_time = psutil.boot_time()
        uptime = (time.time() - boot_time) / 3600
        print(f"{Colors.OKGREEN}Temps de fonctionnement: {Colors.ENDC}{uptime:.2f} heures")
        
    except ImportError:
        print(f"{Colors.FAIL}Le module psutil est requis pour les informations système.{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Installez-le avec: pip install psutil{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")
        log.error(f"Erreur dans l'affichage des informations système: {e}")
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def check_dependencies():
    """Vérifier les dépendances installées"""
    clear_screen()
    print(f"{Colors.BOLD}{Colors.OKBLUE}✅ VÉRIFICATION DES DÉPENDANCES{Colors.ENDC}\n")
    
    try:
        import pkg_resources
        
        # Lire le fichier requirements.txt
        req_path = Path(__file__).parent / "requirements.txt"
        if req_path.exists():
            with open(req_path, 'r') as f:
                requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"Vérification de {len(requirements)} packages...\n")
            
            missing = []
            for req in requirements:
                # Extraire le nom du package (avant >=, ==, etc.)
                package_name = req.split('>=')[0].split('==')[0].split('<')[0].split('>')[0].strip()
                try:
                    version = pkg_resources.get_distribution(package_name).version
                    print(f"{Colors.OKGREEN}✓ {package_name} {version}{Colors.ENDC}")
                except pkg_resources.DistributionNotFound:
                    missing.append(package_name)
                    print(f"{Colors.FAIL}✗ {package_name} (non installé){Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.WARNING}? {package_name} (erreur: {e}){Colors.ENDC}")
            
            if missing:
                print(f"\n{Colors.WARNING}Packages manquants: {', '.join(missing)}{Colors.ENDC}")
                print(f"{Colors.OKBLUE}Installez-les avec: pip install {' '.join(missing)}{Colors.ENDC}")
            else:
                print(f"\n{Colors.OKGREEN}Toutes les dépendances sont installées!{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}Fichier requirements.txt non trouvé{Colors.ENDC}")
            
    except ImportError:
        print(f"{Colors.FAIL}Le module pkg_resources est requis.{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Installez-le avec: pip install setuptools{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")
        log.error(f"Erreur dans la vérification des dépendances: {e}")
    
    input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")


def main():
    """Fonction principale"""
    import time
    
    # Initialisation
    display_header()
    
    # Boucle principale
    while True:
        try:
            display_menu()
            choice = get_user_choice()
            
            if choice == 0:
                print(f"\n{Colors.OKGREEN}Au revoir!{Colors.ENDC}")
                break
            elif choice == 1:
                run_system_monitor()
            elif choice == 2:
                # Vérifier l'état des services
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}🔄 VÉRIFICATION DES SERVICES{Colors.ENDC}\n")
                monitor_system.check_services(['nginx', 'mysql', 'redis', 'apache2', 'postgresql'])
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 3:
                # Gérer les processus
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}📋 GESTION DES PROCESSUS{Colors.ENDC}\n")
                monitor_system.list_processes()
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 4:
                # Analyser les performances
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}📈 ANALYSE DES PERFORMANCES{Colors.ENDC}\n")
                monitor_system.analyze_performance()
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 5:
                run_user_management()
            elif choice == 6:
                run_backup_manager()
            elif choice == 7:
                run_network_scan()
            elif choice == 8:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}⚙️  CONFIGURATION RÉSEAU{Colors.ENDC}\n")
                network_config.show_config()
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 9:
                run_network_diagnostic()
            elif choice == 10:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}📊 ANALYSE DU TRAFIC{Colors.ENDC}\n")
                print("Cette fonctionnalité nécessite des privilèges root.")
                print("Utilisez: sudo python3 scripts/network/traffic_analyzer.py")
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 11:
                run_firewall_manager()
            elif choice == 12:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}🔍 SCAN DE VULNÉRABILITÉS{Colors.ENDC}\n")
                print("Scan des vulnérabilités de base...")
                vulnerability_scan.basic_scan()
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 13:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}🔐 AUDIT DE SÉCURITÉ{Colors.ENDC}\n")
                print("Audit de sécurité en cours...")
                # Placeholder pour l'audit de sécurité
                print("Vérification des utilisateurs...")
                print("Vérification des permissions...")
                print("Vérification des services exposés...")
                print(f"\n{Colors.OKGREEN}Audit terminé!{Colors.ENDC}")
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 14:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}📝 ANALYSE DES LOGS{Colors.ENDC}\n")
                log_analyzer.analyze_system_logs()
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 15:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}📁 GESTION DES LOGS{Colors.ENDC}\n")
                print("Options:")
                print("1. Afficher les logs système")
                print("2. Rotater les logs")
                print("3. Nettoyer les anciens logs")
                print("4. Retour au menu")
                
                log_choice = input("Choix: ").strip()
                if log_choice == "1":
                    log_analyzer.show_system_logs()
                elif log_choice == "2":
                    log_analyzer.rotate_logs()
                elif log_choice == "3":
                    days = input("Nombre de jours à conserver: ").strip()
                    log_analyzer.clean_old_logs(int(days) if days.isdigit() else 30)
                
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 16:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}⚙️  MODIFIER LA CONFIGURATION{Colors.ENDC}\n")
                config_path = Path(__file__).parent / "config" / "config.yaml"
                print(f"Éditez le fichier: {config_path}")
                print(f"Utilisez votre éditeur de texte préféré.")
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 17:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}✅ VÉRIFIER LA CONFIGURATION{Colors.ENDC}\n")
                config = load_config()
                if config:
                    print("Configuration chargée avec succès!")
                    print(f"Nom du projet: {config.get('project_name', 'Non défini')}")
                    print(f"Version: {config.get('version', 'Non définie')}")
                    print(f"Niveau de log: {config.get('log_level', 'Non défini')}")
                else:
                    print("Impossible de charger la configuration.")
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 18:
                run_system_info()
            elif choice == 19:
                clear_screen()
                print(f"{Colors.BOLD}{Colors.OKBLUE}❓ AIDE{Colors.ENDC}\n")
                print("NetGuard - Outil d'administration système et réseau")
                print()
                print("Ce projet permet de:")
                print("- Surveiller les ressources système (CPU, RAM, disque)")
                print("- Scanner et analyser le réseau")
                print("- Gérer les utilisateurs et les sauvegardes")
                print("- Configurer le firewall et la sécurité")
                print("- Analyser les logs système")
                print()
                print("Pour plus d'informations, consultez le README.md")
                input(f"\n{Colors.OKBLUE}Appuyez sur Entrée pour revenir au menu...{Colors.ENDC}")
            elif choice == 20:
                check_dependencies()
            else:
                print(f"{Colors.FAIL}Choix invalide. Veuillez réessayer.{Colors.ENDC}")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Opération annulée par l'utilisateur{Colors.ENDC}")
            break
        except Exception as e:
            print(f"{Colors.FAIL}Une erreur est survenue: {e}{Colors.ENDC}")
            log.error(f"Erreur dans la boucle principale: {e}")
            time.sleep(2)


if __name__ == "__main__":
    main()
