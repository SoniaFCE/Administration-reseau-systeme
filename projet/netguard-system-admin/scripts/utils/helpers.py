#!/usr/bin/env python3
"""
NetGuard - Module d'aide (helpers)

Ce module contient des fonctions utilitaires générales.

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import time
import json
import hashlib
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timedelta


def format_bytes(size, decimal_places=2):
    """
    Formater une taille en bytes en une chaîne lisible
    
    Args:
        size: Taille en bytes
        decimal_places: Nombre de décimales
    
    Returns:
        str: Taille formatée
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PB':
            break
        size /= 1024.0
    
    if unit == 'B':
        return f"{size:.0f} {unit}"
    else:
        return f"{size:.{decimal_places}f} {unit}"


def format_seconds(seconds):
    """
    Formater un nombre de secondes en une chaîne lisible
    
    Args:
        seconds: Nombre de secondes
    
    Returns:
        str: Temps formaté
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days}d {hours}h"


def get_system_info():
    """
    Obtenir des informations sur le système
    
    Returns:
        dict: Informations système
    """
    info = {
        'platform': {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        },
        'python': {
            'version': sys.version,
            'executable': sys.executable
        },
        'timestamp': datetime.now().isoformat()
    }
    
    # Obtenir des informations supplémentaires
    try:
        import psutil
        
        # Mémoire
        mem = psutil.virtual_memory()
        info['memory'] = {
            'total': mem.total,
            'used': mem.used,
            'percent': mem.percent
        }
        
        # CPU
        cpu = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        info['cpu'] = {
            'usage': cpu,
            'cores': cpu_count
        }
        
        # Disque
        disk = psutil.disk_usage('/')
        info['disk'] = {
            'total': disk.total,
            'used': disk.used,
            'percent': disk.percent
        }
        
        # Temps de fonctionnement
        boot_time = psutil.boot_time()
        info['uptime'] = datetime.now() - datetime.fromtimestamp(boot_time)
        
    except ImportError:
        pass
    
    return info


def get_hostname():
    """
    Obtenir le nom d'hôte du système
    
    Returns:
        str: Nom d'hôte
    """
    return platform.node()


def get_local_ip():
    """
    Obtenir l'adresse IP locale
    
    Returns:
        str: Adresse IP locale
    """
    try:
        import socket
        
        # Créer une connexion socket pour obtenir l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Utiliser une adresse publique pour obtenir l'IP locale
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip
    except:
        return "127.0.0.1"


def get_network_interfaces():
    """
    Obtenir la liste des interfaces réseau
    
    Returns:
        list: Liste des interfaces réseau
    """
    interfaces = []
    
    try:
        import psutil
        
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for name, addrs in net_if_addrs.items():
            interface = {
                'name': name,
                'addresses': [],
                'stats': net_if_stats.get(name, {})._asdict() if name in net_if_stats else {}
            }
            
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
                
                interface['addresses'].append(addr_info)
            
            interfaces.append(interface)
        
    except ImportError:
        # Méthode alternative sans psutil
        if platform.system() == "Linux" or platform.system() == "Darwin":
            try:
                output = subprocess.check_output(['ifconfig', '-a'], text=True)
                # Parser la sortie ifconfig
                current_interface = None
                for line in output.split('\n'):
                    if line.startswith(' ') or not line.strip():
                        continue
                    
                    if ':' in line and not line.startswith(' '):
                        # Nouvelle interface
                        current_interface = {'name': line.split(':')[0], 'addresses': []}
                        interfaces.append(current_interface)
                    elif current_interface and ('inet ' in line or 'inet6' in line):
                        # Adresse IP
                        parts = line.split()
                        addr_info = {'family': 'IPv4' if 'inet ' in line else 'IPv6'}
                        for part in parts[1:]:
                            if ':' in part and 'inet6' not in part:
                                addr_info['address'] = part
                                break
                            elif '.' in part:
                                addr_info['address'] = part
                                break
                        if 'address' in addr_info:
                            current_interface['addresses'].append(addr_info)
            except:
                pass
    
    return interfaces


def execute_command(command, timeout=None, shell=True, capture_output=True):
    """
    Exécuter une commande système
    
    Args:
        command: Commande à exécuter
        timeout: Timeout en secondes
        shell: Utiliser le shell
        capture_output: Capturer la sortie
    
    Returns:
        dict: Résultat de l'exécution
    """
    result = {
        'command': command,
        'success': False,
        'returncode': None,
        'stdout': '',
        'stderr': '',
        'error': None
    }
    
    try:
        if isinstance(command, str):
            command = [command]
        
        if capture_output:
            process = subprocess.Popen(
                command if not shell else ' '.join(command),
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            process = subprocess.Popen(
                command if not shell else ' '.join(command),
                shell=shell
            )
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        result['returncode'] = process.returncode
        result['success'] = process.returncode == 0
        result['stdout'] = stdout
        result['stderr'] = stderr
        
    except subprocess.TimeoutExpired:
        process.kill()
        result['error'] = 'Timeout expiré'
        result['returncode'] = -1
    except Exception as e:
        result['error'] = str(e)
        result['returncode'] = -1
    
    return result


def read_file(file_path, encoding='utf-8'):
    """
    Lire un fichier
    
    Args:
        file_path: Chemin du fichier
        encoding: Encodage du fichier
    
    Returns:
        str: Contenu du fichier
    """
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except Exception as e:
        return None


def write_file(file_path, content, encoding='utf-8'):
    """
    Écrire dans un fichier
    
    Args:
        file_path: Chemin du fichier
        content: Contenu à écrire
        encoding: Encodage du fichier
    
    Returns:
        bool: True si succès, False sinon
    """
    try:
        # Créer le dossier si nécessaire
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        return False


def file_exists(file_path):
    """
    Vérifier si un fichier existe
    
    Args:
        file_path: Chemin du fichier
    
    Returns:
        bool: True si le fichier existe
    """
    return os.path.exists(file_path)


def get_file_size(file_path):
    """
    Obtenir la taille d'un fichier
    
    Args:
        file_path: Chemin du fichier
    
    Returns:
        int: Taille en bytes
    """
    try:
        return os.path.getsize(file_path)
    except:
        return 0


def hash_file(file_path, algorithm='sha256'):
    """
    Calculer le hash d'un fichier
    
    Args:
        file_path: Chemin du fichier
        algorithm: Algorithme de hash ('md5', 'sha1', 'sha256', 'sha512')
    
    Returns:
        str: Hash du fichier
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            # Lire le fichier par blocs pour gérer les gros fichiers
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except Exception as e:
        return None


def validate_ip(ip_address):
    """
    Valider une adresse IP
    
    Args:
        ip_address: Adresse IP à valider
    
    Returns:
        bool: True si l'adresse est valide
    """
    try:
        import ipaddress
        ipaddress.ip_address(ip_address)
        return True
    except:
        return False


def validate_subnet(subnet):
    """
    Valider un sous-réseau
    
    Args:
        subnet: Sous-réseau à valider
    
    Returns:
        bool: True si le sous-réseau est valide
    """
    try:
        import ipaddress
        ipaddress.ip_network(subnet, strict=False)
        return True
    except:
        return False


def get_file_extension(file_path):
    """
    Obtenir l'extension d'un fichier
    
    Args:
        file_path: Chemin du fichier
    
    Returns:
        str: Extension du fichier
    """
    return Path(file_path).suffix.lower()


def get_filename(file_path):
    """
    Obtenir le nom de fichier sans le chemin
    
    Args:
        file_path: Chemin du fichier
    
    Returns:
        str: Nom du fichier
    """
    return Path(file_path).name


def get_directory(file_path):
    """
    Obtenir le répertoire parent d'un fichier
    
    Args:
        file_path: Chemin du fichier
    
    Returns:
        str: Répertoire parent
    """
    return Path(file_path).parent


def join_paths(*parts):
    """
    Joindre des parties de chemin
    
    Args:
        *parts: Parties du chemin
    
    Returns:
        str: Chemin joint
    """
    return os.path.join(*parts)


def create_directory(dir_path):
    """
    Créer un répertoire
    
    Args:
        dir_path: Chemin du répertoire
    
    Returns:
        bool: True si succès, False sinon
    """
    try:
        os.makedirs(dir_path, exist_ok=True)
        return True
    except Exception as e:
        return False


def remove_directory(dir_path):
    """
    Supprimer un répertoire
    
    Args:
        dir_path: Chemin du répertoire
    
    Returns:
        bool: True si succès, False sinon
    """
    try:
        import shutil
        shutil.rmtree(dir_path)
        return True
    except Exception as e:
        return False


def list_files(directory, pattern=None, recursive=False):
    """
    Lister les fichiers dans un répertoire
    
    Args:
        directory: Répertoire à lister
        pattern: Pattern pour filtrer les fichiers
        recursive: Lister récursivement
    
    Returns:
        list: Liste des fichiers
    """
    files = []
    
    try:
        if recursive:
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    if pattern is None or pattern in filename:
                        files.append(file_path)
        else:
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                if os.path.isfile(file_path):
                    if pattern is None or pattern in filename:
                        files.append(file_path)
    except Exception as e:
        pass
    
    return files


def get_current_timestamp():
    """
    Obtenir le timestamp actuel
    
    Returns:
        str: Timestamp actuel
    """
    return datetime.now().isoformat()


def parse_timestamp(timestamp):
    """
    Parser un timestamp
    
    Args:
        timestamp: Timestamp à parser
    
    Returns:
        datetime: Date et heure parsées
    """
    try:
        return datetime.fromisoformat(timestamp)
    except:
        return None


def time_since(timestamp):
    """
    Calculer le temps écoulé depuis un timestamp
    
    Args:
        timestamp: Timestamp de départ
    
    Returns:
        timedelta: Temps écoulé
    """
    now = datetime.now()
    try:
        then = datetime.fromisoformat(timestamp)
        return now - then
    except:
        return timedelta(0)


def generate_uuid():
    """
    Générer un UUID unique
    
    Returns:
        str: UUID généré
    """
    try:
        import uuid
        return str(uuid.uuid4())
    except:
        # Alternative si uuid non disponible
        return hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]


def generate_random_string(length=16):
    """
    Générer une chaîne aléatoire
    
    Args:
        length: Longueur de la chaîne
    
    Returns:
        str: Chaîne aléatoire
    """
    import random
    import string
    
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def encrypt_string(text, key):
    """
    Chiffrer une chaîne de caractères (AES simple)
    
    Args:
        text: Texte à chiffrer
        key: Clé de chiffrement
    
    Returns:
        str: Texte chiffré (base64)
    """
    try:
        from cryptography.fernet import Fernet
        
        # générer une clé à partir de la clé fournie
        if len(key) < 32:
            key = key.ljust(32, '0')[:32]
        
        # Créer une clé Fernet
        fernet_key = hashlib.sha256(key.encode()).digest()
        fernet = Fernet(Fernet.generate_key() if not fernet_key else Fernet(Fernet(Fernet.generate_key().decode())))
        
        # Chiffrer
        encrypted = fernet.encrypt(text.encode())
        return encrypted.decode()
    except:
        return None


def decrypt_string(encrypted_text, key):
    """
    Déchiffrer une chaîne de caractères
    
    Args:
        encrypted_text: Texte chiffré (base64)
        key: Clé de chiffrement
    
    Returns:
        str: Texte déchiffré
    """
    try:
        from cryptography.fernet import Fernet
        
        # Recréer la clé Fernet
        if len(key) < 32:
            key = key.ljust(32, '0')[:32]
        
        fernet_key = hashlib.sha256(key.encode()).digest()
        fernet = Fernet(Fernet.generate_key() if not fernet_key else Fernet(Fernet(Fernet.generate_key().decode())))
        
        # Déchiffrer
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except:
        return None


def compress_data(data):
    """
    Compresser des données
    
    Args:
        data: Données à compresser (bytes ou str)
    
    Returns:
        bytes: Données compressées
    """
    try:
        import zlib
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return zlib.compress(data)
    except:
        return data if isinstance(data, bytes) else data.encode('utf-8')


def decompress_data(compressed_data):
    """
    Décompresser des données
    
    Args:
        compressed_data: Données compressées
    
    Returns:
        str: Données décompressées
    """
    try:
        import zlib
        return zlib.decompress(compressed_data).decode('utf-8')
    except:
        return compressed_data.decode('utf-8') if isinstance(compressed_data, bytes) else compressed_data


def get_user_info():
    """
    Obtenir des informations sur l'utilisateur actuel
    
    Returns:
        dict: Informations sur l'utilisateur
    """
    try:
        import pwd
        import getpass
        
        username = getpass.getuser()
        user_info = pwd.getpwnam(username)
        
        return {
            'username': username,
            'uid': user_info.pw_uid,
            'gid': user_info.pw_gid,
            'home': user_info.pw_dir,
            'shell': user_info.pw_shell
        }
    except:
        return {
            'username': os.environ.get('USERNAME', 'unknown'),
            'uid': os.getuid(),
            'gid': os.getgid()
        }
