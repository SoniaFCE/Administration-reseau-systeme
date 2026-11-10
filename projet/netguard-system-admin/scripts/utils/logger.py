#!/usr/bin/env python3
"""
NetGuard - Module de logging

Ce module fournit une configuration de logging avancée pour le projet.

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import json
import logging
import logging.config
from pathlib import Path
from datetime import datetime

# Niveaux de log personnalisés
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG

# Couleurs pour les logs (si supporté)
USE_COLORS = True

# Vérifier si les couleurs sont supportées
try:
    import colorlog
    HAS_COLORLOG = True
except ImportError:
    HAS_COLORLOG = False
    USE_COLORS = False

# Dictionnaire de configuration par défaut
default_logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(message)s'
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s %(module)s %(lineno)d'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'console_color': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'color',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': '/var/log/netguard/netguard.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'encoding': 'utf8'
        },
        'error_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'ERROR',
            'formatter': 'detailed',
            'filename': '/var/log/netguard/netguard_errors.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'encoding': 'utf8'
        },
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'address': '/dev/log'
        }
    },
    'loggers': {
        'netguard': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False
        },
        'netguard.system': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False
        },
        'netguard.network': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False
        },
        'netguard.security': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False
        }
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING'
    }
}

# Configuration avec couleurs
if USE_COLORS and HAS_COLORLOG:
    default_logging_config['formatters']['color'] = {
        '()': 'colorlog.ColoredFormatter',
        'format': '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'log_colors': {
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white'
        }
    }


class NetGuardLogger:
    """Logger personnalisé pour NetGuard"""
    
    def __init__(self, name='netguard', config=None, log_file=None, log_level=None):
        """
        Initialiser le logger NetGuard
        
        Args:
            name: Nom du logger
            config: Configuration personnalisée
            log_file: Fichier de log personnalisé
            log_level: Niveau de log personnalisé
        """
        self.name = name
        self.config = config or default_logging_config
        self.log_file = log_file
        self.log_level = log_level
        self.logger = None
        
        # Configurer le logger
        self._setup_logger()
    
    def _setup_logger(self):
        """Configurer le logger"""
        # Créer le logger
        self.logger = logging.getLogger(self.name)
        
        # Niveau de log
        level = self.log_level or self.config.get('root', {}).get('level', 'INFO')
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        # Créer les handlers
        handlers = []
        
        # Handler console
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = self.config['handlers']['console'].get('level', 'INFO')
        console_handler.setLevel(getattr(logging, console_level.upper(), logging.INFO))
        
        # Formatter avec couleurs si disponible
        if USE_COLORS and HAS_COLORLOG:
            formatter = colorlog.ColoredFormatter(
                '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white'
                }
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)
        
        # Handler fichier
        if self.log_file:
            try:
                file_handler = logging.handlers.RotatingFileHandler(
                    self.log_file,
                    maxBytes=10485760,  # 10MB
                    backupCount=5,
                    encoding='utf8'
                )
                file_level = 'DEBUG'
                file_handler.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                handlers.append(file_handler)
            except Exception as e:
                print(f"Impossible de créer le handler de fichier: {e}")
        else:
            # Utiliser le fichier par défaut
            log_dir = '/var/log/netguard'
            try:
                os.makedirs(log_dir, exist_ok=True)
                
                file_handler = logging.handlers.RotatingFileHandler(
                    os.path.join(log_dir, f'{self.name}.log'),
                    maxBytes=10485760,  # 10MB
                    backupCount=5,
                    encoding='utf8'
                )
                file_level = 'DEBUG'
                file_handler.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                handlers.append(file_handler)
            except:
                pass
        
        # Ajouter les handlers
        for handler in handlers:
            self.logger.addHandler(handler)
        
        # Éviter la propagation si c'est un logger spécifique
        if '.' in self.name:
            self.logger.propagate = False
    
    def debug(self, message, *args, **kwargs):
        """Logger un message DEBUG"""
        if self.logger:
            self.logger.debug(message, *args, **kwargs)
    
    def info(self, message, *args, **kwargs):
        """Logger un message INFO"""
        if self.logger:
            self.logger.info(message, *args, **kwargs)
    
    def warning(self, message, *args, **kwargs):
        """Logger un message WARNING"""
        if self.logger:
            self.logger.warning(message, *args, **kwargs)
    
    def error(self, message, *args, **kwargs):
        """Logger un message ERROR"""
        if self.logger:
            self.logger.error(message, *args, **kwargs)
    
    def critical(self, message, *args, **kwargs):
        """Logger un message CRITICAL"""
        if self.logger:
            self.logger.critical(message, *args, **kwargs)
    
    def exception(self, message, *args, **kwargs):
        """Logger une exception"""
        if self.logger:
            self.logger.exception(message, *args, **kwargs)
    
    def log(self, level, message, *args, **kwargs):
        """Logger un message avec un niveau personnalisé"""
        if self.logger:
            self.logger.log(level, message, *args, **kwargs)


# Logger global
_global_logger = None


def setup_logger(name='netguard', config=None, log_file=None, log_level=None):
    """
    Configurer et obtenir un logger
    
    Args:
        name: Nom du logger
        config: Configuration personnalisée
        log_file: Fichier de log personnalisé
        log_level: Niveau de log personnalisé
    
    Returns:
        NetGuardLogger: Logger configuré
    """
    global _global_logger
    
    if _global_logger is None or _global_logger.name != name:
        _global_logger = NetGuardLogger(name, config, log_file, log_level)
    
    return _global_logger


def get_logger(name='netguard'):
    """
    Obtenir un logger existant
    
    Args:
        name: Nom du logger
    
    Returns:
        NetGuardLogger: Logger
    """
    return setup_logger(name)


def set_log_level(level):
    """
    Définir le niveau de log global
    
    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = getattr(logging, level.upper(), logging.INFO)
    
    # Mettre à jour le logger global
    global _global_logger
    if _global_logger:
        _global_logger.logger.setLevel(level)
    
    # Mettre à jour la configuration par défaut
    default_logging_config['root']['level'] = level
    default_logging_config['loggers']['netguard']['level'] = level
    
    # Reconfigurer le logging
    logging.config.dictConfig(default_logging_config)


def configure_logging(log_file=None, log_level=None, console_level=None):
    """
    Configurer le logging global
    
    Args:
        log_file: Fichier de log
        log_level: Niveau de log pour le fichier
        console_level: Niveau de log pour la console
    """
    global _global_logger
    
    # Créer la configuration
    config = default_logging_config.copy()
    
    # Mettre à jour les niveaux
    if log_level:
        config['root']['level'] = log_level.upper()
        config['loggers']['netguard']['level'] = log_level.upper()
        for logger_name in ['netguard.system', 'netguard.network', 'netguard.security']:
            config['loggers'][logger_name]['level'] = log_level.upper()
    
    if console_level:
        config['handlers']['console']['level'] = console_level.upper()
        if USE_COLORS and HAS_COLORLOG:
            config['handlers']['console_color']['level'] = console_level.upper()
    
    # Mettre à jour les fichiers de log
    if log_file:
        config['handlers']['file']['filename'] = log_file
        config['handlers']['error_file']['filename'] = log_file.replace('.log', '_errors.log')
    
    # Appliquer la configuration
    try:
        logging.config.dictConfig(config)
        
        # Créer un logger global
        _global_logger = NetGuardLogger('netguard', config, log_file, log_level)
        
    except Exception as e:
        print(f"Impossible de configurer le logging: {e}")
        # Créer un logger de base
        _global_logger = NetGuardLogger('netguard', None, log_file, log_level)


def setup_file_logger(log_file, log_level='DEBUG', max_bytes=10485760, backup_count=5):
    """
    Configurer un logger pour écrire dans un fichier
    
    Args:
        log_file: Chemin du fichier de log
        log_level: Niveau de log
        max_bytes: Taille maximale du fichier avant rotation
        backup_count: Nombre de fichiers de backup
    
    Returns:
        logging.Logger: Logger configuré
    """
    # Créer le dossier si nécessaire
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except:
            pass
    
    # Créer le logger
    logger = logging.getLogger(log_file)
    logger.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))
    
    # Créer le handler
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf8'
    )
    
    # Créer le formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
    )
    handler.setFormatter(formatter)
    
    # Ajouter le handler
    logger.addHandler(handler)
    
    return logger


def colorize_text(text, color=None, bg_color=None):
    """
    Colorier un texte pour la sortie console
    
    Args:
        text: Texte à colorier
        color: Couleur du texte (red, green, yellow, blue, magenta, cyan, white)
        bg_color: Couleur de fond (bg_red, bg_green, etc.)
    
    Returns:
        str: Texte colorié
    """
    if not USE_COLORS:
        return text
    
    colors = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'bright_black': '\033[90m',
        'bright_red': '\033[91m',
        'bright_green': '\033[92m',
        'bright_yellow': '\033[93m',
        'bright_blue': '\033[94m',
        'bright_magenta': '\033[95m',
        'bright_cyan': '\033[96m',
        'bright_white': '\033[97m',
        'bg_black': '\033[40m',
        'bg_red': '\033[41m',
        'bg_green': '\033[42m',
        'bg_yellow': '\033[43m',
        'bg_blue': '\033[44m',
        'bg_magenta': '\033[45m',
        'bg_cyan': '\033[46m',
        'bg_white': '\033[47m',
        'bg_bright_black': '\033[100m',
        'bg_bright_red': '\033[101m',
        'bg_bright_green': '\033[102m',
        'bg_bright_yellow': '\033[103m',
        'bg_bright_blue': '\033[104m',
        'bg_bright_magenta': '\033[105m',
        'bg_bright_cyan': '\033[106m',
        'bg_bright_white': '\033[107m',
        'reset': '\033[0m',
        'bold': '\033[1m',
        'dim': '\033[2m',
        'underline': '\033[4m',
        'blink': '\033[5m',
        'reverse': '\033[7m',
        'hidden': '\033[8m'
    }
    
    code = ''
    if color and color in colors:
        code += colors[color]
    if bg_color and bg_color in colors:
        code += colors[bg_color]
    
    code += text
    code += colors['reset']
    
    return code


# Fonctions de logging simplifiées
def debug(message, name='netguard'):
    """Logger un message DEBUG"""
    logger = get_logger(name)
    logger.debug(message)


def info(message, name='netguard'):
    """Logger un message INFO"""
    logger = get_logger(name)
    logger.info(message)


def warning(message, name='netguard'):
    """Logger un message WARNING"""
    logger = get_logger(name)
    logger.warning(message)


def error(message, name='netguard'):
    """Logger un message ERROR"""
    logger = get_logger(name)
    logger.error(message)


def critical(message, name='netguard'):
    """Logger un message CRITICAL"""
    logger = get_logger(name)
    logger.critical(message)


def exception(message, name='netguard'):
    """Logger une exception"""
    logger = get_logger(name)
    logger.exception(message)
