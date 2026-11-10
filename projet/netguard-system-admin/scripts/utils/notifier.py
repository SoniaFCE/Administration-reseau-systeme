#!/usr/bin/env python3
"""
NetGuard - Module de notifications

Ce module permet d'envoyer des notifications via différents canaux:
- Email (SMTP)
- Slack (Webhook)
- Webhook HTTP
- Syslog
- Console

Auteur: NetGuard Team
Licence: MIT
"""

import os
import sys
import json
import time
import smtplib
import socket
import requests
import logging
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Importer le logger
from . import logger

log = logger.setup_logger(__name__)


class Notifier:
    """Classe pour l'envoi de notifications"""
    
    def __init__(self, config=None):
        """
        Initialiser le notificateur
        
        Args:
            config: Configuration des notifications
        """
        self.config = config or {}
        self.history = []
        self.max_history = 100
        
        # Configuration par défaut
        self.default_config = {
            'email': {
                'enabled': False,
                'smtp': {
                    'server': 'smtp.gmail.com',
                    'port': 587,
                    'tls': True,
                    'ssl': False,
                    'username': '',
                    'password': ''
                },
                'sender': {
                    'name': 'NetGuard',
                    'email': 'netguard@localhost'
                },
                'recipients': [],
                'subject_prefix': '[NetGuard]',
                'min_level': 'WARNING'
            },
            'slack': {
                'enabled': False,
                'webhook_url': '',
                'channel': '#netguard-alerts',
                'username': 'NetGuard Bot',
                'icon_emoji': ':robot_face:',
                'min_level': 'ERROR'
            },
            'webhook': {
                'enabled': False,
                'url': '',
                'method': 'POST',
                'headers': {
                    'Content-Type': 'application/json'
                },
                'min_level': 'CRITICAL'
            },
            'syslog': {
                'enabled': True,
                'facility': 'local0',
                'min_level': 'INFO'
            },
            'console': {
                'enabled': True,
                'min_level': 'DEBUG'
            }
        }
        
        # Fusionner avec la configuration fournie
        self._merge_config()
        
        log.info("Notifier initialisé")
    
    def _merge_config(self):
        """Fusionner la configuration par défaut avec la configuration fournie"""
        def merge_dict(default, custom):
            """Fusionner deux dictionnaires"""
            for key, value in custom.items():
                if key in default and isinstance(value, dict):
                    merge_dict(default[key], value)
                else:
                    default[key] = value
            return default
        
        self.config = merge_dict(self.default_config.copy(), self.config)
    
    def send_alert(self, alert):
        """
        Envoyer une alerte via tous les canaux configurés
        
        Args:
            alert: Dictionnaire contenant les informations de l'alerte
        """
        # Normaliser l'alerte
        alert = self._normalize_alert(alert)
        
        # Vérifier le niveau minimum pour chaque canal
        if self._should_send('email', alert):
            self.send_email(alert)
        
        if self._should_send('slack', alert):
            self.send_slack(alert)
        
        if self._should_send('webhook', alert):
            self.send_webhook(alert)
        
        if self._should_send('syslog', alert):
            self.send_syslog(alert)
        
        if self._should_send('console', alert):
            self.send_console(alert)
        
        # Ajouter à l'historique
        self._add_to_history(alert)
    
    def _normalize_alert(self, alert):
        """
        Normaliser une alerte
        
        Args:
            alert: Alerte à normaliser
        
        Returns:
            dict: Alerte normalisée
        """
        if not isinstance(alert, dict):
            alert = {'message': str(alert)}
        
        # Valeurs par défaut
        normalized = {
            'type': alert.get('type', 'GENERIC'),
            'message': alert.get('message', 'Alerte sans message'),
            'level': alert.get('level', 'INFO').upper(),
            'value': alert.get('value', None),
            'timestamp': alert.get('timestamp', datetime.now().isoformat()),
            'details': alert.get('details', {}),
            'source': alert.get('source', 'netguard')
        }
        
        return normalized
    
    def _should_send(self, channel, alert):
        """
        Vérifier si une alerte doit être envoyée via un canal
        
        Args:
            channel: Nom du canal
            alert: Alerte à vérifier
        
        Returns:
            bool: True si l'alerte doit être envoyée
        """
        # Vérifier si le canal est activé
        if not self.config.get(channel, {}).get('enabled', False):
            return False
        
        # Vérifier le niveau minimum
        min_level = self.config.get(channel, {}).get('min_level', 'DEBUG').upper()
        alert_level = alert.get('level', 'INFO').upper()
        
        levels = {
            'DEBUG': 10,
            'INFO': 20,
            'WARNING': 30,
            'ERROR': 40,
            'CRITICAL': 50
        }
        
        return levels.get(alert_level, 20) >= levels.get(min_level, 20)
    
    def _add_to_history(self, alert):
        """
        Ajouter une alerte à l'historique
        
        Args:
            alert: Alerte à ajouter
        """
        self.history.append(alert)
        
        # Limiter la taille de l'historique
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
    
    def send_email(self, alert):
        """
        Envoyer une alerte par email
        
        Args:
            alert: Alerte à envoyer
        
        Returns:
            bool: True si succès, False sinon
        """
        config = self.config.get('email', {})
        
        if not config.get('enabled', False):
            return False
        
        try:
            # Créer le message
            msg = MIMEMultipart()
            
            # Sujet
            subject = f"{config.get('subject_prefix', '[NetGuard]')} {alert.get('type', 'Alert')} - {alert.get('level', 'INFO')}"
            msg['Subject'] = subject
            
            # Expéditeur
            sender_name = config.get('sender', {}).get('name', 'NetGuard')
            sender_email = config.get('sender', {}).get('email', 'netguard@localhost')
            msg['From'] = f"{sender_name} <{sender_email}>"
            
            # Destinataires
            recipients = config.get('recipients', [])
            if not recipients:
                log.warning("Aucun destinataire configuré pour les emails")
                return False
            
            msg['To'] = ', '.join(recipients)
            
            # Contenu
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'plain'))
            
            # Envoyer le message
            smtp_config = config.get('smtp', {})
            server = smtp_config.get('server', 'localhost')
            port = smtp_config.get('port', 25)
            username = smtp_config.get('username', '')
            password = smtp_config.get('password', '')
            use_tls = smtp_config.get('tls', False)
            use_ssl = smtp_config.get('ssl', False)
            
            with smtplib.SMTP(server, port) as smtp:
                if use_ssl:
                    smtp = smtplib.SMTP_SSL(server, port)
                
                if use_tls and not use_ssl:
                    smtp.starttls()
                
                if username and password:
                    smtp.login(username, password)
                
                smtp.send_message(msg)
                
            log.info(f"Email envoyé: {subject}")
            return True
            
        except Exception as e:
            log.error(f"Erreur lors de l'envoi de l'email: {e}")
            return False
    
    def _format_email_body(self, alert):
        """
        Formater le corps d'un email
        
        Args:
            alert: Alerte à formater
        
        Returns:
            str: Corps de l'email
        """
        lines = []
        lines.append(f"NetGuard Alert Notification")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Type: {alert.get('type', 'GENERIC')}")
        lines.append(f"Level: {alert.get('level', 'INFO')}")
        lines.append(f"Timestamp: {alert.get('timestamp', 'N/A')}")
        lines.append(f"Source: {alert.get('source', 'netguard')}")
        lines.append("")
        lines.append(f"Message: {alert.get('message', 'No message')}")
        lines.append("")
        
        if alert.get('value'):
            lines.append(f"Value: {alert.get('value')}")
            lines.append("")
        
        if alert.get('details'):
            lines.append("Details:")
            for key, value in alert['details'].items():
                lines.append(f"  {key}: {value}")
            lines.append("")
        
        lines.append("=" * 50)
        lines.append("This is an automated message from NetGuard")
        
        return '\n'.join(lines)
    
    def send_slack(self, alert):
        """
        Envoyer une alerte via Slack
        
        Args:
            alert: Alerte à envoyer
        
        Returns:
            bool: True si succès, False sinon
        """
        config = self.config.get('slack', {})
        
        if not config.get('enabled', False):
            return False
        
        webhook_url = config.get('webhook_url', '')
        if not webhook_url:
            log.warning("Aucune URL de webhook Slack configurée")
            return False
        
        try:
            # Créer le payload
            payload = self._format_slack_message(alert, config)
            
            # Envoyer la requête
            headers = {'Content-Type': 'application/json'}
            response = requests.post(webhook_url, data=json.dumps(payload), headers=headers, timeout=10)
            
            if response.status_code == 200:
                log.info(f"Message Slack envoyé: {alert.get('type')}")
                return True
            else:
                log.error(f"Échec de l'envoi du message Slack: {response.status_code} - {response.text}")
                return False
            
        except Exception as e:
            log.error(f"Erreur lors de l'envoi du message Slack: {e}")
            return False
    
    def _format_slack_message(self, alert, config):
        """
        Formater un message Slack
        
        Args:
            alert: Alerte à formater
            config: Configuration Slack
        
        Returns:
            dict: Payload Slack
        """
        # Déterminer la couleur en fonction du niveau
        level = alert.get('level', 'INFO').upper()
        color_map = {
            'INFO': '#36a64f',    # Vert
            'WARNING': '#ffcc00',  # Jaune
            'ERROR': '#ff3300',    # Rouge
            'CRITICAL': '#ff0000'  # Rouge foncé
        }
        color = color_map.get(level, '#36a64f')
        
        # Créer le payload
        payload = {
            'username': config.get('username', 'NetGuard Bot'),
            'icon_emoji': config.get('icon_emoji', ':robot_face:'),
            'channel': config.get('channel', '#netguard-alerts'),
            'attachments': [
                {
                    'color': color,
                    'title': f"{alert.get('type', 'Alert')} - {level}",
                    'text': alert.get('message', 'No message'),
                    'fields': [],
                    'footer': 'NetGuard',
                    'ts': int(time.time())
                }
            ]
        }
        
        # Ajouter des champs supplémentaires
        fields = []
        
        if alert.get('timestamp'):
            fields.append({
                'title': 'Timestamp',
                'value': alert['timestamp'],
                'short': True
            })
        
        if alert.get('value'):
            fields.append({
                'title': 'Value',
                'value': str(alert['value']),
                'short': True
            })
        
        if alert.get('source'):
            fields.append({
                'title': 'Source',
                'value': alert['source'],
                'short': True
            })
        
        if alert.get('details'):
            for key, value in alert['details'].items():
                fields.append({
                    'title': str(key),
                    'value': str(value),
                    'short': len(str(value)) < 20
                })
        
        payload['attachments'][0]['fields'] = fields
        
        return payload
    
    def send_webhook(self, alert):
        """
        Envoyer une alerte via un webhook HTTP
        
        Args:
            alert: Alerte à envoyer
        
        Returns:
            bool: True si succès, False sinon
        """
        config = self.config.get('webhook', {})
        
        if not config.get('enabled', False):
            return False
        
        url = config.get('url', '')
        if not url:
            log.warning("Aucune URL de webhook configurée")
            return False
        
        try:
            # Créer le payload
            payload = self._format_webhook_payload(alert, config)
            
            # Créer les headers
            headers = config.get('headers', {})
            headers['Content-Type'] = headers.get('Content-Type', 'application/json')
            
            # Envoyer la requête
            method = config.get('method', 'POST').upper()
            
            if method == 'POST':
                response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, data=json.dumps(payload), headers=headers, timeout=10)
            else:
                # GET avec les paramètres dans l'URL
                response = requests.get(url, params=payload, headers=headers, timeout=10)
            
            if response.status_code in [200, 201, 204]:
                log.info(f"Webhook envoyé: {alert.get('type')}")
                return True
            else:
                log.error(f"Échec de l'envoi du webhook: {response.status_code} - {response.text}")
                return False
            
        except Exception as e:
            log.error(f"Erreur lors de l'envoi du webhook: {e}")
            return False
    
    def _format_webhook_payload(self, alert, config):
        """
        Formater le payload pour un webhook
        
        Args:
            alert: Alerte à formater
            config: Configuration du webhook
        
        Returns:
            dict: Payload du webhook
        """
        # Par défaut, envoyer l'alerte telle quelle
        payload = alert.copy()
        
        # Ajouter des informations supplémentaires
        payload['netguard'] = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }
        
        return payload
    
    def send_syslog(self, alert):
        """
        Envoyer une alerte via syslog
        
        Args:
            alert: Alerte à envoyer
        
        Returns:
            bool: True si succès, False sinon
        """
        config = self.config.get('syslog', {})
        
        if not config.get('enabled', True):
            return False
        
        try:
            import syslog
            
            # Déterminer la priorité en fonction du niveau
            level = alert.get('level', 'INFO').upper()
            facility = getattr(syslog, config.get('facility', 'LOG_LOCAL0'), syslog.LOG_LOCAL0)
            
            priority_map = {
                'DEBUG': syslog.LOG_DEBUG,
                'INFO': syslog.LOG_INFO,
                'WARNING': syslog.LOG_WARNING,
                'ERROR': syslog.LOG_ERR,
                'CRITICAL': syslog.LOG_CRIT
            }
            priority = priority_map.get(level, syslog.LOG_INFO)
            
            # Formater le message
            message = self._format_syslog_message(alert)
            
            # Envoyer le message
            syslog.syslog(priority | facility, message)
            
            log.debug(f"Message syslog envoyé: {alert.get('type')}")
            return True
            
        except ImportError:
            # syslog non disponible sur Windows
            log.warning("syslog non disponible sur cette plateforme")
            return False
        except Exception as e:
            log.error(f"Erreur lors de l'envoi du message syslog: {e}")
            return False
    
    def _format_syslog_message(self, alert):
        """
        Formater un message syslog
        
        Args:
            alert: Alerte à formater
        
        Returns:
            str: Message syslog
        """
        parts = []
        parts.append(f"NetGuard/{alert.get('type', 'GENERIC')}")
        parts.append(f"[{alert.get('level', 'INFO')}]")
        parts.append(f"{alert.get('message', 'No message')}")
        
        if alert.get('value'):
            parts.append(f"value={alert['value']}")
        
        if alert.get('source'):
            parts.append(f"source={alert['source']}")
        
        return ' '.join(parts)
    
    def send_console(self, alert):
        """
        Afficher une alerte dans la console
        
        Args:
            alert: Alerte à afficher
        
        Returns:
            bool: True si succès, False sinon
        """
        config = self.config.get('console', {})
        
        if not config.get('enabled', True):
            return False
        
        try:
            message = self._format_console_message(alert)
            
            # Utiliser print au lieu de logging pour éviter les conflits
            print(message)
            
            return True
            
        except Exception as e:
            log.error(f"Erreur lors de l'affichage console: {e}")
            return False
    
    def _format_console_message(self, alert):
        """
        Formater un message pour la console
        
        Args:
            alert: Alerte à formater
        
        Returns:
            str: Message formaté
        """
        from . import helpers
        
        level = alert.get('level', 'INFO').upper()
        
        # Déterminer les couleurs
        color_map = {
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red'
        }
        color = color_map.get(level, 'white')
        
        # Formater le message
        timestamp = alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        type = alert.get('type', 'ALERT')
        message = alert.get('message', 'No message')
        
        # Utiliser les couleurs si supporté
        if helpers.USE_COLORS:
            level_str = helpers.colorize_text(level, color=color)
            msg_str = helpers.colorize_text(f"{message}", color=color)
            
            return f"[{timestamp}] {level_str} [{type}] {msg_str}"
        else:
            return f"[{timestamp}] {level} [{type}] {message}"
    
    def get_history(self):
        """
        Obtenir l'historique des alertes
        
        Returns:
            list: Historique des alertes
        """
        return self.history.copy()
    
    def clear_history(self):
        """Effacer l'historique des alertes"""
        self.history = []
    
    def test_notifications(self):
        """
        Tester tous les canaux de notification
        
        Returns:
            dict: Résultats des tests
        """
        results = {
            'email': False,
            'slack': False,
            'webhook': False,
            'syslog': False,
            'console': False
        }
        
        # Créer une alerte de test
        test_alert = {
            'type': 'TEST',
            'message': 'Ceci est un message de test',
            'level': 'INFO',
            'timestamp': datetime.now().isoformat(),
            'source': 'test'
        }
        
        # Tester chaque canal
        if self._should_send('email', test_alert):
            results['email'] = self.send_email(test_alert)
        
        if self._should_send('slack', test_alert):
            results['slack'] = self.send_slack(test_alert)
        
        if self._should_send('webhook', test_alert):
            results['webhook'] = self.send_webhook(test_alert)
        
        if self._should_send('syslog', test_alert):
            results['syslog'] = self.send_syslog(test_alert)
        
        if self._should_send('console', test_alert):
            results['console'] = self.send_console(test_alert)
        
        return results


# Instance globale du notificateur
_global_notifier = None


def get_notifier(config=None):
    """
    Obtenir une instance du notificateur
    
    Args:
        config: Configuration des notifications
    
    Returns:
        Notifier: Instance du notificateur
    """
    global _global_notifier
    
    if _global_notifier is None:
        _global_notifier = Notifier(config)
    
    return _global_notifier


def send_alert(alert, config=None):
    """
    Envoyer une alerte
    
    Args:
        alert: Alerte à envoyer
        config: Configuration des notifications
    """
    notifier = get_notifier(config)
    notifier.send_alert(alert)


def test_notifications(config=None):
    """
    Tester les notifications
    
    Args:
        config: Configuration des notifications
    
    Returns:
        dict: Résultats des tests
    """
    notifier = get_notifier(config)
    return notifier.test_notifications()
