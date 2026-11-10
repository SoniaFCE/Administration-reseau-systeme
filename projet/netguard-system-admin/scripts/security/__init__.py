#!/usr/bin/env python3
"""
NetGuard - Module Sécurité

Ce module contient les outils de gestion de la sécurité système.

Sous-modules:
- firewall_manager: Gestion du pare-feu
- vulnerability_scan: Scan de vulnérabilités
- audit: Audit de sécurité

Auteur: NetGuard Team
Licence: MIT
"""

__version__ = "1.0.0"
__all__ = ['FirewallManager', 'VulnerabilityScanner', 'SecurityAudit']

# Import des sous-modules
try:
    from .firewall_manager import FirewallManager
    from .vulnerability_scan import VulnerabilityScanner
    from .audit import SecurityAudit
except ImportError as e:
    print(f"Avertissement: Impossible de charger les sous-modules de sécurité: {e}")


def get_security_tools():
    """Obtenir la liste des outils de sécurité disponibles"""
    return {
        'firewall_manager': 'Gestion du pare-feu',
        'vulnerability_scan': 'Scan de vulnérabilités',
        'audit': 'Audit de sécurité'
    }
