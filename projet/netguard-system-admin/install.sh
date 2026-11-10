#!/bin/bash

# NetGuard - Script d'installation
# Ce script installe les dépendances et configure NetGuard

# Vérifier si on est root (nécessaire pour certaines installations)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Ce script nécessite des privilèges root pour certaines installations."
    echo "   Certaines fonctionnalités peuvent ne pas fonctionner sans root."
    read -p "Voulez-vous continuer? (o/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Oo]$ ]]; then
        exit 1
    fi
fi

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
function message {
    echo -e "${BLUE}[*]${NC} $1"
}

function success {
    echo -e "${GREEN}[✓]${NC} $1"
}

function warning {
    echo -e "${YELLOW}[!]${NC} $1"
}

function error {
    echo -e "${RED}[✗]${NC} $1"
}

# Vérifier le système d'exploitation
OS=$(uname -s)
case "$OS" in
    Linux*)     OS=Linux;;
    Darwin*)    OS=Mac;;
    *)          OS=Unknown;;
esac

message "Système détecté: $OS"

# Créer les répertoires nécessaires
message "Création des répertoires..."
sudo mkdir -p /var/log/netguard
sudo mkdir -p /var/lib/netguard
sudo mkdir -p /etc/netguard
sudo chown -R $USER:$USER /var/log/netguard
sudo chown -R $USER:$USER /var/lib/netguard
success "Répertoires créés"

# Installer les dépendances système
message "Installation des dépendances système..."

if [ "$OS" = "Linux" ]; then
    # Détecter la distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    else
        DISTRO="unknown"
    fi
    
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        sudo apt update
        sudo apt install -y python3 python3-pip python3-venv git curl wget nmap net-tools iftop htop iotop tcpdump sysstat lsof strace telnet mailutils postfix
        success "Dépendances Ubuntu/Debian installées"
    elif [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "fedora" ]; then
        sudo yum install -y python3 python3-pip python3-devel git curl wget nmap net-tools iftop htop iotop tcpdump sysstat lsof strace telnet mailx postfix
        success "Dépendances CentOS/RHEL/Fedora installées"
    elif [ "$DISTRO" = "arch" ] || [ "$DISTRO" = "manjaro" ]; then
        sudo pacman -Syu --noconfirm python python-pip git curl wget nmap net-tools iftop htop iotop tcpdump sysstat lsof strace mailx postfix
        success "Dépendances Arch/Manjaro installées"
    else
        warning "Distribution Linux non reconnue. Installation des dépendances de base..."
        sudo apt update && sudo apt install -y python3 python3-pip git curl wget nmap
        success "Dépendances de base installées"
    fi
elif [ "$OS" = "Mac" ]; then
    # Vérifier si Homebrew est installé
    if ! command -v brew &> /dev/null; then
        message "Installation de Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        success "Homebrew installé"
    fi
    
    brew install python nmap net-tools iftop htop iotop tcpdump sysstat lsof strace
    success "Dépendances macOS installées"
else
    warning "Système d'exploitation non supporté: $OS"
fi

# Installer les dépendances Python
message "Installation des dépendances Python..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
success "Dépendances Python installées"

# Copier les fichiers de configuration
message "Copie des fichiers de configuration..."
cp config/config.example.yaml config/config.yaml
cp config/hosts.example.yaml config/hosts.yaml 2>/dev/null || true
success "Fichiers de configuration copiés"

# Configurer les services systemd (Linux seulement)
if [ "$OS" = "Linux" ]; then
    message "Configuration des services systemd..."
    
    # Copier le service de surveillance
    sudo cp services/netguard-monitor.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable netguard-monitor
    
    # Copier le service de scan réseau
    sudo cp services/netguard-scan.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable netguard-scan
    
    success "Services systemd configurés"
    
    # Configurer logrotate
    sudo cp services/netguard-logrotate /etc/logrotate.d/netguard
    success "Configuration logrotate terminée"
fi

# Configurer les permissions
message "Configuration des permissions..."
sudo chmod +x main.py
sudo chmod +x scripts/system/*.py
sudo chmod +x scripts/network/*.py
sudo chmod +x scripts/security/*.py
sudo chmod +x scripts/users/*.py
sudo chmod +x scripts/storage/*.py
sudo chmod +x scripts/logs/*.sh
success "Permissions configurées"

# Afficher les informations de fin
message ""
echo ""
echo "========================================="
echo "       Installation terminée!"
echo "========================================="
echo ""
echo "NetGuard est maintenant installé sur votre système."
echo ""
echo "Pour démarrer:"
echo "  python3 main.py"
echo ""
echo "Pour exécuter le scan réseau:"
echo "  python3 scripts/network/network_scan.py --subnet 192.168.1.0/24"
echo ""
echo "Pour surveiller le système:"
echo "  python3 scripts/system/monitor_system.py --realtime"
echo ""
echo "Fichiers de configuration:"
echo "  config/config.yaml"
echo "  config/hosts.yaml"
echo ""
echo "Logs:"
echo "  /var/log/netguard/"
echo ""
echo "Données:"
echo "  /var/lib/netguard/"
echo ""
echo "========================================="
