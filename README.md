# NetGuard - System & Network Administration Toolkit

**NetGuard** est un ensemble d'outils open-source pour l'administration système et réseau, conçu pour automatiser les tâches courantes, surveiller les infrastructures et simplifier la gestion des serveurs. Ce projet combine des scripts Python, Bash et PowerShell pour offrir une solution complète aux administrateurs système.

---

## 📋 Table des matières

- [📌 Fonctionnalités](#-fonctionnalités)
- [🛠 Prérequis](#-prérequis)
- [🚀 Installation](#-installation)
- [🎯 Utilisation](#-utilisation)
- [📁 Structure du projet](#-structure-du-projet)
- [🔧 Configuration](#-configuration)
- [📊 Exemples d'utilisation](#-exemples-dutilisation)
- [🔒 Sécurité](#-sécurité)
- [📜 Licence](#-licence)
- [🤝 Contribution](#-contribution)

---

## 📌 Fonctionnalités

### 🖥️ Administration Système
- **Surveillance des ressources** : CPU, RAM, disque, température
- **Gestion des logs** : Rotation, compression, analyse des journaux
- **Gestion des utilisateurs** : Création, suppression, modification des comptes
- **Sauvegardes automatisées** : Backup incrémental et complet
- **Gestion des processus** : Surveillance et contrôle des services
- **Analyse des performances** : Génération de rapports détaillés

### 🌐 Administration Réseau
- **Scan de réseau** : Découverte d'hôtes et de services
- **Analyse de trafic** : Surveillance du bandwidth et des connexions
- **Gestion des interfaces** : Configuration IP, VLAN, bonding
- **Diagnostic réseau** : Ping, traceroute, tests de connectivité
- **Monitoring de services** : Vérification HTTP, DNS, SMTP, etc.
- **Configuration firewall** : Règles iptables/nftables
- **Analyse de sécurité** : Scan de vulnérabilités basique

### ⚡ Automatisation
- **Déploiement de configurations** : Push de configurations sur plusieurs serveurs
- **Mises à jour automatisées** : Gestion des patches de sécurité
- **Orchestration** : Exécution de commandes à distance
- **Alertes intelligentes** : Notifications par email/Slack/Webhook

---

## 🛠 Prérequis

### Système d'exploitation supportés
- ✅ Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+)
- ✅ Windows Server 2019+
- ✅ macOS (pour les outils de développement)

### Dépendances logicielles

#### Pour tous les systèmes
```bash
# Python 3.8 ou supérieur
python3 --version

# pip (gestionnaire de packages Python)
pip3 --version
```

#### Pour Linux
```bash
# Outils système de base
sudo apt update && sudo apt install -y \
    curl wget git net-tools iproute2 \
    iftop htop iotop nmon \
    tcpdump nmap netstat-nat \
    sysstat lsof strace telnet \
    mailutils postfix  # Pour les alertes email

# Pour le monitoring avancé
sudo apt install -y \
    prometheus-node-exporter \
    grafana  # Optionnel pour les dashboards
```

#### Pour Windows
```powershell
# Installer Chocolatey (gestionnaire de packages)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Installer les dépendances
choco install -y python git curl wget nmap sysinternals
```

---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
cd /path/vers/votre/dossier
git clone https://github.com/votre-utilisateur/netguard-system-admin.git
cd netguard-system-admin
```

### 2. Installer les dépendances Python

```bash
# Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# ou sur Windows: venv\Scripts\activate

# Installer les packages Python requis
pip install -r requirements.txt
```

### 3. Configuration initiale

```bash
# Copier le fichier de configuration exemple
cp config/config.example.yaml config/config.yaml

# Modifier le fichier de configuration
nano config/config.yaml  # ou utilisez votre éditeur préféré
```

### 4. Installer les services (optionnel)

Pour une surveillance continue, vous pouvez installer les scripts comme services systemd :

```bash
# Sur Linux
sudo cp services/netguard-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable netguard-monitor
sudo systemctl start netguard-monitor

# Sur Windows (PowerShell en tant qu'administrateur)
New-Service -Name "NetGuardMonitor" -BinaryPathName "C:\chemin\vers\python.exe C:\chemin\vers\netguard\scripts\monitor_system.py" -DisplayName "NetGuard System Monitor" -StartupType Automatic
Start-Service -Name "NetGuardMonitor"
```

---

## 🎯 Utilisation

### Lancer le menu principal

```bash
# Sur Linux/macOS
python3 main.py

# Sur Windows
python main.py
```

### Commandes de base

```bash
# Afficher l'aide
python3 main.py --help

# Lancer un scan réseau
python3 scripts/network_scan.py --subnet 192.168.1.0/24

# Surveiller les ressources système
python3 scripts/monitor_system.py --duration 60 --interval 5

# Gérer les logs
bash scripts/manage_logs.sh --rotate --days 30

# Vérifier la configuration réseau
python3 scripts/network_config.py --check
```

### Utilisation des modules individuellement

#### 1. Surveillance Système

```bash
# Surveiller en temps réel
python3 scripts/monitor_system.py --realtime

# Générer un rapport
python3 scripts/monitor_system.py --report --output report.html

# Vérifier un service spécifique
python3 scripts/check_service.py --service nginx --alert-threshold 3
```

#### 2. Administration Réseau

```bash
# Scanner le réseau local
python3 scripts/network_scan.py --quick

# Analyser le trafic réseau
sudo python3 scripts/traffic_analyzer.py --interface eth0 --duration 300

# Configurer une interface réseau
sudo bash scripts/network_config.sh --set-ip eth0 192.168.1.100 255.255.255.0 192.168.1.1

# Tester la connectivité
python3 scripts/network_diagnostic.py --ping google.com
python3 scripts/network_diagnostic.py --traceroute google.com
python3 scripts/network_diagnostic.py --check-ports 80,443,22 google.com
```

#### 3. Gestion des Utilisateurs

```bash
# Lister tous les utilisateurs
python3 scripts/user_management.py --list

# Créer un nouvel utilisateur
sudo python3 scripts/user_management.py --create --username jdoe --password SecureP@ss --groups sudo,developers

# Supprimer un utilisateur
sudo python3 scripts/user_management.py --delete --username jdoe --backup
```

#### 4. Gestion des Sauvegardes

```bash
# Sauvegarde complète
python3 scripts/backup_manager.py --full --source /var/www --destination /backup/www

# Sauvegarde incrémentale
python3 scripts/backup_manager.py --incremental --source /home --destination /backup/home

# Restaurer une sauvegarde
python3 scripts/backup_manager.py --restore --source /backup/www/2024-01-15.tar.gz --destination /var/www
```

---

## 📁 Structure du projet

```
netguard-system-admin/
├── README.md                    # Documentation principale
├── LICENSE                      # Licence du projet
├── requirements.txt             # Dépendances Python
├── main.py                      # Point d'entrée principal
├── config/
│   ├── config.yaml              # Configuration principale
│   ├── hosts.yaml               # Liste des hôtes à surveiller
│   ├── alerts.yaml              # Configuration des alertes
│   └── network_interfaces.yaml  # Configuration réseau
├── scripts/
│   ├── __init__.py
│   ├── system/
│   │   ├── monitor_system.py    # Surveillance des ressources
│   │   ├── check_service.py     # Vérification des services
│   │   ├── process_manager.py   # Gestion des processus
│   │   └── performance.py       # Analyse des performances
│   ├── network/
│   │   ├── network_scan.py      # Scan du réseau
│   │   ├── network_config.py    # Configuration réseau
│   │   ├── traffic_analyzer.py  # Analyse du trafic
│   │   └── network_diagnostic.py # Diagnostic réseau
│   ├── security/
│   │   ├── firewall_manager.py  # Gestion du firewall
│   │   ├── vulnerability_scan.py # Scan de vulnérabilités
│   │   └── audit.py            # Audit de sécurité
│   ├── users/
│   │   └── user_management.py   # Gestion des utilisateurs
│   ├── storage/
│   │   ├── backup_manager.py    # Gestion des sauvegardes
│   │   └── disk_analyzer.py     # Analyse des disques
│   └── logs/
│       ├── manage_logs.sh       # Gestion des logs (Bash)
│       └── log_analyzer.py      # Analyse des logs
├── services/
│   └── netguard-monitor.service  # Service systemd
├── docs/
│   ├── architecture.md          # Architecture du projet
│   ├── usage.md                 # Guide d'utilisation
│   └── api.md                   # Documentation API
├── tests/
│   └── test_*.py                # Tests unitaires
└── utils/
    ├── helpers.py               # Fonctions utilitaires
    ├── logger.py                # Gestion des logs
    └── notifier.py              # Système de notifications
```

---

## 🔧 Configuration

### Fichier `config/config.yaml`

```yaml
# Configuration générale
project_name: "NetGuard"
version: "1.0.0"
log_level: "INFO"
log_file: "/var/log/netguard/netguard.log"

# Surveillance système
system_monitor:
  check_interval: 60  # en secondes
  cpu_threshold: 90    # % d'utilisation
  memory_threshold: 85 # % d'utilisation
  disk_threshold: 90   # % d'utilisation
  temperature_threshold: 75 # en °C

# Configuration réseau
network:
  primary_interface: "eth0"
  subnet: "192.168.1.0/24"
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  scan_ports:
    - 22
    - 80
    - 443
    - 3306
    - 8080

# Alertes
alerts:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "votre@email.com"
    password: "votre-mot-de-passe"
    sender: "netguard@domaine.com"
    recipients:
      - "admin@domaine.com"
  slack:
    enabled: false
    webhook_url: ""
  webhook:
    enabled: false
    url: ""

# Sauvegardes
backup:
  retention_days: 30
  compression_level: 6
  encryption_key: ""  # Optionnel
  storage:
    local:
      enabled: true
      path: "/backup"
    remote:
      enabled: false
      type: "sftp"  # sftp, s3, azure, google
      host: ""
      username: ""
      password: ""
      path: "/backup"

# Sécurité
security:
  ssh_port: 22
  firewall_enabled: true
  fail2ban_enabled: true
  auto_update: true
```

### Fichier `config/hosts.yaml`

```yaml
servers:
  - name: "web-server-01"
    ip: "192.168.1.10"
    ssh_port: 22
    username: "admin"
    password: "secure-password"
    ssh_key: "/home/user/.ssh/id_rsa"
    type: "web"
    services:
      - "nginx"
      - "mysql"
      - "php-fpm"
    
  - name: "db-server-01"
    ip: "192.168.1.11"
    ssh_port: 22
    username: "admin"
    type: "database"
    services:
      - "postgresql"
      - "redis"

  - name: "monitor-server"
    ip: "192.168.1.12"
    username: "admin"
    type: "monitoring"
    services:
      - "prometheus"
      - "grafana"
      - "node_exporter"
```

---

## 📊 Exemples d'utilisation

### Exemple 1 : Surveillance complète du système

```bash
# Démarrer la surveillance continue
python3 scripts/monitor_system.py \
    --check-cpu \
    --check-memory \
    --check-disk \
    --check-temp \
    --check-services nginx,mysql,redis \
    --alert-threshold 85 \
    --duration 3600 \
    --interval 30
```

**Sortie attendue :**
```
[2024-01-15 10:00:00] INFO - Surveillance démarrée
[2024-01-15 10:00:30] INFO - CPU: 45.2% | RAM: 62.8% | Disk: / 78.5% | Temp: 42°C
[2024-01-15 10:01:00] INFO - Services: nginx(✓), mysql(✓), redis(✓)
[2024-01-15 10:05:00] WARNING - Disk / at 85.1% (seuil: 85%)
[2024-01-15 10:05:00] INFO - Alerte envoyée: Disk / à 85.1%
```

### Exemple 2 : Scan de réseau complet

```bash
python3 scripts/network_scan.py \
    --subnet 192.168.1.0/24 \
    --ports 1-1000 \
    --scan-type full \
    --output scan_results.json \
    --save-to-db
```

**Sortie JSON partielle :**
```json
{
  "scan_start": "2024-01-15T10:00:00Z",
  "scan_end": "2024-01-15T10:15:23Z",
  "subnet": "192.168.1.0/24",
  "hosts_found": 42,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router",
      "mac": "00:11:22:33:44:55",
      "os": "Linux",
      "open_ports": [22, 80, 443],
      "services": {
        "22": "ssh",
        "80": "http",
        "443": "https"
      }
    },
    {
      "ip": "192.168.1.10",
      "hostname": "web-server-01",
      "mac": "aa:bb:cc:dd:ee:ff",
      "os": "Ubuntu 22.04",
      "open_ports": [22, 80, 443, 3306],
      "services": {
        "22": "ssh",
        "80": "nginx",
        "443": "nginx",
        "3306": "mysql"
      }
    }
  ],
  "statistics": {
    "total_ips": 256,
    "active_hosts": 42,
    "total_open_ports": 156,
    "scan_duration_seconds": 923
  }
}
```

### Exemple 3 : Gestion des sauvegardes

```bash
# Sauvegarde quotidienne
python3 scripts/backup_manager.py \
    --daily \
    --source /var/www/html \
    --destination /backup/www \
    --exclude "*.log,*.tmp,*.cache" \
    --compress \
    --encrypt

# Restauration depuis une sauvegarde
python3 scripts/backup_manager.py \
    --restore \
    --source /backup/www/2024-01-14_daily.tar.gz.gpg \
    --destination /var/www/html \
    --decrypt
```

### Exemple 4 : Analyse de sécurité

```bash
# Scan de vulnérabilités
sudo python3 scripts/security/vulnerability_scan.py \
    --target 192.168.1.10 \
    --scan-type deep \
    --check-ports 1-65535 \
    --check-cves \
    --output vulnerability_report.html

# Audit de configuration SSH
python3 scripts/security/audit.py \
    --check-ssh \
    --check-firewall \
    --check-users \
    --check-passwords
```

---

## 🔒 Sécurité

### Bonnes pratiques

1. **Accès sécurisé**
   - Utilisez toujours SSH avec authentification par clé
   - Désactivez l'authentification par mot de passe
   - Changez le port SSH par défaut (22 → 2222 par exemple)

2. **Gestion des mots de passe**
   - Utilisez des mots de passe forts (12+ caractères, mélange de types)
   - Activez le chiffrement des sauvegardes
   - Ne stockez jamais les mots de passe en clair

3. **Mises à jour**
   - Activez les mises à jour automatiques
   - Vérifiez régulièrement les vulnérabilités
   - Maintenez vos outils à jour

4. **Firewall**
   - Activez le firewall par défaut
   - Fermez tous les ports inutilisés
   - Utilisez des règles restrictives

### Configuration SSH sécurisée

```yaml
# /etc/ssh/sshd_config
Port 2222
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
```

### Configuration Firewall (iptables)

```bash
# Politique par défaut : tout bloquer
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Autoriser le trafic local
sudo iptables -A INPUT -i lo -j ACCEPT

# Autoriser les connexions établies
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Autoriser SSH (port personnalisé)
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# Autoriser HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Autoriser ICMP (ping)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Journaliser les connexions refusées
sudo iptables -A INPUT -j LOG --log-prefix "FIREWALL: " --log-level 4

# Sauvegarder les règles
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## 📜 Licence

Ce projet est sous licence **MIT**. Vous êtes libre d'utiliser, modifier, distribuer ce code selon les termes de la licence.

```
MIT License

Copyright (c) 2024 NetGuard

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. **Forker le dépôt** sur GitHub
2. **Créer une branche** pour votre fonctionnalité (`git checkout -b feature/nouvelle-fonctionnalité`)
3. **Commiter vos modifications** (`git commit -m 'Ajout de la nouvelle fonctionnalité'`)
4. **Pousser vers la branche** (`git push origin feature/nouvelle-fonctionnalité`)
5. **Ouvrir une Pull Request**

### Directives de contribution

- Suivez le style de code existant
- Ajoutez des tests pour les nouvelles fonctionnalités
- Mettez à jour la documentation
- Utilisez des commits atomiques et descriptifs
- Respectez la licence MIT

### Rapport de bugs

Pour signaler un bug :

1. Vérifiez que le bug n'a pas déjà été signalé
2. Créez une issue avec :
   - Une description claire du problème
   - Les étapes pour reproduire
   - Le comportement attendu
   - Le comportement actuel
   - Votre environnement (OS, version de Python, etc.)
   - Les logs pertinents

---

## 📞 Support

Pour toute question ou problème :

- **Documentation** : Consultez les fichiers dans `/docs/`
- **Issues** : Ouvrez une issue sur GitHub
- **Email** : support@netguard-project.org
- **Discord** : Rejoignez notre serveur Discord (lien dans le fichier CONTRIBUTING.md)

---

## 🚀 Roadmap

### Version 1.1.0 (Prévue : Q2 2024)
- [ ] Intégration avec Prometheus/Grafana
- [ ] Dashboard web en temps réel
- [ ] Support de Docker/Kubernetes
- [ ] Module de gestion des certificats SSL
- [ ] Intégration avec Ansible

### Version 1.2.0 (Prévue : Q4 2024)
- [ ] Support du cloud (AWS, Azure, GCP)
- [ ] Module de gestion des conteneurs
- [ ] Système de tickets intégré
- [ ] API RESTful
- [ ] Interface CLI améliorée

---

## 🎓 Ressources d'apprentissage

### Administration Système
- [The Linux Command Line](https://linuxcommand.org/tlcl.php) - William Shotts
- [Linux System Administration](https://www.oreilly.com/library/view/linux-system-administration/9781492075335/) - Tom Adelstein
- [UNIX and Linux System Administration Handbook](https://www.admin.com/) - Evi Nemeth

### Réseau
- [Computer Networking: A Top-Down Approach](https://gaia.cs.umass.edu/kurose_ross/) - Kurose & Ross
- [TCP/IP Illustrated](https://www.amazon.com/TCP-Illustrated-Vol-Addison-Wesley-Professional/dp/0201633469) - W. Richard Stevens

### Sécurité
- [The Art of Invisibility](https://www.amazon.com/Art-Invisibility-Worlds-Teaches-Disappear/dp/0316380504) - Kevin Mitnick
- [Hacking Exposed](https://www.mcgraw-hill.com/education/products/0072260825) - Stuart McClure

### Outils recommandés
- **Surveillance** : Nagios, Zabbix, Prometheus, Grafana
- **Automatisation** : Ansible, Puppet, Chef, SaltStack
- **Sécurité** : Fail2Ban, ClamAV, Snort, Suricata
- **Réseau** : Wireshark, tcpdump, nmap, netstat

---

*NetGuard - Votre partenaire pour l'administration système et réseau*
