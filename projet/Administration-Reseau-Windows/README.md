# Administration Réseau Windows

Projet complet d'administration réseau sous Windows avec des scripts PowerShell pour automatiser les tâches courantes de gestion, surveillance et dépannage.

## 📋 Table des matières

- [Description](#-description)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Structure du projet](#-structure-du-projet)
- [Scripts disponibles](#-scripts-disponibles)
- [Utilisation](#-utilisation)
- [Exemples](#-exemples)
- [Configuration](#-configuration)
- [Sécurité](#-sécurité)
- [Contribution](#-contribution)
- [Licence](#-licence)

---

## 📝 Description

Ce projet fournit une collection de scripts PowerShell pour l'administration réseau sous Windows. Il permet d'automatiser les tâches suivantes :

- Analyse et diagnostic réseau
- Gestion des adresses IP et DNS
- Surveillance des services réseau
- Gestion des utilisateurs et groupes
- Configuration du pare-feu Windows
- Test de connectivité et de performance
- Génération de rapports système

---

## 📦 Prérequis

- **Système d'exploitation** : Windows 10/11 ou Windows Server 2016/2019/2022
- **PowerShell** : Version 5.1 ou supérieure (PowerShell 7 recommandé)
- **Droits d'administration** : Certains scripts nécessitent des droits administrateur

Vérifiez votre version de PowerShell :
```powershell
$PSVersionTable
```

---

## ⚙️ Installation

### 1. Cloner ou télécharger le projet

```powershell
# Si vous utilisez Git
cd C:\Users\ayaso\Desktop\projet
git clone https://github.com/votre-utilisateur/Administration-Reseau-Windows.git
cd Administration-Reseau-Windows
```

Ou simplement copiez le dossier dans votre répertoire de travail.

### 2. Autoriser l'exécution des scripts PowerShell

```powershell
# Vérifier la politique d'exécution actuelle
Get-ExecutionPolicy

# Autoriser l'exécution des scripts locaux (à exécuter en tant qu'administrateur)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

### 3. Importer les modules nécessaires

```powershell
# Installer les modules nécessaires (PowerShell 5.1+)
Install-Module -Name Posh-Git, PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
```

---

## 🗂️ Structure du projet

```
Administration-Reseau-Windows/
├── README.md                    # Documentation principale
├── LICENCE                      # Licence du projet
├── scripts/                     # Scripts PowerShell
│   ├── analyse-reseau/          # Scripts d'analyse réseau
│   │   ├── Get-NetworkInfo.ps1     # Informations réseau complètes
│   │   ├── Test-Connectivity.ps1   # Tests de connectivité
│   │   └── Get-OpenPorts.ps1       # Ports ouverts
│   ├── gestion-utilisateurs/    # Gestion des utilisateurs
│   │   ├── Get-UserInfo.ps1         # Informations utilisateurs
│   │   ├── New-LocalUser.ps1       # Créer un utilisateur local
│   │   └── Manage-Groups.ps1       # Gestion des groupes
│   ├── services/                # Gestion des services
│   │   ├── Get-ServiceStatus.ps1   # Statut des services
│   │   ├── Start-Service.ps1       # Démarrer un service
│   │   └── Monitor-Services.ps1    # Surveillance des services
│   ├── configuration/           # Configuration système
│   │   ├── Set-NetworkConfig.ps1   # Configuration réseau
│   │   ├── Configure-Firewall.ps1  # Configuration du pare-feu
│   │   └── Set-DNS.ps1             # Configuration DNS
│   └── rapports/                 # Génération de rapports
│       ├── Generate-NetworkReport.ps1
│       └── Export-SystemInfo.ps1
├── config/                      # Fichiers de configuration
│   ├── settings.json             # Paramètres par défaut
│   └── network-config.json       # Configuration réseau
├── docs/                        # Documentation
│   ├── GUIDE-UTILISATION.md      # Guide d'utilisation détaillé
│   └── TROUBLESHOOTING.md        # Résolution des problèmes
└── logs/                        # Journaux d'exécution
```

---

## 💻 Scripts disponibles

### 🌐 Analyse Réseau

| Script | Description | Commande |
|--------|-------------|----------|
| `Get-NetworkInfo.ps1` | Affiche toutes les informations réseau (IP, DNS, passerelle, etc.) | `.\(Get-NetworkInfo.ps1` |
| `Test-Connectivity.ps1` | Teste la connectivité vers des hôtes distants | `.\(Test-Connectivity.ps1 -Host google.com` |
| `Get-OpenPorts.ps1` | Liste les ports ouverts sur la machine | `.\(Get-OpenPorts.ps1` |
| `Get-NetworkInterfaces.ps1` | Affiche les interfaces réseau disponibles | `.\(Get-NetworkInterfaces.ps1` |

### 👥 Gestion des Utilisateurs

| Script | Description | Commande |
|--------|-------------|----------|
| `Get-UserInfo.ps1` | Affiche les informations sur les utilisateurs locaux | `.\(Get-UserInfo.ps1` |
| `New-LocalUser.ps1` | Crée un nouvel utilisateur local | `.\(New-LocalUser.ps1 -Username user1 -Password P@ssw0rd` |
| `Manage-Groups.ps1` | Gère les groupes locaux | `.\(Manage-Groups.ps1 -Action Add -Group Admin -User user1` |
| `Get-LastLogon.ps1` | Affiche la dernière date de connexion | `.\(Get-LastLogon.ps1` |

### ⚙️ Services

| Script | Description | Commande |
|--------|-------------|----------|
| `Get-ServiceStatus.ps1` | Affiche le statut de tous les services | `.\(Get-ServiceStatus.ps1` |
| `Start-Service.ps1` | Démarre un service spécifique | `.\(Start-Service.ps1 -Name Spoler` |
| `Stop-Service.ps1` | Arrête un service spécifique | `.\(Stop-Service.ps1 -Name Spoler` |
| `Monitor-Services.ps1` | Surveille les services critiques | `.\(Monitor-Services.ps1 -Services DHCP,DNS` |

### 🔧 Configuration

| Script | Description | Commande |
|--------|-------------|----------|
| `Set-NetworkConfig.ps1` | Configure une interface réseau (IP, masque, passerelle) | `.\(Set-NetworkConfig.ps1 -IP 192.168.1.100 -Mask 255.255.255.0 -Gateway 192.168.1.1` |
| `Configure-Firewall.ps1` | Configure les règles du pare-feu | `.\(Configure-Firewall.ps1 -Action Allow -Port 80 -Direction Inbound` |
| `Set-DNS.ps1` | Configure les serveurs DNS | `.\(Set-DNS.ps1 -Servers 8.8.8.8,8.8.4.4` |

### 📊 Rapports

| Script | Description | Commande |
|--------|-------------|----------|
| `Generate-NetworkReport.ps1` | Génère un rapport complet du réseau | `.\(Generate-NetworkReport.ps1 -Output report.txt` |
| `Export-SystemInfo.ps1` | Exporte les informations système | `.\(Export-SystemInfo.ps1 -Output system-info.csv` |

---

## 🎯 Utilisation

### Exécuter un script

```powershell
# Naviguer vers le dossier des scripts
cd C:\Users\ayaso\Desktop\projet\Administration-Reseau-Windows\scripts

# Exécuter un script
.\analyse-reseau\Get-NetworkInfo.ps1

# Avec des paramètres
.\analyse-reseau\Test-Connectivity.ps1 -Host google.com -Count 5
```

### Exécuter tous les diagnostics réseau

```powershell
# Créer un script de diagnostic complet
.\diagnostic-complet.ps1
```

Ce script exécute :
- Analyse des interfaces réseau
- Test de connectivité Internet
- Vérification DNS
- Liste des ports ouverts
- Statut des services critiques
- Informations système

---

## 📝 Exemples

### Exemple 1 : Obtenir les informations réseau

```powershell
.\(Get-NetworkInfo.ps1
```

Résultat :
```
Nom de l'ordinateur : MON-PC
Adresses IP :
  - Ethernet : 192.168.1.100
  - Wi-Fi : 192.168.1.101
Passerelle par défaut : 192.168.1.1
Serveurs DNS : 8.8.8.8, 8.8.4.4
```

### Exemple 2 : Créer un nouvel utilisateur

```powershell
.\gestion-utilisateurs\New-LocalUser.ps1 -Username "jdoe" -Password "P@ssw0rd123" -FullName "John Doe" -Description "Utilisateur réseau"
```

### Exemple 3 : Configurer une adresse IP statique

```powershell
.\configuration\Set-NetworkConfig.ps1 -InterfaceName "Ethernet" -IPAddress "192.168.1.200" -SubnetMask "255.255.255.0" -DefaultGateway "192.168.1.1" -DNSServers "8.8.8.8,8.8.4.4"
```

### Exemple 4 : Tester la connectivité

```powershell
.\analyse-reseau\Test-Connectivity.ps1 -Hosts "google.com","facebook.com","microsoft.com" -Count 3
```

### Exemple 5 : Générer un rapport réseau complet

```powershell
.\rapports\Generate-NetworkReport.ps1 -OutputPath "C:\temp\rapport-reseau.txt" -IncludeAll
```

---

## ⚙️ Configuration

### Fichier de configuration principal

Le fichier `config/settings.json` contient les paramètres par défaut :

```json
{
    "Network": {
        "DefaultInterface": "Ethernet",
        "PrimaryDNS": "8.8.8.8",
        "SecondaryDNS": "8.8.4.4",
        "DefaultGateway": "192.168.1.1"
    },
    "Logging": {
        "Enabled": true,
        "Path": "logs",
        "Level": "Info"
    },
    "Services": {
        "CriticalServices": ["DHCP", "DNS", "Spoler", "WinRM"],
        "MonitorInterval": 60
    }
}
```

### Personnalisation

1. Modifiez le fichier `config/settings.json` selon vos besoins
2. Les scripts lisent automatiquement ce fichier de configuration

---

## 🔒 Sécurité

### Bonnes pratiques

- **Exécution en tant qu'administrateur** : Certains scripts nécessitent des droits élevés
- **Sauvegarde** : Faites des sauvegardes avant d'exécuter des scripts de modification
- **Validation** : Vérifiez toujours les scripts avant exécution
- **Mots de passe** : Ne stockez pas les mots de passe en clair

### Sécuriser les scripts

```powershell
# Signer un script avec un certificat
$cert = Get-PfxCertificate -FilePath "C:\path\to\cert.pfx"
Set-AuthenticodeSignature -FilePath "script.ps1" -Certificate $cert
```

### Limiter les permissions

```powershell
# Exécuter avec des droits limités
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File script.ps1" -Verb RunAs
```

---

## 📚 Documentation supplémentaire

- **Guide d'utilisation détaillé** : `docs/GUIDE-UTILISATION.md`
- **Résolution des problèmes** : `docs/TROUBLESHOOTING.md`
- **API PowerShell** : [Microsoft Docs](https://docs.microsoft.com/fr-fr/powershell/)

---

## 🤝 Contribution

1. Forker le projet
2. Créer une branche de fonctionnalité (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Commiter vos changements (`git commit -m 'Ajout d'une nouvelle fonctionnalité'`)
4. Pousser vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Ouvrir une Pull Request

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENCE](LICENCE) pour plus de détails.

---

## 📞 Support

Pour toute question ou problème, ouvrez une issue ou contactez l'équipe de support.

---

**Créé avec ❤️ pour les administrateurs réseau Windows**
