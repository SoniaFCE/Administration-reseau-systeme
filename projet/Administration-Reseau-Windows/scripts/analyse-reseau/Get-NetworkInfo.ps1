<#
.SYNOPSIS
    Affiche les informations réseau complètes de la machine.

.DESCRIPTION
    Ce script récupère et affiche toutes les informations réseau disponibles :
    adresses IP, interfaces réseau, configuration DNS, passerelle par défaut, etc.

.PARAMETER ExportToFile
    Si spécifié, exporte les résultats dans un fichier.

.PARAMETER OutputFormat
    Format de sortie (Table, List, CSV, JSON). Par défaut : Table.

.EXAMPLE
    .\Get-NetworkInfo.ps1
    Affiche les informations réseau à l'écran.

.EXAMPLE
    .\Get-NetworkInfo.ps1 -ExportToFile "C:\temp\network-info.txt"
    Exporte les informations dans un fichier texte.

.EXAMPLE
    .\Get-NetworkInfo.ps1 -OutputFormat JSON
    Affiche les résultats au format JSON.

.NOTES
    Nécessite les droits administrateur pour certaines informations.
    Version : 1.0
    Auteur : Administration Réseau Windows
#>

param(
    [string]$ExportToFile,
    [ValidateSet("Table", "List", "CSV", "JSON")]
    [string]$OutputFormat = "Table"
)

# Définir le niveau de journalisation
$ErrorActionPreference = "Stop"

# Fonction pour écrire dans les logs
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $logPath = "..\..\logs"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Écrire dans la console
    switch ($Level) {
        "Error" { Write-Host $logEntry -ForegroundColor Red }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Écrire dans le fichier de log
    $logFile = Join-Path $logPath "network-info_$(Get-Date -Format 'yyyy-MM-dd').log"
    Add-Content -Path $logFile -Value $logEntry
}

try {
    Write-Log "Début de l'analyse réseau"
    
    # Obtenir le nom de la machine
    $computerInfo = @{
        "Nom de l'ordinateur" = $env:COMPUTERNAME
        "Nom du domaine" = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { "Non dans un domaine" }
        "Nom de l'utilisateur" = $env:USERNAME
        "Système d'exploitation" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        "Version OS" = (Get-WmiObject -Class Win32_OperatingSystem).Version
        "Architecture" = (Get-WmiObject -Class Win32_Processor).AddressWidth + " bits"
    }
    
    # Obtenir les informations des interfaces réseau
    $networkInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $interface = $_
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $interface.InterfaceIndex -ErrorAction SilentlyContinue
        
        [PSCustomObject]@{
            "Nom de l'interface" = $interface.Name
            "Description" = $interface.InterfaceDescription
            "MAC Address" = $interface.MacAddress
            "Statut" = $interface.Status
            "Vitesse (Mbps)" = $interface.LinkSpeed
            "Index" = $interface.InterfaceIndex
        } | Add-Member -NotePropertyName "Adresses IP" -NotePropertyValue (
            if ($ipConfig) { 
                $ipConfig.IPv4Address.IPAddress -join ", "
            } else { "N/A" }
        ) -PassThru | Add-Member -NotePropertyName "Adresse IPv6" -NotePropertyValue (
            if ($ipConfig) { 
                $ipConfig.IPv6Address.IPAddress -join ", "
            } else { "N/A" }
        ) -PassThru | Add-Member -NotePropertyName "Passerelle par défaut" -NotePropertyValue (
            if ($ipConfig) { 
                $ipConfig.DefaultGateway -join ", "
            } else { "N/A" }
        ) -PassThru | Add-Member -NotePropertyName "Serveurs DNS" -NotePropertyValue (
            if ($ipConfig) { 
                $ipConfig.DNSServer.IPAddress -join ", "
            } else { "N/A" }
        ) -PassThru
    }
    
    # Obtenir la configuration DNS globale
    $dnsConfig = Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -eq 2 } | Select-Object -First 1
    
    # Obtenir la configuration TCP/IP complète
    $tcpipInfo = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
        Sort-Object LocalPort
    
    # Obtenir les informations de routage
    $routingInfo = Get-NetRoute | Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" } | 
        Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceIndex | 
        Sort-Object RouteMetric
    
    # Créer l'objet de sortie
    $output = [PSCustomObject]@{
        ComputerInfo = $computerInfo
        NetworkInterfaces = $networkInterfaces
        DNSConfiguration = @{
            "Serveurs DNS" = if ($dnsConfig) { $dnsConfig.ServerAddresses -join ", " } else { "N/A" }
            "Suffixes DNS" = (Get-DnsClientGlobalSetting).SuffixSearchList
        }
        TCPConnections = $tcpipInfo | Select-Object -First 20
        RoutingTable = $routingInfo | Select-Object -First 10
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    Write-Log "Analyse réseau terminée avec succès"
    
    # Formater et afficher ou exporter les résultats
    switch ($OutputFormat) {
        "Table" {
            Write-Host "`n=== INFORMATIONS SYSTÈME ===" -ForegroundColor Cyan
            $computerInfo.GetEnumerator() | ForEach-Object {
                Write-Host "$($_.Key): $($_.Value)" -ForegroundColor White
            }
            
            Write-Host "`n=== INTERFACES RÉSEAU ===" -ForegroundColor Cyan
            $networkInterfaces | Format-Table -AutoSize
            
            Write-Host "`n=== CONFIGURATION DNS ===" -ForegroundColor Cyan
            Write-Host "Serveurs DNS: $($output.DNSConfiguration.'Serveurs DNS')"
            Write-Host "Suffixes DNS: $($output.DNSConfiguration.'Suffixes DNS' -join ', ')"
            
            Write-Host "`n=== CONNEXIONS TCP ACTIVES (Top 20) ===" -ForegroundColor Cyan
            $output.TCPConnections | Format-Table -AutoSize
            
            Write-Host "`n=== TABLE DE ROUTAGE (Top 10) ===" -ForegroundColor Cyan
            $output.RoutingTable | Format-Table -AutoSize
        }
        
        "List" {
            Write-Host "`n=== INFORMATIONS RÉSEAU COMPLÈTES ===" -ForegroundColor Cyan
            $output | Format-List
        }
        
        "CSV" {
            $output | Export-Csv -Path $ExportToFile -NoTypeInformation -Encoding UTF8
            Write-Log "Résultats exportés vers $ExportToFile" -Level Success
        }
        
        "JSON" {
            $output | ConvertTo-Json -Depth 10 | Out-String
        }
    }
    
    # Exporter dans un fichier si demandé
    if ($ExportToFile -and $OutputFormat -ne "CSV") {
        switch ($OutputFormat) {
            "JSON" { $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportToFile -Encoding UTF8 }
            default {
                $header = "`n=== RAPPORT D'ANALYSE RÉSEAU ===`nGénéré le : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
                $content = $header + ($output | Out-String)
                $content | Out-File -FilePath $ExportToFile -Encoding UTF8
            }
        }
        Write-Log "Résultats exportés vers $ExportToFile" -Level Success
    }
    
} catch {
    Write-Log "Erreur lors de l'analyse réseau : $_" -Level Error
    Write-Error "Une erreur est survenue : $_"
    exit 1
}

Write-Log "Script terminé" -Level Success
