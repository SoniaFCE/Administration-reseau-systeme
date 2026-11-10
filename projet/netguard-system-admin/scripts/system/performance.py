#!/usr/bin/env python3
"""
NetGuard - Module d'analyse des performances

Ce module permet d'analyser les performances système:
- Collecte des métriques de performance
- Génération de rapports détaillés
- Détection des anomalies
- Analyse des tendances

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
from datetime import datetime, timedelta
from collections import defaultdict

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import matplotlib
    matplotlib.use('Agg')  # Utiliser un backend non-interactif
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from ..utils import logger, helpers

# Configuration du logger
log = logger.setup_logger(__name__)


class PerformanceAnalyzer:
    """Classe pour l'analyse des performances système"""
    
    def __init__(self, config=None):
        """
        Initialiser l'analyseur de performances
        
        Args:
            config: Dictionnaire de configuration
        """
        self.config = config or {}
        self.history = []
        self.max_history = self.config.get('history_days', 30)
        self.data_file = self.config.get('data_file', '/var/lib/netguard/performance.json')
        
        # Charger l'historique si le fichier existe
        self._load_history()
        
        log.info("PerformanceAnalyzer initialisé")
    
    def _load_history(self):
        """Charger l'historique des données"""
        if not os.path.exists(self.data_file):
            return
        
        try:
            with open(self.data_file, 'r') as f:
                self.history = json.load(f)
            
            # Nettoyer les anciennes données
            self._clean_old_data()
            
            log.info(f"Chargées {len(self.history)} entrées historiques")
        except Exception as e:
            log.error(f"Erreur lors du chargement de l'historique: {e}")
            self.history = []
    
    def _save_history(self):
        """Sauvegarder l'historique des données"""
        try:
            # Créer le dossier si nécessaire
            os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
            
            with open(self.data_file, 'w') as f:
                json.dump(self.history, f, indent=2, default=str)
            
            log.debug(f"Historique sauvegardé ({len(self.history)} entrées)")
        except Exception as e:
            log.error(f"Erreur lors de la sauvegarde de l'historique: {e}")
    
    def _clean_old_data(self):
        """Nettoyer les données trop anciennes"""
        if not self.history or not self.max_history:
            return
        
        cutoff_date = datetime.now() - timedelta(days=self.max_history)
        self.history = [
            entry for entry in self.history
            if datetime.fromisoformat(entry['timestamp']) >= cutoff_date
        ]
    
    def collect_performance_data(self):
        """
        Collecter les données de performance
        
        Returns:
            dict: Données de performance collectées
        """
        if not HAS_PSUTIL:
            log.error("psutil non disponible")
            return None
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'architecture': platform.machine()
            }
        }
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            cpu_count = psutil.cpu_count()
            cpu_times = psutil.cpu_times_percent(interval=1)
            
            data['cpu'] = {
                'usage': cpu_percent,
                'average': sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0,
                'cores': cpu_count,
                'times': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'iowait': getattr(cpu_times, 'iowait', 0),
                    'steal': getattr(cpu_times, 'steal', 0)
                }
            }
            
            # Mémoire
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            data['memory'] = {
                'total': mem.total,
                'used': mem.used,
                'free': mem.free,
                'percent': mem.percent,
                'active': getattr(mem, 'active', 0),
                'inactive': getattr(mem, 'inactive', 0),
                'buffers': getattr(mem, 'buffers', 0),
                'cached': getattr(mem, 'cached', 0)
            }
            
            data['swap'] = {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent
            }
            
            # Disque
            disk_io = psutil.disk_io_counters(perdisk=True)
            disk_partitions = psutil.disk_partitions(all=False)
            
            data['disk'] = {
                'io': {},
                'partitions': []
            }
            
            for disk, io in disk_io.items():
                data['disk']['io'][disk] = {
                    'read_count': io.read_count,
                    'write_count': io.write_count,
                    'read_bytes': io.read_bytes,
                    'write_bytes': io.write_bytes,
                    'read_time': io.read_time,
                    'write_time': io.write_time
                }
            
            for partition in disk_partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    data['disk']['partitions'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except:
                    pass
            
            # Réseau
            net_io = psutil.net_io_counters(pernic=True)
            
            data['network'] = {
                'interfaces': {}
            }
            
            for interface, io in net_io.items():
                data['network']['interfaces'][interface] = {
                    'bytes_sent': io.bytes_sent,
                    'bytes_recv': io.bytes_recv,
                    'packets_sent': io.packets_sent,
                    'packets_recv': io.packets_recv,
                    'errin': io.errin,
                    'errout': io.errout,
                    'dropin': io.dropin,
                    'dropout': io.dropout
                }
            
            # Processus
            pids = psutil.pids()
            process_count = {
                'total': len(pids),
                'running': 0,
                'sleeping': 0,
                'zombie': 0,
                'stopped': 0
            }
            
            for proc in psutil.process_iter(['status']):
                try:
                    status = proc.info['status']
                    if status == psutil.STATUS_RUNNING:
                        process_count['running'] += 1
                    elif status == psutil.STATUS_SLEEPING:
                        process_count['sleeping'] += 1
                    elif status == psutil.STATUS_ZOMBIE:
                        process_count['zombie'] += 1
                    elif status == psutil.STATUS_STOPPED:
                        process_count['stopped'] += 1
                except:
                    pass
            
            data['processes'] = process_count
            
            # Température
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                data['temperature'] = {}
                
                for name, entries in temps.items():
                    data['temperature'][name] = []
                    for entry in entries:
                        if entry.current:
                            data['temperature'][name].append({
                                'label': entry.label or name,
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical
                            })
            
            # GPU
            try:
                import GPUtil
                gpus = GPUtil.getGPUs()
                data['gpu'] = [
                    {
                        'id': gpu.id,
                        'name': gpu.name,
                        'load': gpu.load,
                        'memory_total': gpu.memoryTotal,
                        'memory_used': gpu.memoryUsed,
                        'memory_free': gpu.memoryFree,
                        'temperature': gpu.temperature
                    }
                    for gpu in gpus
                ]
            except:
                pass
            
        except Exception as e:
            log.error(f"Erreur lors de la collecte des données de performance: {e}")
            data['error'] = str(e)
        
        return data
    
    def add_performance_sample(self):
        """
        Ajouter un échantillon de performance à l'historique
        
        Returns:
            dict: Échantillon ajouté
        """
        data = self.collect_performance_data()
        if data:
            self.history.append(data)
            self._save_history()
            self._clean_old_data()
        return data
    
    def analyze_performance(self, duration=None, interval=1):
        """
        Analyser les performances sur une durée
        
        Args:
            duration: Durée de l'analyse en secondes (None pour utiliser l'historique)
            interval: Intervalle entre les échantillons en secondes
        
        Returns:
            dict: Résultats de l'analyse
        """
        if duration:
            # Collecter de nouvelles données
            samples = []
            start_time = time.time()
            
            print(f"Collecte des données de performance pendant {duration}s...")
            
            while time.time() - start_time < duration:
                sample = self.collect_performance_data()
                if sample:
                    samples.append(sample)
                time.sleep(interval)
            
            analysis = self._analyze_samples(samples)
        else:
            # Utiliser l'historique
            analysis = self._analyze_samples(self.history)
        
        return analysis
    
    def _analyze_samples(self, samples):
        """
        Analyser un ensemble d'échantillons
        
        Args:
            samples: Liste d'échantillons de performance
        
        Returns:
            dict: Résultats de l'analyse
        """
        if not samples:
            return {'error': 'Aucun échantillon disponible'}
        
        analysis = {
            'samples': len(samples),
            'period': {
                'start': samples[0]['timestamp'],
                'end': samples[-1]['timestamp']
            },
            'statistics': {}
        }
        
        # Analyse CPU
        cpu_values = []
        for sample in samples:
            if 'cpu' in sample and 'average' in sample['cpu']:
                cpu_values.append(sample['cpu']['average'])
        
        if cpu_values:
            analysis['statistics']['cpu'] = self._calculate_statistics(cpu_values)
        
        # Analyse mémoire
        mem_values = []
        for sample in samples:
            if 'memory' in sample and 'percent' in sample['memory']:
                mem_values.append(sample['memory']['percent'])
        
        if mem_values:
            analysis['statistics']['memory'] = self._calculate_statistics(mem_values)
        
        # Analyse disque
        disk_values = []
        for sample in samples:
            if 'disk' in sample and 'partitions' in sample['disk']:
                for partition in sample['disk']['partitions']:
                    disk_values.append(partition['percent'])
        
        if disk_values:
            analysis['statistics']['disk'] = self._calculate_statistics(disk_values)
        
        # Analyse réseau
        net_values = {'bytes_sent': [], 'bytes_recv': []}
        for sample in samples:
            if 'network' in sample and 'interfaces' in sample['network']:
                for iface, io in sample['network']['interfaces'].items():
                    net_values['bytes_sent'].append(io['bytes_sent'])
                    net_values['bytes_recv'].append(io['bytes_recv'])
        
        if net_values['bytes_sent']:
            analysis['statistics']['network'] = {
                'bytes_sent': self._calculate_statistics(net_values['bytes_sent']),
                'bytes_recv': self._calculate_statistics(net_values['bytes_recv'])
            }
        
        # Détection des anomalies
        analysis['anomalies'] = self._detect_anomalies(samples)
        
        # Tendances
        analysis['trends'] = self._calculate_trends(samples)
        
        return analysis
    
    def _calculate_statistics(self, values):
        """
        Calculer les statistiques pour une liste de valeurs
        
        Args:
            values: Liste de valeurs numériques
        
        Returns:
            dict: Statistiques calculées
        """
        if not values:
            return {}
        
        stats = {
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'median': self._calculate_median(values),
            'count': len(values)
        }
        
        if HAS_NUMPY:
            stats['std_dev'] = float(np.std(values))
            stats['variance'] = float(np.var(values))
        
        return stats
    
    def _calculate_median(self, values):
        """
        Calculer la médiane d'une liste de valeurs
        
        Args:
            values: Liste de valeurs numériques
        
        Returns:
            float: Médiane
        """
        if not values:
            return 0
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        mid = n // 2
        
        if n % 2 == 0:
            return (sorted_values[mid - 1] + sorted_values[mid]) / 2
        else:
            return sorted_values[mid]
    
    def _detect_anomalies(self, samples):
        """
        Détecter les anomalies dans les échantillons
        
        Args:
            samples: Liste d'échantillons
        
        Returns:
            dict: Anomalies détectées
        """
        anomalies = {
            'cpu': [],
            'memory': [],
            'disk': []
        }
        
        # Définir des seuils pour la détection d'anomalies
        cpu_threshold = 90
        memory_threshold = 85
        disk_threshold = 90
        
        for i, sample in enumerate(samples):
            timestamp = sample['timestamp']
            
            # Anomalies CPU
            if 'cpu' in sample and 'average' in sample['cpu']:
                cpu_usage = sample['cpu']['average']
                if cpu_usage > cpu_threshold:
                    anomalies['cpu'].append({
                        'timestamp': timestamp,
                        'value': cpu_usage,
                        'threshold': cpu_threshold
                    })
            
            # Anomalies mémoire
            if 'memory' in sample and 'percent' in sample['memory']:
                mem_usage = sample['memory']['percent']
                if mem_usage > memory_threshold:
                    anomalies['memory'].append({
                        'timestamp': timestamp,
                        'value': mem_usage,
                        'threshold': memory_threshold
                    })
            
            # Anomalies disque
            if 'disk' in sample and 'partitions' in sample['disk']:
                for partition in sample['disk']['partitions']:
                    if partition['percent'] > disk_threshold:
                        anomalies['disk'].append({
                            'timestamp': timestamp,
                            'device': partition['device'],
                            'mountpoint': partition['mountpoint'],
                            'value': partition['percent'],
                            'threshold': disk_threshold
                        })
        
        return anomalies
    
    def _calculate_trends(self, samples):
        """
        Calculer les tendances à partir des échantillons
        
        Args:
            samples: Liste d'échantillons
        
        Returns:
            dict: Tendances calculées
        """
        if len(samples) < 2:
            return {}
        
        trends = {
            'cpu': self._calculate_trend([s['cpu']['average'] for s in samples if 'cpu' in s and 'average' in s['cpu']]),
            'memory': self._calculate_trend([s['memory']['percent'] for s in samples if 'memory' in s and 'percent' in s['memory']])
        }
        
        return trends
    
    def _calculate_trend(self, values):
        """
        Calculer la tendance d'une série de valeurs
        
        Args:
            values: Liste de valeurs numériques
        
        Returns:
            dict: Informations sur la tendance
        """
        if len(values) < 2:
            return {'direction': 'stable', 'rate': 0}
        
        # Calculer la pente de la droite de régression linéaire
        n = len(values)
        x = list(range(n))
        y = values
        
        if HAS_NUMPY:
            # Utiliser numpy pour la régression linéaire
            A = np.vstack([x, np.ones(len(x))]).T
            m, c = np.linalg.lstsq(A, y, rcond=None)[0]
            slope = m
        else:
            # Calcul manuel de la pente
            x_mean = sum(x) / n
            y_mean = sum(y) / n
            
            numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
            denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
            
            if denominator == 0:
                slope = 0
            else:
                slope = numerator / denominator
        
        # Déterminer la direction
        if slope > 0.1:
            direction = 'increasing'
        elif slope < -0.1:
            direction = 'decreasing'
        else:
            direction = 'stable'
        
        return {
            'direction': direction,
            'rate': slope,
            'strength': abs(slope)
        }
    
    def generate_report(self, output_file=None, format='text', samples=None):
        """
        Générer un rapport de performance
        
        Args:
            output_file: Nom du fichier de sortie
            format: Format du rapport (text, json, html)
            samples: Échantillons à utiliser (None pour utiliser l'historique)
        
        Returns:
            str: Contenu du rapport
        """
        if samples is None:
            samples = self.history
        
        if not samples:
            return "Aucune donnée disponible pour le rapport"
        
        # Analyser les échantillons
        analysis = self._analyze_samples(samples)
        
        if format == 'json':
            content = json.dumps(analysis, indent=2, default=str, ensure_ascii=False)
            
        elif format == 'html':
            content = self._generate_html_report(analysis, samples)
            
        else:  # text
            content = self._generate_text_report(analysis, samples)
        
        # Sauvegarder le rapport si un fichier est spécifié
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Rapport généré: {output_file}")
            except Exception as e:
                log.error(f"Erreur lors de la sauvegarde du rapport: {e}")
        
        return content
    
    def _generate_text_report(self, analysis, samples):
        """Générer un rapport en texte"""
        lines = []
        
        lines.append("=" * 70)
        lines.append("RAPPORT D'ANALYSE DES PERFORMANCES - NetGuard")
        lines.append("=" * 70)
        lines.append("")
        
        # Période d'analyse
        lines.append("PÉRIODE D'ANALYSE")
        lines.append("-" * 70)
        lines.append(f"Début: {analysis['period']['start']}")
        lines.append(f"Fin: {analysis['period']['end']}")
        lines.append(f"Nombre d'échantillons: {analysis['samples']}")
        lines.append("")
        
        # Statistiques CPU
        if 'cpu' in analysis['statistics']:
            lines.append("STATISTIQUES CPU")
            lines.append("-" * 70)
            cpu_stats = analysis['statistics']['cpu']
            lines.append(f"Minimum: {cpu_stats['min']:.2f}%")
            lines.append(f"Maximum: {cpu_stats['max']:.2f}%")
            lines.append(f"Moyenne: {cpu_stats['avg']:.2f}%")
            lines.append(f"Médiane: {cpu_stats['median']:.2f}%")
            if 'std_dev' in cpu_stats:
                lines.append(f"Écart-type: {cpu_stats['std_dev']:.2f}%")
            lines.append("")
        
        # Statistiques mémoire
        if 'memory' in analysis['statistics']:
            lines.append("STATISTIQUES MÉMOIRE")
            lines.append("-" * 70)
            mem_stats = analysis['statistics']['memory']
            lines.append(f"Minimum: {mem_stats['min']:.2f}%")
            lines.append(f"Maximum: {mem_stats['max']:.2f}%")
            lines.append(f"Moyenne: {mem_stats['avg']:.2f}%")
            lines.append(f"Médiane: {mem_stats['median']:.2f}%")
            if 'std_dev' in mem_stats:
                lines.append(f"Écart-type: {mem_stats['std_dev']:.2f}%")
            lines.append("")
        
        # Statistiques disque
        if 'disk' in analysis['statistics']:
            lines.append("STATISTIQUES DISQUE")
            lines.append("-" * 70)
            disk_stats = analysis['statistics']['disk']
            lines.append(f"Minimum: {disk_stats['min']:.2f}%")
            lines.append(f"Maximum: {disk_stats['max']:.2f}%")
            lines.append(f"Moyenne: {disk_stats['avg']:.2f}%")
            lines.append(f"Médiane: {disk_stats['median']:.2f}%")
            if 'std_dev' in disk_stats:
                lines.append(f"Écart-type: {disk_stats['std_dev']:.2f}%")
            lines.append("")
        
        # Anomalies
        anomalies = analysis.get('anomalies', {})
        total_anomalies = sum(len(v) for v in anomalies.values())
        
        if total_anomalies > 0:
            lines.append("ANOMALIES DÉTECTÉES")
            lines.append("-" * 70)
            
            for type, anoms in anomalies.items():
                if anoms:
                    lines.append(f"{type.upper()}: {len(anoms)} anomalies")
                    for anomaly in anoms[:5]:  # Afficher les 5 premières
                        lines.append(f"  - {anomaly['timestamp']}: {anomaly['value']:.1f}% > {anomaly['threshold']}%")
                    if len(anoms) > 5:
                        lines.append(f"  ... et {len(anoms) - 5} de plus")
            lines.append("")
        
        # Tendances
        trends = analysis.get('trends', {})
        if trends:
            lines.append("TENDANCES")
            lines.append("-" * 70)
            for resource, trend in trends.items():
                direction_emoji = {
                    'increasing': '⬆️',
                    'decreasing': '⬇️',
                    'stable': '➡️'
                }.get(trend['direction'], '➡️')
                lines.append(f"{resource.upper()}: {direction_emoji} {trend['direction']} (taux: {trend['rate']:.4f})")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _generate_html_report(self, analysis, samples):
        """Générer un rapport HTML"""
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Performance - NetGuard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c3e50;
            margin-top: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .stat-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
        }}
        .anomaly {{
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            background: #f8d7da;
            color: #721c24;
        }}
        .trend {{
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 5px;
        }}
        .trend.increasing {{
            background: #d4edda;
            border-left: 4px solid #28a745;
        }}
        .trend.decreasing {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }}
        .trend.stable {{
            background: #e2e3e5;
            border-left: 4px solid #6c757d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        table, th, td {{
            border: 1px solid #dee2e6;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: #f8f9fa;
        }}
        .chart-container {{
            height: 300px;
            margin: 20px 0;
        }}
        footer {{
            text-align: center;
            margin-top: 50px;
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'Analyse des Performances - NetGuard</h1>
        
        <div class="section">
            <h2>📊 Période d'Analyse</h2>
            <div class="stat-box">
                <p><strong>Début:</strong> {analysis['period']['start']}</p>
                <p><strong>Fin:</strong> {analysis['period']['end']}</p>
                <p><strong>Nombre d'échantillons:</strong> {analysis['samples']}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📈 Statistiques</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 20px;">
                {''.join([f'''
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>CPU</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value">{analysis['statistics']['cpu']['avg']:.2f}%</span></p>
                    <p><strong>Minimum:</strong> {analysis['statistics']['cpu']['min']:.2f}%</p>
                    <p><strong>Maximum:</strong> {analysis['statistics']['cpu']['max']:.2f}%</p>
                    <p><strong>Médiane:</strong> {analysis['statistics']['cpu']['median']:.2f}%</p>
                </div>
                ''' if 'cpu' in analysis['statistics'] else ''])}
                
                {''.join([f'''
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>Mémoire</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value">{analysis['statistics']['memory']['avg']:.2f}%</span></p>
                    <p><strong>Minimum:</strong> {analysis['statistics']['memory']['min']:.2f}%</p>
                    <p><strong>Maximum:</strong> {analysis['statistics']['memory']['max']:.2f}%</p>
                    <p><strong>Médiane:</strong> {analysis['statistics']['memory']['median']:.2f}%</p>
                </div>
                ''' if 'memory' in analysis['statistics'] else ''])}
                
                {''.join([f'''
                <div class="stat-box" style="flex: 1; min-width: 200px;">
                    <h3>Disque</h3>
                    <p><strong>Moyenne:</strong> <span class="stat-value">{analysis['statistics']['disk']['avg']:.2f}%</span></p>
                    <p><strong>Minimum:</strong> {analysis['statistics']['disk']['min']:.2f}%</p>
                    <p><strong>Maximum:</strong> {analysis['statistics']['disk']['max']:.2f}%</p>
                    <p><strong>Médiane:</strong> {analysis['statistics']['disk']['median']:.2f}%</p>
                </div>
                ''' if 'disk' in analysis['statistics'] else ''])}
            </div>
        </div>
        
        {''.join([f'''
        <div class="section">
            <h2>⚠️ Anomalies Détectées ({sum(len(v) for v in analysis['anomalies'].values())} total)</h2>
            <div class="anomaly">
                <p><strong>CPU:</strong> {len(analysis['anomalies']['cpu'])} anomalies</p>
                {''.join([f'<p>- {anomaly["timestamp"]}: {anomaly["value"]:.1f}% &gt; {anomaly["threshold"]}%</p>' for anomaly in analysis['anomalies']['cpu'][:5]])}
                {f'<p>... et {len(analysis["anomalies"]["cpu"]) - 5} de plus</p>' if len(analysis['anomalies']['cpu']) > 5 else ''}
            </div>
            <div class="anomaly">
                <p><strong>Mémoire:</strong> {len(analysis['anomalies']['memory'])} anomalies</p>
                {''.join([f'<p>- {anomaly["timestamp"]}: {anomaly["value"]:.1f}% &gt; {anomaly["threshold"]}%</p>' for anomaly in analysis['anomalies']['memory'][:5]])}
                {f'<p>... et {len(analysis["anomalies"]["memory"]) - 5} de plus</p>' if len(analysis['anomalies']['memory']) > 5 else ''}
            </div>
            <div class="anomaly">
                <p><strong>Disque:</strong> {len(analysis['anomalies']['disk'])} anomalies</p>
                {''.join([f'<p>- {anomaly["timestamp"]}: {anomaly["mountpoint"]} à {anomaly["value"]:.1f}% &gt; {anomaly["threshold"]}%</p>' for anomaly in analysis['anomalies']['disk'][:5]])}
                {f'<p>... et {len(analysis["anomalies"]["disk"]) - 5} de plus</p>' if len(analysis['anomalies']['disk']) > 5 else ''}
            </div>
        </div>
        ''' if analysis.get('anomalies') and sum(len(v) for v in analysis['anomalies'].values()) > 0 else ''}
        
        {''.join([f'''
        <div class="section">
            <h2>📊 Tendances</h2>
            {''.join([f'''
            <div class="trend {trend['direction']}">
                <p><strong>{resource.upper()}:</strong> {trend['direction'].upper()} (taux: {trend['rate']:.4f})</p>
            </div>
            ''' for resource, trend in analysis.get('trends', {}).items()])}
        </div>
        ''' if analysis.get('trends') else '']}
        
        <footer>
            <p>Généré par NetGuard Performance Analyzer v1.0.0</p>
        </footer>
    </div>
</body>
</html>
"""
        return html


def main(args=None):
    """
    Fonction principale pour le module d'analyse des performances
    
    Args:
        args: Arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(
        description="Analyser les performances système",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python performance.py --collect --duration 300 --interval 10
  python performance.py --analyze --duration 60
  python performance.py --report --output performance_report.html --format html
  python performance.py --show-history
  python performance.py --detect-anomalies
        """
    )
    
    # Arguments pour la collecte
    parser.add_argument('--collect', action='store_true',
                        help='Collecter des données de performance')
    parser.add_argument('--duration', type=int, default=60,
                        help='Durée de la collecte en secondes (par défaut: 60)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Intervalle entre les échantillons en secondes (par défaut: 5)')
    
    # Arguments pour l'analyse
    parser.add_argument('--analyze', action='store_true',
                        help='Analyser les données collectées')
    parser.add_argument('--history', action='store_true',
                        help='Analyser l\'historique complet')
    
    # Arguments pour le rapport
    parser.add_argument('--report', action='store_true',
                        help='Générer un rapport de performance')
    parser.add_argument('--output', type=str,
                        help='Fichier de sortie pour le rapport')
    parser.add_argument('--format', type=str, choices=['text', 'json', 'html'],
                        default='text', help='Format du rapport (par défaut: text)')
    
    # Arguments pour l'historique
    parser.add_argument('--show-history', action='store_true',
                        help='Afficher l\'historique des données')
    parser.add_argument('--clear-history', action='store_true',
                        help='Effacer l\'historique')
    
    # Arguments pour les anomalies
    parser.add_argument('--detect-anomalies', action='store_true',
                        help='Détecter les anomalies dans l\'historique')
    
    # Arguments de configuration
    parser.add_argument('--config', type=str,
                        help='Fichier de configuration YAML')
    parser.add_argument('--data-file', type=str,
                        help='Fichier de stockage des données')
    parser.add_argument('--history-days', type=int, default=30,
                        help='Nombre de jours d\'historique à conserver (par défaut: 30)')
    
    # Arguments divers
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
                if 'performance' in config:
                    config = config['performance']
        except Exception as e:
            log.error(f"Erreur lors du chargement de la configuration: {e}")
    
    # Créer l'analyseur de performances
    analyzer = PerformanceAnalyzer({
        'data_file': args.data_file,
        'history_days': args.history_days
    })
    
    # Collecter des données
    if args.collect:
        print(f"Collecte des données de performance pendant {args.duration}s...")
        print(f"Intervalle: {args.interval}s")
        
        samples = []
        start_time = time.time()
        
        while time.time() - start_time < args.duration:
            sample = analyzer.collect_performance_data()
            if sample:
                samples.append(sample)
                print(f"  Échantillon {len(samples)} collecté à {sample['timestamp']}")
            time.sleep(args.interval)
        
        print(f"\n{samples} échantillons collectés")
        
        # Sauvegarder les échantillons
        analyzer.history.extend(samples)
        analyzer._save_history()
        
        return
    
    # Analyser les données
    if args.analyze or args.history:
        if args.history:
            analysis = analyzer.analyze_performance()
        else:
            analysis = analyzer.analyze_performance(duration=args.duration)
        
        if args.json:
            print(json.dumps(analysis, indent=2, default=str))
        else:
            # Afficher un résumé
            print(f"\nAnalyse des performances:")
            print(f"Période: {analysis['period']['start']} à {analysis['period']['end']}")
            print(f"Échantillons: {analysis['samples']}")
            
            if 'cpu' in analysis['statistics']:
                print(f"\nCPU: Moyenne={analysis['statistics']['cpu']['avg']:.2f}%, "
                      f"Max={analysis['statistics']['cpu']['max']:.2f}%")
            if 'memory' in analysis['statistics']:
                print(f"Mémoire: Moyenne={analysis['statistics']['memory']['avg']:.2f}%, "
                      f"Max={analysis['statistics']['memory']['max']:.2f}%")
            
            anomalies = sum(len(v) for v in analysis.get('anomalies', {}).values())
            print(f"\nAnomalies détectées: {anomalies}")
            
            for type, trend in analysis.get('trends', {}).items():
                print(f"Tendance {type}: {trend['direction']} (taux: {trend['rate']:.4f})")
        
        return
    
    # Générer un rapport
    if args.report:
        report = analyzer.generate_report(
            output_file=args.output,
            format=args.format
        )
        
        if not args.quiet and not args.output:
            print(f"\n{report}")
        
        return
    
    # Afficher l'historique
    if args.show_history:
        print(f"\nHistorique des données ({len(analyzer.history)} entrées):")
        print(f"Fichier: {analyzer.data_file}")
        
        if analyzer.history:
            print(f"\nDernières entrées:")
            for i, entry in enumerate(analyzer.history[-5:], 1):
                print(f"{i}. {entry['timestamp']}")
                if 'cpu' in entry:
                    print(f"   CPU: {entry['cpu']['average']:.2f}%")
                if 'memory' in entry:
                    print(f"   Mémoire: {entry['memory']['percent']:.2f}%")
        else:
            print("Aucune donnée dans l'historique")
        
        return
    
    # Effacer l'historique
    if args.clear_history:
        analyzer.history = []
        analyzer._save_history()
        print("Historique effacé")
        return
    
    # Détecter les anomalies
    if args.detect_anomalies:
        anomalies = analyzer._detect_anomalies(analyzer.history)
        
        total = sum(len(v) for v in anomalies.values())
        print(f"\nAnomalies détectées: {total}")
        
        for type, anoms in anomalies.items():
            if anoms:
                print(f"\n{type.upper()}: {len(anoms)} anomalies")
                for anomaly in anoms[:5]:
                    print(f"  - {anomaly['timestamp']}: {anomaly.get('value', 'N/A')} > {anomaly['threshold']}")
                if len(anoms) > 5:
                    print(f"  ... et {len(anoms) - 5} de plus")
        
        return
    
    # Par défaut: collecter un échantillon et afficher un rapport
    print("Collecte d'un échantillon de performance...")
    analyzer.add_performance_sample()
    
    report = analyzer.generate_report(format='text')
    print(f"\n{report}")


if __name__ == "__main__":
    main()
