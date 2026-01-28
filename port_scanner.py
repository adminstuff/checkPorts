#!/usr/bin/env python3
"""
Outil de scan de ports réseau avec interface graphique (PyQt5) et mode CLI.

Usage CLI:
    python port_scanner.py --cli --profile "Web Standard" --ip 192.168.1.1
    python port_scanner.py --cli --ip 192.168.1.1-192.168.1.10 --ports 22,80,443
    python port_scanner.py --cli --profile "Administration" --ip 10.0.0.0/24 --output rapport.json
"""

import sys
import socket
import ipaddress
import json
import os
import argparse
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

CLI_MODE = '--cli' in sys.argv or '-c' in sys.argv

if not CLI_MODE:
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
            QGroupBox, QGridLayout, QSpinBox, QProgressBar, QFileDialog,
            QMessageBox, QHeaderView, QSplitter, QCheckBox,
            QListWidget, QAbstractItemView, QFrame, QScrollArea,
            QComboBox, QInputDialog, QButtonGroup, QRadioButton, QMenu,
            QAction, QToolButton
        )
        from PyQt5.QtCore import Qt, QThread, pyqtSignal
        from PyQt5.QtGui import QColor, QFont
        GUI_AVAILABLE = True
    except ImportError:
        GUI_AVAILABLE = False
else:
    GUI_AVAILABLE = False

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    )
    from reportlab.lib.enums import TA_CENTER
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


@dataclass
class ScanResult:
    ip: str
    port: int
    is_open: bool
    service: str
    response_time: Optional[float] = None


@dataclass
class Profile:
    name: str
    ports: List[int]
    ips: List[str]
    timeout: int = 2
    threads: int = 20


COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

DEFAULT_PROFILES = {
    "Web Standard": Profile(
        name="Web Standard",
        ports=[80, 443, 8080, 8443],
        ips=[]
    ),
    "Services Mail": Profile(
        name="Services Mail",
        ports=[25, 110, 143, 465, 587, 993, 995],
        ips=[]
    ),
    "Administration": Profile(
        name="Administration",
        ports=[22, 23, 3389, 5900],
        ips=[]
    ),
    "Base de données": Profile(
        name="Base de données",
        ports=[3306, 5432, 1433, 1521, 27017, 6379],
        ips=[]
    ),
    "Transfert fichiers": Profile(
        name="Transfert fichiers",
        ports=[20, 21, 22, 69, 115, 445],
        ips=[]
    ),
    "Tous ports communs": Profile(
        name="Tous ports communs",
        ports=list(COMMON_PORTS.keys()),
        ips=[]
    )
}


def get_profiles_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")


def sanitize_filename(name: str) -> str:
    invalid_chars = '<>:"/\\|?*'
    filename = name
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def profile_to_file_content(profile: Profile) -> str:
    """Sérialise un profil au format texte .profil (clé = valeur, commentaires #)."""
    lines = [
        "# Fichier de profil Port Scanner",
        "# Modifiable manuellement - les lignes commencant par # sont ignorees",
        "",
        f"name = {profile.name}",
        "",
        "# Liste des ports a scanner (separes par des virgules)",
        f"ports = {', '.join(str(p) for p in profile.ports)}",
        "",
        "# Liste des adresses IP cibles (une par ligne ou separees par des virgules)",
        "# Laisser vide pour definir les IPs dans l'interface",
        f"ips = {', '.join(profile.ips) if profile.ips else ''}",
        "",
        "# Timeout en secondes pour chaque test de port",
        f"timeout = {profile.timeout}",
        "",
        "# Nombre de threads paralleles",
        f"threads = {profile.threads}",
        ""
    ]
    return '\n'.join(lines)


def parse_profile_file(filepath: str) -> Optional[Profile]:
    """Lit un fichier .profil et retourne un objet Profile, ou None si invalide."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        data = {}
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                data[key.strip()] = value.strip()

        name = data.get('name', os.path.splitext(os.path.basename(filepath))[0])

        ports_str = data.get('ports', '')
        ports = []
        if ports_str:
            for p in ports_str.replace(' ', '').split(','):
                if p:
                    try:
                        ports.append(int(p))
                    except ValueError:
                        pass

        ips_str = data.get('ips', '')
        ips = [ip for ip in ips_str.replace(' ', '').split(',') if ip] if ips_str else []

        timeout = int(data.get('timeout', 2))
        threads = int(data.get('threads', 20))

        return Profile(name=name, ports=ports, ips=ips, timeout=timeout, threads=threads)

    except Exception:
        return None


def save_profile_to_file(profile: Profile, is_default: bool = False) -> bool:
    profiles_dir = get_profiles_dir()
    os.makedirs(profiles_dir, exist_ok=True)

    filename = sanitize_filename(profile.name) + ".profil"
    filepath = os.path.join(profiles_dir, filename)

    try:
        content = profile_to_file_content(profile)
        if is_default:
            content = "# [PROFIL PAR DEFAUT]\n" + content

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception:
        return False


def delete_profile_file(profile_name: str) -> bool:
    profiles_dir = get_profiles_dir()
    filename = sanitize_filename(profile_name) + ".profil"
    filepath = os.path.join(profiles_dir, filename)

    try:
        if os.path.exists(filepath):
            os.remove(filepath)
        return True
    except Exception:
        return False


def is_default_profile_file(filepath: str) -> bool:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            return '[PROFIL PAR DEFAUT]' in first_line
    except Exception:
        return False


def init_default_profiles():
    """Crée les fichiers .profil par défaut s'ils n'existent pas encore."""
    profiles_dir = get_profiles_dir()
    os.makedirs(profiles_dir, exist_ok=True)

    for name, profile in DEFAULT_PROFILES.items():
        filename = sanitize_filename(name) + ".profil"
        filepath = os.path.join(profiles_dir, filename)
        if not os.path.exists(filepath):
            save_profile_to_file(profile, is_default=True)


def load_profiles() -> Dict[str, Profile]:
    """Charge tous les profils depuis le dossier profiles/."""
    init_default_profiles()

    profiles = {}
    profiles_dir = get_profiles_dir()

    if os.path.exists(profiles_dir):
        for filename in os.listdir(profiles_dir):
            if filename.endswith('.profil'):
                filepath = os.path.join(profiles_dir, filename)
                profile = parse_profile_file(filepath)
                if profile:
                    profiles[profile.name] = profile

    return profiles


def get_default_profile_names() -> List[str]:
    return list(DEFAULT_PROFILES.keys())


def get_service_name(port: int) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return "Unknown"


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> ScanResult:
    """Teste la connectivité TCP sur un port et retourne le résultat."""
    start_time = datetime.now()
    is_open = False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        is_open = (result == 0)
        sock.close()
    except Exception:
        is_open = False

    response_time = (datetime.now() - start_time).total_seconds() * 1000
    service = get_service_name(port)

    return ScanResult(ip, port, is_open, service, response_time)


# Le code CLI est placé avant les classes GUI pour que `sys.exit(run_cli())`
# s'exécute avant que Python ne tente de résoudre les références à PyQt5.

def parse_ip_argument(ip_arg: str) -> List[str]:
    """Parse une chaîne IP (unique, plage, CIDR ou liste CSV) en liste d'adresses."""
    ips = []

    for part in ip_arg.split(','):
        part = part.strip()
        if not part:
            continue

        if '/' in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                for host in network.hosts():
                    ips.append(str(host))
            except ValueError as e:
                print(f"[ERREUR] CIDR invalide '{part}': {e}", file=sys.stderr)

        elif '-' in part and part.count('-') == 1 and not part.startswith('-'):
            try:
                start_str, end_str = part.split('-')
                # Format court : 192.168.1.1-10 -> 192.168.1.1-192.168.1.10
                if '.' not in end_str:
                    base = '.'.join(start_str.split('.')[:-1])
                    end_str = f"{base}.{end_str}"

                start_ip = ipaddress.ip_address(start_str.strip())
                end_ip = ipaddress.ip_address(end_str.strip())

                if start_ip > end_ip:
                    start_ip, end_ip = end_ip, start_ip

                current = start_ip
                while current <= end_ip:
                    ips.append(str(current))
                    current = ipaddress.ip_address(int(current) + 1)
            except ValueError as e:
                print(f"[ERREUR] Plage IP invalide '{part}': {e}", file=sys.stderr)

        else:
            try:
                ipaddress.ip_address(part)
                ips.append(part)
            except ValueError as e:
                print(f"[ERREUR] IP invalide '{part}': {e}", file=sys.stderr)

    return ips


def parse_ports_argument(ports_arg: str) -> List[int]:
    """Parse une chaîne de ports (unique, plage, liste CSV) en liste triée."""
    ports = []

    for part in ports_arg.split(','):
        part = part.strip()
        if not part:
            continue

        if '-' in part:
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                for p in range(start_port, end_port + 1):
                    if 1 <= p <= 65535 and p not in ports:
                        ports.append(p)
            except ValueError:
                print(f"[ERREUR] Plage de ports invalide '{part}'", file=sys.stderr)
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535 and p not in ports:
                    ports.append(p)
            except ValueError:
                print(f"[ERREUR] Port invalide '{part}'", file=sys.stderr)

    return sorted(ports)


def cli_scan(ips: List[str], ports: List[int], timeout: float, threads: int,
             show_closed: bool = False, quiet: bool = False) -> List[ScanResult]:
    results = []
    total = len(ips) * len(ports)
    completed = 0
    open_count = 0

    if not quiet:
        print(f"\n{'='*60}")
        print(f"SCAN DE PORTS")
        print(f"{'='*60}")
        print(f"Cibles: {len(ips)} IP(s)")
        print(f"Ports: {len(ports)} port(s)")
        print(f"Total: {total} tests")
        print(f"Timeout: {timeout}s | Threads: {threads}")
        print(f"{'='*60}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}

        for ip in ips:
            for port in ports:
                future = executor.submit(scan_port, ip, port, timeout)
                futures[future] = (ip, port)

        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)

                if result.is_open:
                    open_count += 1
                    if not quiet:
                        print(f"[OUVERT] {result.ip}:{result.port} ({result.service}) - {result.response_time:.1f}ms")
                elif show_closed and not quiet:
                    print(f"[FERME]  {result.ip}:{result.port} ({result.service})")

            except Exception as e:
                ip, port = futures[future]
                results.append(ScanResult(ip, port, False, "Error"))
                if not quiet:
                    print(f"[ERREUR] {ip}:{port} - {e}", file=sys.stderr)

            completed += 1

            if not quiet and total > 10:
                progress = int((completed / total) * 100)
                if completed % max(1, total // 10) == 0:
                    print(f"... Progression: {progress}% ({completed}/{total})")

    if not quiet:
        closed_count = len(results) - open_count
        print(f"\n{'='*60}")
        print(f"RESULTATS")
        print(f"{'='*60}")
        print(f"Total scanne: {len(results)}")
        print(f"Ports ouverts: {open_count}")
        print(f"Ports fermes: {closed_count}")
        print(f"{'='*60}\n")

    return results


def export_results_json(results: List[ScanResult], filename: str, only_open: bool = False):
    if only_open:
        results = [r for r in results if r.is_open]

    data = {
        "scan_date": datetime.now().isoformat(),
        "total_scans": len(results),
        "open_ports": sum(1 for r in results if r.is_open),
        "results": [asdict(r) for r in sorted(results, key=lambda x: (x.ip, x.port))]
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[OK] Résultats exportés vers: {filename}")


def export_results_csv(results: List[ScanResult], filename: str, only_open: bool = False):
    if only_open:
        results = [r for r in results if r.is_open]

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("ip,port,service,status,response_time_ms\n")
        for r in sorted(results, key=lambda x: (x.ip, x.port)):
            status = "OPEN" if r.is_open else "CLOSED"
            time_str = f"{r.response_time:.1f}" if r.response_time else ""
            f.write(f"{r.ip},{r.port},{r.service},{status},{time_str}\n")

    print(f"[OK] Résultats exportés vers: {filename}")


def export_results_text(results: List[ScanResult], filename: str, only_open: bool = False):
    if only_open:
        results = [r for r in results if r.is_open]

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("RAPPORT DE SCAN DE PORTS\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        open_count = sum(1 for r in results if r.is_open)
        f.write(f"Total: {len(results)} | Ouverts: {open_count} | Fermes: {len(results) - open_count}\n\n")

        f.write("-" * 70 + "\n")
        f.write(f"{'IP':<20} {'PORT':<8} {'SERVICE':<15} {'STATUT':<10} {'TEMPS':<10}\n")
        f.write("-" * 70 + "\n")

        for r in sorted(results, key=lambda x: (x.ip, x.port)):
            status = "OUVERT" if r.is_open else "FERME"
            time_str = f"{r.response_time:.1f}ms" if r.response_time else "-"
            f.write(f"{r.ip:<20} {r.port:<8} {r.service:<15} {status:<10} {time_str:<10}\n")

        f.write("-" * 70 + "\n")

    print(f"[OK] Résultats exportés vers: {filename}")


def generate_pdf_report_cli(results: List[ScanResult], filename: str,
                            timeout: int, threads: int, only_open: bool = False):
    if not PDF_AVAILABLE:
        print("[ERREUR] ReportLab non installé.", file=sys.stderr)
        return

    if only_open:
        filtered_results = [r for r in results if r.is_open]
    else:
        filtered_results = results

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        alignment=TA_CENTER,
        spaceAfter=30
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20
    )

    elements = []
    elements.append(Paragraph("Rapport de Scan de Ports", title_style))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Informations générales", heading_style))
    scan_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    source_ip = get_local_ip()
    filter_text = "Ports ouverts uniquement" if only_open else "Tous"

    info_data = [
        ["Date du scan:", scan_time],
        ["IP source:", source_ip],
        ["Timeout:", f"{timeout} secondes"],
        ["Threads:", str(threads)],
        ["Filtre:", filter_text],
        ["Mode:", "CLI"]
    ]
    info_table = Table(info_data, colWidths=[4*cm, 10*cm])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(info_table)

    elements.append(Paragraph("Statistiques", heading_style))

    total = len(results)
    open_count = sum(1 for r in results if r.is_open)

    stats_data = [
        ["Total de tests:", str(total)],
        ["Ports ouverts:", str(open_count)],
        ["Ports fermés:", str(total - open_count)],
        ["Résultats exportés:", str(len(filtered_results))]
    ]

    stats_table = Table(stats_data, colWidths=[4*cm, 10*cm])
    stats_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(stats_table)
    elements.append(Paragraph("Résultats détaillés", heading_style))

    table_data = [["IP", "Port", "Service", "Statut", "Temps (ms)"]]
    sorted_results = sorted(filtered_results, key=lambda r: (r.ip, r.port))

    for result in sorted_results:
        status = "OUVERT" if result.is_open else "FERMÉ"
        time_str = f"{result.response_time:.1f}" if result.response_time else "-"
        table_data.append([result.ip, str(result.port), result.service, status, time_str])

    results_table = Table(table_data, colWidths=[3.5*cm, 1.5*cm, 3*cm, 2*cm, 2*cm])
    table_style = [
        ('BACKGROUND', (0, 0), (-1, 0), rl_colors.HexColor('#2196F3')),
        ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, rl_colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]

    # Couleurs conditionnelles par statut ouvert/fermé
    for i, result in enumerate(sorted_results, start=1):
        if result.is_open:
            table_style.append(('BACKGROUND', (3, i), (3, i), rl_colors.HexColor('#c8e6c9')))
            table_style.append(('TEXTCOLOR', (3, i), (3, i), rl_colors.HexColor('#2e7d32')))
        else:
            table_style.append(('BACKGROUND', (3, i), (3, i), rl_colors.HexColor('#ffcdd2')))
            table_style.append(('TEXTCOLOR', (3, i), (3, i), rl_colors.HexColor('#c62828')))

    results_table.setStyle(TableStyle(table_style))
    elements.append(results_table)

    doc.build(elements)
    print(f"[OK] Rapport PDF exporté vers: {filename}")


def list_profiles_cli():
    profiles = load_profiles()
    default_names = get_default_profile_names()

    print(f"\n{'='*60}")
    print("PROFILS DISPONIBLES")
    print(f"{'='*60}\n")

    print("Profils par défaut:")
    for name in sorted(profiles.keys()):
        if name in default_names:
            p = profiles[name]
            print(f"  - {name}")
            print(f"    Ports: {', '.join(str(port) for port in p.ports[:5])}{'...' if len(p.ports) > 5 else ''}")

    print("\nProfils personnalisés:")
    custom_found = False
    for name in sorted(profiles.keys()):
        if name not in default_names:
            custom_found = True
            p = profiles[name]
            print(f"  - {name}")
            print(f"    Ports: {', '.join(str(port) for port in p.ports[:5])}{'...' if len(p.ports) > 5 else ''}")
            if p.ips:
                print(f"    IPs: {', '.join(p.ips[:3])}{'...' if len(p.ips) > 3 else ''}")

    if not custom_found:
        print("  (aucun)")

    print(f"\nDossier des profils: {get_profiles_dir()}")
    print()


def run_cli():
    parser = argparse.ArgumentParser(
        description="Port Scanner - Outil de scan de ports réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s --cli --ip 192.168.1.1 --ports 22,80,443
  %(prog)s --cli --ip 192.168.1.1-192.168.1.10 --ports 80-443
  %(prog)s --cli --ip 10.0.0.0/24 --profile "Web Standard"
  %(prog)s --cli --profile "Administration" --ip 192.168.1.1 -o rapport.json
  %(prog)s --cli --list-profiles
        """
    )

    parser.add_argument('-c', '--cli', action='store_true',
                        help='Mode ligne de commande (sans interface graphique)')

    parser.add_argument('--ip', '-i', type=str,
                        help='Adresse(s) IP cible(s). Formats: IP unique, plage (1.1.1.1-1.1.1.10), CIDR (1.1.1.0/24)')

    parser.add_argument('--ports', '-p', type=str,
                        help='Port(s) à scanner. Formats: port unique, liste (22,80,443), plage (80-443)')

    parser.add_argument('--profile', '-P', type=str,
                        help='Nom du profil à utiliser')

    parser.add_argument('--timeout', '-t', type=float, default=2.0,
                        help='Timeout en secondes (défaut: 2)')

    parser.add_argument('--threads', '-T', type=int, default=20,
                        help='Nombre de threads (défaut: 20)')

    parser.add_argument('--output', '-o', type=str,
                        help='Fichier de sortie (.json, .csv, .txt, .pdf)')

    parser.add_argument('--only-open', action='store_true',
                        help='N\'afficher/exporter que les ports ouverts')

    parser.add_argument('--show-closed', action='store_true',
                        help='Afficher aussi les ports fermés pendant le scan')

    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Mode silencieux (pas de sortie console)')

    parser.add_argument('--list-profiles', '-l', action='store_true',
                        help='Lister les profils disponibles')

    args = parser.parse_args()

    if args.list_profiles:
        list_profiles_cli()
        return 0

    ips = []
    ports = []
    timeout = args.timeout
    threads = args.threads

    if args.profile:
        profiles = load_profiles()
        if args.profile not in profiles:
            print(f"[ERREUR] Profil '{args.profile}' non trouvé.", file=sys.stderr)
            print("Utilisez --list-profiles pour voir les profils disponibles.", file=sys.stderr)
            return 1

        profile = profiles[args.profile]
        ports = profile.ports.copy()
        ips = profile.ips.copy()
        timeout = profile.timeout
        threads = profile.threads

        if not args.quiet:
            print(f"[INFO] Profil '{args.profile}' chargé")

    if args.ip:
        ips = parse_ip_argument(args.ip)

    if args.ports:
        ports = parse_ports_argument(args.ports)

    if args.timeout != 2.0:
        timeout = args.timeout

    if args.threads != 20:
        threads = args.threads

    if not ips:
        print("[ERREUR] Aucune adresse IP spécifiée.", file=sys.stderr)
        print("Utilisez --ip ou --profile avec des IPs définies.", file=sys.stderr)
        return 1

    if not ports:
        print("[ERREUR] Aucun port spécifié.", file=sys.stderr)
        print("Utilisez --ports ou --profile.", file=sys.stderr)
        return 1

    results = cli_scan(ips, ports, timeout, threads,
                       show_closed=args.show_closed, quiet=args.quiet)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()

        if ext == '.json':
            export_results_json(results, args.output, only_open=args.only_open)
        elif ext == '.csv':
            export_results_csv(results, args.output, only_open=args.only_open)
        elif ext == '.txt':
            export_results_text(results, args.output, only_open=args.only_open)
        elif ext == '.pdf':
            if not PDF_AVAILABLE:
                print("[ERREUR] ReportLab non installé. Export PDF impossible.", file=sys.stderr)
                print("Installez avec: pip install reportlab", file=sys.stderr)
                return 1
            generate_pdf_report_cli(results, args.output, timeout, threads, args.only_open)
        else:
            print(f"[ERREUR] Format de sortie non reconnu: {ext}", file=sys.stderr)
            print("Formats supportés: .json, .csv, .txt, .pdf", file=sys.stderr)
            return 1

    # Exit codes : 0 = ports ouverts trouvés, 2 = aucun port ouvert
    open_count = sum(1 for r in results if r.is_open)
    return 0 if open_count > 0 else 2


if CLI_MODE:
    sys.exit(run_cli())


# =============================================================================
# CLASSES GUI (uniquement chargées si pas en mode CLI)
# =============================================================================

class ScanWorker(QThread):
    """Thread de travail pour le scan de ports"""
    progress = pyqtSignal(int)
    result_ready = pyqtSignal(object)
    scan_complete = pyqtSignal()
    status_update = pyqtSignal(str)

    def __init__(self, ips: List[str], ports: List[int], timeout: float, max_threads: int):
        super().__init__()
        self.ips = ips
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        total_scans = len(self.ips) * len(self.ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}

            for ip in self.ips:
                if not self._is_running:
                    break
                for port in self.ports:
                    if not self._is_running:
                        break
                    future = executor.submit(scan_port, ip, port, self.timeout)
                    futures[future] = (ip, port)

            for future in as_completed(futures):
                if not self._is_running:
                    break
                try:
                    result = future.result()
                    self.result_ready.emit(result)
                except Exception:
                    ip, port = futures[future]
                    self.result_ready.emit(ScanResult(ip, port, False, "Error"))

                completed += 1
                progress_pct = int((completed / total_scans) * 100)
                self.progress.emit(progress_pct)
                self.status_update.emit(f"Scan en cours: {completed}/{total_scans}")

        self.scan_complete.emit()


class PortScannerApp(QMainWindow):
    """Application principale de scan de ports"""

    # Constantes pour les filtres
    FILTER_ALL = "all"
    FILTER_OPEN = "open"
    FILTER_CLOSED = "closed"

    def __init__(self):
        super().__init__()
        self.scan_results: List[ScanResult] = []
        self.worker: Optional[ScanWorker] = None
        self.profiles = load_profiles()
        self.current_filter = self.FILTER_ALL
        self.init_ui()

    def init_ui(self):
        """Initialise l'interface utilisateur"""
        self.setWindowTitle("Port Scanner - Outil de test de ports réseau")
        self.setMinimumSize(1100, 750)

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Splitter horizontal pour la configuration et les résultats
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)

        # Panneau de configuration (gauche) avec scroll
        config_scroll = QScrollArea()
        config_scroll.setWidgetResizable(True)
        config_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        config_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        config_scroll.setMinimumWidth(380)

        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)

        # Groupe Profils
        profiles_group = self.create_profiles_group()
        config_layout.addWidget(profiles_group)

        # Groupe IP
        ip_group = self.create_ip_group()
        config_layout.addWidget(ip_group)

        # Groupe Ports
        ports_group = self.create_ports_group()
        config_layout.addWidget(ports_group)

        # Groupe Options
        options_group = self.create_options_group()
        config_layout.addWidget(options_group)

        # Boutons d'action
        action_layout = QHBoxLayout()

        self.start_btn = QPushButton("Démarrer le scan")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.start_btn.clicked.connect(self.start_scan)

        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_scan)

        action_layout.addWidget(self.start_btn)
        action_layout.addWidget(self.stop_btn)
        config_layout.addLayout(action_layout)

        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        config_layout.addWidget(self.progress_bar)

        # Label de statut
        self.status_label = QLabel("Prêt")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        config_layout.addWidget(self.status_label)

        config_layout.addStretch()

        # Bouton export PDF
        self.export_btn = QPushButton("Exporter en PDF")
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.export_btn.clicked.connect(self.export_pdf)
        config_layout.addWidget(self.export_btn)

        config_scroll.setWidget(config_widget)
        splitter.addWidget(config_scroll)

        # Panneau des résultats (droite)
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)

        # En-tête avec titre et filtres
        header_layout = QHBoxLayout()

        results_label = QLabel("Résultats du scan")
        results_label.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(results_label)

        header_layout.addStretch()

        # Groupe de filtres
        filter_label = QLabel("Filtrer:")
        header_layout.addWidget(filter_label)

        self.filter_group = QButtonGroup(self)

        self.filter_all_rb = QRadioButton("Tous")
        self.filter_all_rb.setChecked(True)
        self.filter_all_rb.toggled.connect(lambda checked: checked and self.apply_filter(self.FILTER_ALL))
        self.filter_group.addButton(self.filter_all_rb)
        header_layout.addWidget(self.filter_all_rb)

        self.filter_open_rb = QRadioButton("Ouverts")
        self.filter_open_rb.setStyleSheet("color: green;")
        self.filter_open_rb.toggled.connect(lambda checked: checked and self.apply_filter(self.FILTER_OPEN))
        self.filter_group.addButton(self.filter_open_rb)
        header_layout.addWidget(self.filter_open_rb)

        self.filter_closed_rb = QRadioButton("Fermés")
        self.filter_closed_rb.setStyleSheet("color: red;")
        self.filter_closed_rb.toggled.connect(lambda checked: checked and self.apply_filter(self.FILTER_CLOSED))
        self.filter_group.addButton(self.filter_closed_rb)
        header_layout.addWidget(self.filter_closed_rb)

        results_layout.addLayout(header_layout)

        # Tableau des résultats
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Adresse IP", "Port", "Service", "Statut", "Temps (ms)"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d0d0d0;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        results_layout.addWidget(self.results_table)

        # Statistiques
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.StyledPanel)
        stats_layout = QHBoxLayout(stats_frame)

        self.stats_total = QLabel("Total: 0")
        self.stats_open = QLabel("Ouverts: 0")
        self.stats_open.setStyleSheet("color: green; font-weight: bold;")
        self.stats_closed = QLabel("Fermés: 0")
        self.stats_closed.setStyleSheet("color: red; font-weight: bold;")
        self.stats_filtered = QLabel("Affichés: 0")
        self.stats_filtered.setStyleSheet("color: #2196F3; font-weight: bold;")

        stats_layout.addWidget(self.stats_total)
        stats_layout.addWidget(self.stats_open)
        stats_layout.addWidget(self.stats_closed)
        stats_layout.addWidget(self.stats_filtered)
        stats_layout.addStretch()

        results_layout.addWidget(stats_frame)

        splitter.addWidget(results_widget)
        splitter.setSizes([400, 700])

    def create_profiles_group(self) -> QGroupBox:
        """Crée le groupe de gestion des profils"""
        group = QGroupBox("Profils de configuration")
        layout = QVBoxLayout()

        # Sélection du profil
        profile_select_layout = QHBoxLayout()
        profile_select_layout.addWidget(QLabel("Profil:"))

        self.profile_combo = QComboBox()
        self.update_profile_combo()
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)
        profile_select_layout.addWidget(self.profile_combo, 1)

        # Bouton menu pour les actions sur les profils
        self.profile_menu_btn = QToolButton()
        self.profile_menu_btn.setText("...")
        self.profile_menu_btn.setPopupMode(QToolButton.InstantPopup)

        profile_menu = QMenu(self.profile_menu_btn)

        load_action = QAction("Charger le profil", self)
        load_action.triggered.connect(self.load_selected_profile)
        profile_menu.addAction(load_action)

        save_action = QAction("Sauvegarder comme nouveau profil", self)
        save_action.triggered.connect(self.save_new_profile)
        profile_menu.addAction(save_action)

        update_action = QAction("Mettre à jour le profil actuel", self)
        update_action.triggered.connect(self.update_current_profile)
        profile_menu.addAction(update_action)

        profile_menu.addSeparator()

        delete_action = QAction("Supprimer le profil", self)
        delete_action.triggered.connect(self.delete_profile)
        profile_menu.addAction(delete_action)

        profile_menu.addSeparator()

        reload_action = QAction("Recharger les profils", self)
        reload_action.triggered.connect(self.reload_profiles)
        profile_menu.addAction(reload_action)

        open_folder_action = QAction("Ouvrir le dossier des profils", self)
        open_folder_action.triggered.connect(self.open_profiles_folder)
        profile_menu.addAction(open_folder_action)

        self.profile_menu_btn.setMenu(profile_menu)
        profile_select_layout.addWidget(self.profile_menu_btn)

        layout.addLayout(profile_select_layout)

        # Bouton de chargement rapide
        self.load_profile_btn = QPushButton("Charger le profil sélectionné")
        self.load_profile_btn.clicked.connect(self.load_selected_profile)
        layout.addWidget(self.load_profile_btn)

        group.setLayout(layout)
        return group

    def create_ip_group(self) -> QGroupBox:
        """Crée le groupe de configuration des IPs"""
        group = QGroupBox("Adresses IP cibles")
        layout = QVBoxLayout()

        # Champ IP unique
        ip_single_layout = QHBoxLayout()
        ip_single_layout.addWidget(QLabel("IP unique:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("ex: 192.168.1.1")
        ip_single_layout.addWidget(self.ip_input)
        self.add_ip_btn = QPushButton("+")
        self.add_ip_btn.setFixedWidth(30)
        self.add_ip_btn.clicked.connect(self.add_single_ip)
        ip_single_layout.addWidget(self.add_ip_btn)
        layout.addLayout(ip_single_layout)

        # Champ plage IP
        ip_range_layout = QHBoxLayout()
        ip_range_layout.addWidget(QLabel("Plage IP:"))
        self.ip_range_start = QLineEdit()
        self.ip_range_start.setPlaceholderText("192.168.1.1")
        ip_range_layout.addWidget(self.ip_range_start)
        ip_range_layout.addWidget(QLabel("-"))
        self.ip_range_end = QLineEdit()
        self.ip_range_end.setPlaceholderText("192.168.1.254")
        ip_range_layout.addWidget(self.ip_range_end)
        self.add_range_btn = QPushButton("+")
        self.add_range_btn.setFixedWidth(30)
        self.add_range_btn.clicked.connect(self.add_ip_range)
        ip_range_layout.addWidget(self.add_range_btn)
        layout.addLayout(ip_range_layout)

        # CIDR
        cidr_layout = QHBoxLayout()
        cidr_layout.addWidget(QLabel("CIDR:"))
        self.cidr_input = QLineEdit()
        self.cidr_input.setPlaceholderText("ex: 192.168.1.0/24")
        cidr_layout.addWidget(self.cidr_input)
        self.add_cidr_btn = QPushButton("+")
        self.add_cidr_btn.setFixedWidth(30)
        self.add_cidr_btn.clicked.connect(self.add_cidr)
        cidr_layout.addWidget(self.add_cidr_btn)
        layout.addLayout(cidr_layout)

        # Liste des IPs avec scroll
        layout.addWidget(QLabel("IPs à scanner:"))
        self.ip_list = QListWidget()
        self.ip_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ip_list.setMinimumHeight(80)
        self.ip_list.setMaximumHeight(120)
        layout.addWidget(self.ip_list)

        # Boutons de gestion
        ip_btns_layout = QHBoxLayout()
        self.remove_ip_btn = QPushButton("Supprimer")
        self.remove_ip_btn.clicked.connect(self.remove_selected_ips)
        ip_btns_layout.addWidget(self.remove_ip_btn)

        self.clear_ips_btn = QPushButton("Tout effacer")
        self.clear_ips_btn.clicked.connect(lambda: self.ip_list.clear())
        ip_btns_layout.addWidget(self.clear_ips_btn)
        layout.addLayout(ip_btns_layout)

        group.setLayout(layout)
        return group

    def create_ports_group(self) -> QGroupBox:
        """Crée le groupe de configuration des ports"""
        group = QGroupBox("Ports à tester")
        layout = QVBoxLayout()

        # Ports prédéfinis dans un scroll area
        ports_scroll = QScrollArea()
        ports_scroll.setWidgetResizable(True)
        ports_scroll.setMaximumHeight(150)
        ports_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        ports_widget = QWidget()
        ports_grid = QGridLayout(ports_widget)
        ports_grid.setSpacing(2)

        self.port_checkboxes = {}
        row, col = 0, 0
        for port, service in COMMON_PORTS.items():
            cb = QCheckBox(f"{port} ({service})")
            cb.setChecked(True)
            self.port_checkboxes[port] = cb
            ports_grid.addWidget(cb, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1

        ports_scroll.setWidget(ports_widget)
        layout.addWidget(ports_scroll)

        # Boutons tout sélectionner / désélectionner
        select_btns_layout = QHBoxLayout()
        select_all_btn = QPushButton("Tout")
        select_all_btn.clicked.connect(lambda: self.select_all_ports(True))
        deselect_all_btn = QPushButton("Aucun")
        deselect_all_btn.clicked.connect(lambda: self.select_all_ports(False))
        select_btns_layout.addWidget(select_all_btn)
        select_btns_layout.addWidget(deselect_all_btn)
        layout.addLayout(select_btns_layout)

        # Port personnalisé
        custom_layout = QHBoxLayout()
        custom_layout.addWidget(QLabel("Port:"))
        self.custom_port_input = QSpinBox()
        self.custom_port_input.setRange(1, 65535)
        self.custom_port_input.setValue(8080)
        custom_layout.addWidget(self.custom_port_input)
        self.add_port_btn = QPushButton("Ajouter")
        self.add_port_btn.clicked.connect(self.add_custom_port)
        custom_layout.addWidget(self.add_port_btn)
        layout.addLayout(custom_layout)

        # Liste des ports personnalisés
        self.custom_ports_list = QListWidget()
        self.custom_ports_list.setMaximumHeight(50)
        self.custom_ports_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.custom_ports_list)

        self.remove_port_btn = QPushButton("Supprimer ports personnalisés")
        self.remove_port_btn.clicked.connect(self.remove_custom_ports)
        layout.addWidget(self.remove_port_btn)

        group.setLayout(layout)
        return group

    def create_options_group(self) -> QGroupBox:
        """Crée le groupe d'options"""
        group = QGroupBox("Options de scan")
        layout = QGridLayout()

        # Timeout
        layout.addWidget(QLabel("Timeout (sec):"), 0, 0)
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setValue(2)
        layout.addWidget(self.timeout_input, 0, 1)

        # Threads
        layout.addWidget(QLabel("Threads:"), 1, 0)
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 100)
        self.threads_input.setValue(20)
        layout.addWidget(self.threads_input, 1, 1)

        # IP source
        layout.addWidget(QLabel("IP source:"), 2, 0)
        self.source_ip_label = QLabel(get_local_ip())
        self.source_ip_label.setStyleSheet("font-weight: bold; color: #2196F3;")
        layout.addWidget(self.source_ip_label, 2, 1)

        group.setLayout(layout)
        return group

    def update_profile_combo(self):
        """Met à jour la liste déroulante des profils"""
        current = self.profile_combo.currentText()
        self.profile_combo.clear()
        self.profile_combo.addItem("-- Sélectionner un profil --")

        default_names = get_default_profile_names()

        # Profils par défaut
        for name in self.profiles:
            if name in default_names:
                self.profile_combo.addItem(f"[Défaut] {name}")

        # Profils personnalisés
        for name in self.profiles:
            if name not in default_names:
                self.profile_combo.addItem(f"[Perso] {name}")

        # Restaurer la sélection si possible
        idx = self.profile_combo.findText(current)
        if idx >= 0:
            self.profile_combo.setCurrentIndex(idx)

    def on_profile_changed(self, text: str):
        """Appelé quand un profil est sélectionné"""
        pass  # Action sur double-clic ou bouton charger

    def get_profile_name_from_combo(self) -> Optional[str]:
        """Extrait le nom du profil depuis le combo"""
        text = self.profile_combo.currentText()
        if text.startswith("[Défaut] "):
            return text[9:]
        elif text.startswith("[Perso] "):
            return text[8:]
        return None

    def load_selected_profile(self):
        """Charge le profil sélectionné"""
        name = self.get_profile_name_from_combo()
        if not name or name not in self.profiles:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un profil valide.")
            return

        profile = self.profiles[name]

        # Charger les ports
        self.select_all_ports(False)
        self.custom_ports_list.clear()

        for port in profile.ports:
            if port in self.port_checkboxes:
                self.port_checkboxes[port].setChecked(True)
            else:
                service = get_service_name(port)
                self.custom_ports_list.addItem(f"{port} ({service})")

        # Charger les IPs
        self.ip_list.clear()
        for ip in profile.ips:
            self.ip_list.addItem(ip)

        # Charger les options
        self.timeout_input.setValue(profile.timeout)
        self.threads_input.setValue(profile.threads)

        self.status_label.setText(f"Profil '{name}' chargé")

    def save_new_profile(self):
        """Sauvegarde la configuration actuelle comme nouveau profil"""
        name, ok = QInputDialog.getText(
            self, "Nouveau profil",
            "Nom du profil:"
        )

        if not ok or not name.strip():
            return

        name = name.strip()
        default_names = get_default_profile_names()

        if name in default_names:
            QMessageBox.warning(
                self, "Erreur",
                "Impossible d'utiliser le nom d'un profil par défaut.\n"
                "Choisissez un autre nom."
            )
            return

        profile = Profile(
            name=name,
            ports=self.get_selected_ports(),
            ips=self.get_target_ips(),
            timeout=self.timeout_input.value(),
            threads=self.threads_input.value()
        )

        # Sauvegarder dans un fichier .profil
        if save_profile_to_file(profile, is_default=False):
            self.profiles[name] = profile
            self.update_profile_combo()

            # Sélectionner le nouveau profil
            idx = self.profile_combo.findText(f"[Perso] {name}")
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)

            profiles_dir = get_profiles_dir()
            filename = sanitize_filename(name) + ".profil"
            QMessageBox.information(
                self, "Succès",
                f"Profil '{name}' sauvegardé.\n\n"
                f"Fichier: {os.path.join(profiles_dir, filename)}"
            )
        else:
            QMessageBox.critical(self, "Erreur", "Impossible de sauvegarder le profil.")

    def update_current_profile(self):
        """Met à jour le profil actuellement sélectionné"""
        name = self.get_profile_name_from_combo()
        default_names = get_default_profile_names()

        if not name:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un profil.")
            return

        if name in default_names:
            QMessageBox.warning(
                self, "Erreur",
                "Impossible de modifier un profil par défaut.\n"
                "Utilisez 'Sauvegarder comme nouveau profil'."
            )
            return

        profile = Profile(
            name=name,
            ports=self.get_selected_ports(),
            ips=self.get_target_ips(),
            timeout=self.timeout_input.value(),
            threads=self.threads_input.value()
        )

        # Sauvegarder dans le fichier .profil
        if save_profile_to_file(profile, is_default=False):
            self.profiles[name] = profile
            QMessageBox.information(self, "Succès", f"Profil '{name}' mis à jour.")
        else:
            QMessageBox.critical(self, "Erreur", "Impossible de mettre à jour le profil.")

    def delete_profile(self):
        """Supprime le profil sélectionné"""
        name = self.get_profile_name_from_combo()
        default_names = get_default_profile_names()

        if not name:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un profil.")
            return

        if name in default_names:
            QMessageBox.warning(
                self, "Erreur",
                "Impossible de supprimer un profil par défaut."
            )
            return

        reply = QMessageBox.question(
            self, "Confirmation",
            f"Supprimer le profil '{name}' et son fichier ?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Supprimer le fichier .profil
            if delete_profile_file(name):
                del self.profiles[name]
                self.update_profile_combo()
                QMessageBox.information(self, "Succès", f"Profil '{name}' supprimé.")
            else:
                QMessageBox.critical(self, "Erreur", "Impossible de supprimer le fichier du profil.")

    def reload_profiles(self):
        """Recharge tous les profils depuis les fichiers .profil"""
        self.profiles = load_profiles()
        self.update_profile_combo()
        self.status_label.setText(f"Profils rechargés ({len(self.profiles)} profils)")

    def open_profiles_folder(self):
        """Ouvre le dossier des profils dans l'explorateur de fichiers"""
        import subprocess
        import platform

        profiles_dir = get_profiles_dir()
        os.makedirs(profiles_dir, exist_ok=True)

        system = platform.system()
        try:
            if system == "Darwin":  # macOS
                subprocess.run(["open", profiles_dir])
            elif system == "Windows":
                subprocess.run(["explorer", profiles_dir])
            else:  # Linux
                subprocess.run(["xdg-open", profiles_dir])
        except Exception as e:
            QMessageBox.information(
                self, "Dossier des profils",
                f"Chemin du dossier:\n{profiles_dir}"
            )

    def add_single_ip(self):
        """Ajoute une IP unique à la liste"""
        ip = self.ip_input.text().strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
                if not self.ip_exists(ip):
                    self.ip_list.addItem(ip)
                self.ip_input.clear()
            except ValueError:
                QMessageBox.warning(self, "Erreur", f"Adresse IP invalide: {ip}")

    def add_ip_range(self):
        """Ajoute une plage d'IPs"""
        start = self.ip_range_start.text().strip()
        end = self.ip_range_end.text().strip()

        try:
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)

            if start_ip > end_ip:
                start_ip, end_ip = end_ip, start_ip

            count = int(end_ip) - int(start_ip) + 1
            if count > 256:
                reply = QMessageBox.question(
                    self, "Confirmation",
                    f"Vous allez ajouter {count} adresses IP. Continuer?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            current = start_ip
            while current <= end_ip:
                ip_str = str(current)
                if not self.ip_exists(ip_str):
                    self.ip_list.addItem(ip_str)
                current = ipaddress.ip_address(int(current) + 1)

            self.ip_range_start.clear()
            self.ip_range_end.clear()

        except ValueError as e:
            QMessageBox.warning(self, "Erreur", f"Plage IP invalide: {e}")

    def add_cidr(self):
        """Ajoute des IPs depuis une notation CIDR"""
        cidr = self.cidr_input.text().strip()

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())

            if len(hosts) > 256:
                reply = QMessageBox.question(
                    self, "Confirmation",
                    f"Vous allez ajouter {len(hosts)} adresses IP. Continuer?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            for host in hosts:
                ip_str = str(host)
                if not self.ip_exists(ip_str):
                    self.ip_list.addItem(ip_str)

            self.cidr_input.clear()

        except ValueError as e:
            QMessageBox.warning(self, "Erreur", f"CIDR invalide: {e}")

    def ip_exists(self, ip: str) -> bool:
        """Vérifie si une IP est déjà dans la liste"""
        for i in range(self.ip_list.count()):
            if self.ip_list.item(i).text() == ip:
                return True
        return False

    def remove_selected_ips(self):
        """Supprime les IPs sélectionnées"""
        for item in self.ip_list.selectedItems():
            self.ip_list.takeItem(self.ip_list.row(item))

    def select_all_ports(self, select: bool):
        """Sélectionne ou désélectionne tous les ports"""
        for cb in self.port_checkboxes.values():
            cb.setChecked(select)

    def add_custom_port(self):
        """Ajoute un port personnalisé"""
        port = self.custom_port_input.value()

        # Vérifier si déjà dans les ports communs
        if port in self.port_checkboxes:
            self.port_checkboxes[port].setChecked(True)
            return

        # Vérifier si déjà dans la liste personnalisée
        for i in range(self.custom_ports_list.count()):
            if int(self.custom_ports_list.item(i).text().split()[0]) == port:
                return

        service = get_service_name(port)
        self.custom_ports_list.addItem(f"{port} ({service})")

    def remove_custom_ports(self):
        """Supprime les ports personnalisés sélectionnés"""
        for item in self.custom_ports_list.selectedItems():
            self.custom_ports_list.takeItem(self.custom_ports_list.row(item))

    def get_selected_ports(self) -> List[int]:
        """Retourne la liste des ports sélectionnés"""
        ports = []

        # Ports communs cochés
        for port, cb in self.port_checkboxes.items():
            if cb.isChecked():
                ports.append(port)

        # Ports personnalisés
        for i in range(self.custom_ports_list.count()):
            port_text = self.custom_ports_list.item(i).text()
            port = int(port_text.split()[0])
            if port not in ports:
                ports.append(port)

        return sorted(ports)

    def get_target_ips(self) -> List[str]:
        """Retourne la liste des IPs cibles"""
        ips = []
        for i in range(self.ip_list.count()):
            ips.append(self.ip_list.item(i).text())
        return ips

    def apply_filter(self, filter_type: str):
        """Applique un filtre sur les résultats affichés"""
        self.current_filter = filter_type
        self.refresh_results_table()

    def get_filtered_results(self) -> List[ScanResult]:
        """Retourne les résultats filtrés selon le filtre actuel"""
        if self.current_filter == self.FILTER_ALL:
            return self.scan_results
        elif self.current_filter == self.FILTER_OPEN:
            return [r for r in self.scan_results if r.is_open]
        elif self.current_filter == self.FILTER_CLOSED:
            return [r for r in self.scan_results if not r.is_open]
        return self.scan_results

    def refresh_results_table(self):
        """Rafraîchit le tableau avec les résultats filtrés"""
        self.results_table.setRowCount(0)

        filtered = self.get_filtered_results()
        sorted_results = sorted(filtered, key=lambda r: (r.ip, r.port))

        for result in sorted_results:
            self.add_result_row(result)

        self.update_stats()

    def add_result_row(self, result: ScanResult):
        """Ajoute une ligne au tableau des résultats"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        # IP
        ip_item = QTableWidgetItem(result.ip)
        self.results_table.setItem(row, 0, ip_item)

        # Port
        port_item = QTableWidgetItem(str(result.port))
        port_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 1, port_item)

        # Service
        service_item = QTableWidgetItem(result.service)
        self.results_table.setItem(row, 2, service_item)

        # Statut
        status_item = QTableWidgetItem("OUVERT" if result.is_open else "FERMÉ")
        status_item.setTextAlignment(Qt.AlignCenter)
        if result.is_open:
            status_item.setBackground(QColor("#c8e6c9"))
            status_item.setForeground(QColor("#2e7d32"))
        else:
            status_item.setBackground(QColor("#ffcdd2"))
            status_item.setForeground(QColor("#c62828"))
        self.results_table.setItem(row, 3, status_item)

        # Temps de réponse
        time_str = f"{result.response_time:.1f}" if result.response_time else "-"
        time_item = QTableWidgetItem(time_str)
        time_item.setTextAlignment(Qt.AlignCenter)
        self.results_table.setItem(row, 4, time_item)

    def start_scan(self):
        """Démarre le scan"""
        ips = self.get_target_ips()
        ports = self.get_selected_ports()

        if not ips:
            QMessageBox.warning(self, "Erreur", "Veuillez ajouter au moins une adresse IP.")
            return

        if not ports:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner au moins un port.")
            return

        # Réinitialiser
        self.results_table.setRowCount(0)
        self.scan_results.clear()
        self.progress_bar.setValue(0)
        self.current_filter = self.FILTER_ALL
        self.filter_all_rb.setChecked(True)
        self.update_stats()

        # Désactiver les boutons
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)

        # Démarrer le worker
        timeout = self.timeout_input.value()
        threads = self.threads_input.value()

        self.worker = ScanWorker(ips, ports, timeout, threads)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.result_ready.connect(self.on_result_ready)
        self.worker.scan_complete.connect(self.scan_finished)
        self.worker.status_update.connect(self.status_label.setText)
        self.worker.start()

    def on_result_ready(self, result: ScanResult):
        """Appelé quand un résultat est prêt"""
        self.scan_results.append(result)

        # Ajouter au tableau si correspond au filtre
        if self.current_filter == self.FILTER_ALL:
            self.add_result_row(result)
        elif self.current_filter == self.FILTER_OPEN and result.is_open:
            self.add_result_row(result)
        elif self.current_filter == self.FILTER_CLOSED and not result.is_open:
            self.add_result_row(result)

        self.update_stats()

    def stop_scan(self):
        """Arrête le scan en cours"""
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Arrêt en cours...")

    def update_stats(self):
        """Met à jour les statistiques"""
        total = len(self.scan_results)
        open_ports = sum(1 for r in self.scan_results if r.is_open)
        closed_ports = total - open_ports
        filtered = len(self.get_filtered_results())

        self.stats_total.setText(f"Total: {total}")
        self.stats_open.setText(f"Ouverts: {open_ports}")
        self.stats_closed.setText(f"Fermés: {closed_ports}")
        self.stats_filtered.setText(f"Affichés: {filtered}")

    def scan_finished(self):
        """Appelé quand le scan est terminé"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(len(self.scan_results) > 0)
        self.status_label.setText("Scan terminé")
        self.progress_bar.setValue(100)

    def export_pdf(self):
        """Exporte les résultats en PDF"""
        if not self.scan_results:
            QMessageBox.warning(self, "Erreur", "Aucun résultat à exporter.")
            return

        # Demander quel filtre appliquer à l'export
        filter_options = ["Tous les résultats", "Ports ouverts uniquement", "Ports fermés uniquement"]
        current_idx = 0
        if self.current_filter == self.FILTER_OPEN:
            current_idx = 1
        elif self.current_filter == self.FILTER_CLOSED:
            current_idx = 2

        choice, ok = QInputDialog.getItem(
            self, "Export PDF",
            "Quels résultats exporter ?",
            filter_options, current_idx, False
        )

        if not ok:
            return

        # Déterminer le filtre pour l'export
        if choice == filter_options[0]:
            export_filter = self.FILTER_ALL
        elif choice == filter_options[1]:
            export_filter = self.FILTER_OPEN
        else:
            export_filter = self.FILTER_CLOSED

        filename, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le rapport PDF",
            f"rapport_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF Files (*.pdf)"
        )

        if not filename:
            return

        try:
            self.generate_pdf_report(filename, export_filter)
            QMessageBox.information(
                self, "Succès",
                f"Rapport exporté avec succès:\n{filename}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export: {e}")

    def generate_pdf_report(self, filename: str, export_filter: str):
        """Génère le rapport PDF"""
        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=30
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20
        )

        normal_style = styles['Normal']

        elements = []

        # Titre
        elements.append(Paragraph("Rapport de Scan de Ports", title_style))
        elements.append(Spacer(1, 20))

        # Informations générales
        elements.append(Paragraph("Informations générales", heading_style))

        scan_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        source_ip = get_local_ip()

        # Texte du filtre
        filter_text = "Tous"
        if export_filter == self.FILTER_OPEN:
            filter_text = "Ports ouverts uniquement"
        elif export_filter == self.FILTER_CLOSED:
            filter_text = "Ports fermés uniquement"

        info_data = [
            ["Date du scan:", scan_time],
            ["IP source:", source_ip],
            ["Timeout:", f"{self.timeout_input.value()} secondes"],
            ["Threads:", str(self.threads_input.value())],
            ["Filtre appliqué:", filter_text]
        ]

        info_table = Table(info_data, colWidths=[4*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(info_table)

        # IPs testées
        elements.append(Paragraph("Adresses IP testées", heading_style))

        tested_ips = sorted(set(r.ip for r in self.scan_results))
        ip_text = ", ".join(tested_ips)
        elements.append(Paragraph(ip_text, normal_style))

        # Ports testés
        elements.append(Paragraph("Ports testés", heading_style))

        tested_ports = sorted(set(r.port for r in self.scan_results))
        ports_text = ", ".join(str(p) for p in tested_ports)
        elements.append(Paragraph(ports_text, normal_style))

        # Statistiques
        elements.append(Paragraph("Statistiques", heading_style))

        total = len(self.scan_results)
        open_count = sum(1 for r in self.scan_results if r.is_open)
        closed_count = total - open_count

        # Résultats filtrés pour l'export
        if export_filter == self.FILTER_ALL:
            filtered_results = self.scan_results
        elif export_filter == self.FILTER_OPEN:
            filtered_results = [r for r in self.scan_results if r.is_open]
        else:
            filtered_results = [r for r in self.scan_results if not r.is_open]

        stats_data = [
            ["Total de tests:", str(total)],
            ["Ports ouverts:", str(open_count)],
            ["Ports fermés:", str(closed_count)],
            ["Résultats exportés:", str(len(filtered_results))]
        ]

        stats_table = Table(stats_data, colWidths=[4*cm, 10*cm])
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(stats_table)

        # Résultats détaillés
        elements.append(Paragraph("Résultats détaillés", heading_style))

        # En-tête du tableau
        table_data = [["IP", "Port", "Service", "Statut", "Temps (ms)"]]

        # Trier les résultats par IP puis par port
        sorted_results = sorted(filtered_results, key=lambda r: (r.ip, r.port))

        for result in sorted_results:
            status = "OUVERT" if result.is_open else "FERMÉ"
            time_str = f"{result.response_time:.1f}" if result.response_time else "-"
            table_data.append([
                result.ip,
                str(result.port),
                result.service,
                status,
                time_str
            ])

        results_table = Table(table_data, colWidths=[3.5*cm, 1.5*cm, 3*cm, 2*cm, 2*cm])

        # Style du tableau
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), rl_colors.HexColor('#2196F3')),
            ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, rl_colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]

        # Colorer les lignes selon le statut
        for i, result in enumerate(sorted_results, start=1):
            if result.is_open:
                table_style.append(('BACKGROUND', (3, i), (3, i), rl_colors.HexColor('#c8e6c9')))
                table_style.append(('TEXTCOLOR', (3, i), (3, i), rl_colors.HexColor('#2e7d32')))
            else:
                table_style.append(('BACKGROUND', (3, i), (3, i), rl_colors.HexColor('#ffcdd2')))
                table_style.append(('TEXTCOLOR', (3, i), (3, i), rl_colors.HexColor('#c62828')))

        results_table.setStyle(TableStyle(table_style))
        elements.append(results_table)

        # Générer le PDF
        doc.build(elements)




# =============================================================================
# MODE GUI
# =============================================================================

def run_gui():
    """Execute le mode GUI"""
    if not GUI_AVAILABLE:
        print("[ERREUR] PyQt5 non disponible.", file=sys.stderr)
        print("Installez avec: pip install PyQt5", file=sys.stderr)
        print("Ou utilisez le mode CLI: python port_scanner.py --cli --help", file=sys.stderr)
        return 1

    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Style global
    app.setStyleSheet("""
        QGroupBox {
            font-weight: bold;
            border: 1px solid #cccccc;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QLineEdit, QSpinBox, QComboBox {
            padding: 5px;
            border: 1px solid #cccccc;
            border-radius: 3px;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
            border-color: #2196F3;
        }
        QPushButton {
            padding: 5px 10px;
        }
        QListWidget {
            border: 1px solid #cccccc;
            border-radius: 3px;
        }
        QScrollArea {
            border: none;
        }
    """)

    window = PortScannerApp()
    window.show()

    return app.exec_()


def main():
    """Point d'entrée principal"""
    if CLI_MODE:
        sys.exit(run_cli())
    else:
        sys.exit(run_gui())


if __name__ == "__main__":
    main()
