# Port Scanner

Outil de scan de ports reseau avec interface graphique (PyQt5) et mode ligne de commande (CLI).

## Fonctionnalites

- **Double interface** : GUI moderne ou CLI pour automatisation/scripts
- **Formats IP flexibles** : IP unique, liste, plage (range), notation CIDR
- **Profils de configuration** : Sauvegarde et rechargement de configurations
- **Multi-thread** : Scan parallele pour de meilleures performances
- **Export** : JSON, CSV, TXT et PDF
- **Filtrage des resultats** : Tous / Ouverts / Fermes

## Installation

### Dependances requises

```bash
# Interface graphique (optionnel si CLI uniquement)
pip install PyQt5

# Export PDF (optionnel)
pip install reportlab
```

### Clonage du depot

```bash
git clone https://github.com/adminstuff/checkPorts.git
cd checkPorts
```

## Utilisation

### Mode graphique (GUI)

```bash
python port_scanner.py
```

L'interface permet de :
- Saisir les cibles dans un champ unique (detection automatique du format)
- Selectionner les ports a scanner
- Configurer le timeout et le nombre de threads
- Filtrer et exporter les resultats

### Mode ligne de commande (CLI)

```bash
python port_scanner.py --cli [options]
```

#### Options disponibles

| Option | Description |
|--------|-------------|
| `-c, --cli` | Active le mode ligne de commande |
| `-v, --version` | Affiche la version |
| `-i, --ip` | Adresse(s) IP cible(s) |
| `-p, --ports` | Port(s) a scanner |
| `-P, --profile` | Nom du profil a utiliser |
| `-t, --timeout` | Timeout en secondes (defaut: 2) |
| `-T, --threads` | Nombre de threads (defaut: 20) |
| `-o, --output` | Fichier de sortie (.json, .csv, .txt, .pdf) |
| `--only-open` | Exporter uniquement les ports ouverts |
| `--show-closed` | Afficher les ports fermes pendant le scan |
| `-q, --quiet` | Mode silencieux |
| `-l, --list-profiles` | Lister les profils disponibles |

#### Formats d'adresses IP supportes

| Format | Exemple | Description |
|--------|---------|-------------|
| IP unique | `192.168.1.1` | Une seule adresse |
| Liste | `192.168.1.1,192.168.1.5,10.0.0.1` | Plusieurs IPs separees par virgule |
| Plage | `192.168.1.1-192.168.1.254` | Toutes les IPs de la plage |
| Plage courte | `192.168.1.1-254` | Format raccourci |
| CIDR | `192.168.1.0/24` | Notation reseau |
| Mixte | `192.168.1.1,10.0.0.0/24` | Combinaison de formats |

#### Formats de ports supportes

| Format | Exemple | Description |
|--------|---------|-------------|
| Port unique | `80` | Un seul port |
| Liste | `22,80,443` | Plusieurs ports |
| Plage | `80-443` | Tous les ports de la plage |
| Mixte | `22,80-90,443` | Combinaison |

### Exemples

```bash
# Scan simple
python port_scanner.py --cli --ip 192.168.1.1 --ports 22,80,443

# Scan d'une plage avec profil
python port_scanner.py --cli --ip 192.168.1.1-254 --profile "Web Standard"

# Scan CIDR avec export JSON
python port_scanner.py --cli --ip 10.0.0.0/24 --ports 22,80 --output scan.json

# Scan silencieux avec export PDF (ports ouverts uniquement)
python port_scanner.py --cli -q --ip 192.168.1.0/24 --profile "Administration" \
    --output rapport.pdf --only-open

# Lister les profils
python port_scanner.py --cli --list-profiles

# Afficher la version
python port_scanner.py --version
```

## Profils

Les profils sont stockes dans le dossier `profiles/` au format `.profil` (fichiers texte editables).

### Profils par defaut

| Profil | Ports |
|--------|-------|
| Web Standard | 80, 443, 8080, 8443 |
| Services Mail | 25, 110, 143, 465, 587, 993, 995 |
| Administration | 22, 23, 3389, 5900 |
| Base de donnees | 3306, 5432, 1433, 1521, 27017, 6379 |
| Transfert fichiers | 20, 21, 22, 69, 115, 445 |
| Tous ports communs | Tous les ports standards |

### Format des fichiers profil

```ini
# Fichier de profil Port Scanner
name = Mon Profil

# Ports a scanner
ports = 22, 80, 443, 8080

# IPs cibles (optionnel)
ips = 192.168.1.1, 192.168.1.2

# Configuration
timeout = 2
threads = 20
```

## Codes de retour (CLI)

| Code | Signification |
|------|---------------|
| 0 | Succes - ports ouverts trouves |
| 1 | Erreur (arguments invalides, profil non trouve, etc.) |
| 2 | Succes - aucun port ouvert trouve |

## Licence

Ce projet est distribue sous licence MIT.

## Contribution

Les contributions sont les bienvenues ! N'hesitez pas a ouvrir une issue ou une pull request.
