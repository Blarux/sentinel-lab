# Sentinel-Lab

Outil professionnel d'audit et de sécurisation système multi-plateforme (Windows / Linux / macOS).
Détecte les ports ouverts à risque, identifie les processus associés, vérifie l'état
du pare-feu et propose des remédiations interactives.

---

## Fonctionnalités

- **Scan réseau** : liste tous les ports en écoute (TCP/UDP) et les processus associés (nom + exécutable).
- **Base de menaces** : comparaison avec une liste de ports à risque (`config/threats.yaml`).
- **Pare-feu** : vérifie l'état du firewall (Windows `netsh` / Linux `ufw`, `firewalld`, `iptables`).
- **Corrélation firewall ↔ scanner** : un port flaggé mais déjà bloqué par une règle `Sentinel-Block-*`
  est automatiquement requalifié en `PROTECTED` (vert).
- **Remédiation interactive** : fermer un port ou tuer un processus après confirmation.
- **Logs rotatifs** : tout est tracé dans `logs/sentinel_audit.log`.
- **CLI stylisée** : interface Rich (tableaux, barres de progression, panneaux colorés).

---

## Prérequis

| Élément | Version minimum |
|---|---|
| Python | 3.10+ |
| Windows | 10 / 11 (droits Administrateur requis) |
| Linux | kernel récent + `ufw` ou `firewalld` ou `iptables` (sudo requis) |
| macOS | 11+ (Big Sur ou plus récent, `pfctl` natif, sudo requis) |
| RAM | 100 MB |

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/<TON_USERNAME>/sentinel-lab.git
cd sentinel-lab
```

### 2. Créer un environnement virtuel (recommandé)

**Windows (PowerShell) :**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS :**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

Dépendances installées :
- `rich` — interface CLI
- `psutil` — énumération réseau et processus
- `PyYAML` — lecture de `threats.yaml`

---

## Utilisation

### Lancement standard

**Windows** (obligatoirement en Administrateur) :
```powershell
# Clic droit sur PowerShell / cmd → "Exécuter en tant qu'administrateur"
python main.py
```

**Linux** :
```bash
sudo python3 main.py
```

**macOS** :
```bash
sudo python3 main.py
```

Le script refuse de tourner sans privilèges élevés (nécessaire pour énumérer les sockets
et interroger le pare-feu).

### Notes spécifiques macOS

- Le pare-feu applicatif (ALF) est lu via `defaults read /Library/Preferences/com.apple.alf globalstate` :
  `0` = off, `1` = on (allow signed), `2` = on (block all).
- Les règles de blocage Sentinel sont appliquées via `pfctl` dans l'anchor `com.sentinel-lab`.
- Pour inspecter manuellement les règles Sentinel :
  ```bash
  sudo pfctl -a com.sentinel-lab -s rules
  ```

### Options CLI

```bash
python main.py [--config PATH] [--no-udp] [--no-interactive] [--debug]
```

| Flag | Description |
|---|---|
| `--config PATH` | Chemin vers un `threats.yaml` alternatif |
| `--no-udp` | Désactive l'énumération UDP (scan plus rapide) |
| `--no-interactive` | Audit seul, sans prompt de remédiation |
| `--debug` | Affiche les détails de parsing firewall et les matchs |
| `--no-admin-check` | Bypass de la vérif admin (**non recommandé**) |

### Exemples

**Audit rapide non-interactif :**
```bash
sudo python3 main.py --no-interactive --no-udp
```

**Debug de la corrélation firewall :**
```bash
python main.py --debug
```

---

## Configuration

Le fichier [`config/threats.yaml`](config/threats.yaml) contient :

- `threat_ports` : ports à flagger (port + protocole + raison)
- `suspicious_ips` : IPs distantes à signaler
- `protected_processes` : processus système jamais tués par la remédiation

Exemple d'ajout :
```yaml
threat_ports:
  - { port: 8080, protocol: tcp, name: "HTTP-Alt", reason: "Non-standard HTTP, souvent exposé par erreur" }
```

---

## Compilation en .exe (Windows)

```bash
pip install pyinstaller
pyinstaller sentinel_lab.spec
```

Résultat : `dist/sentinel-lab.exe`
→ Exécutable autonome avec `uac_admin=True` (demande automatiquement l'élévation).

---

## Arborescence

```
sentinel-lab/
├── main.py                     # Point d'entrée CLI
├── requirements.txt
├── sentinel_lab.spec           # Build PyInstaller
├── config/
│   └── threats.yaml            # Base de menaces
├── core/
│   ├── logger.py               # Logging rotatif
│   └── os_detector.py          # Détection OS + admin check
├── modules/
│   ├── network_scanner.py      # Scan ports + corrélation firewall
│   ├── firewall_manager.py     # Gestion netsh/ufw/firewalld
│   └── remediator.py           # Actions : kill process, block port
└── logs/
    └── sentinel_audit.log      # Créé automatiquement
```

---

## Dépannage

### « ADMIN RIGHTS REQUIRED »
Tu as lancé le script sans élévation. Relance :
- Windows : clic droit sur le terminal → *Exécuter en tant qu'administrateur*
- Linux : `sudo python3 main.py`

### Le scanner détecte des menaces malgré les règles firewall
1. Vérifie que les règles sont nommées `Sentinel-Block-*` (préfixe obligatoire) :
   ```powershell
   netsh advfirewall firewall show rule name=all | findstr Sentinel
   ```
2. Lance avec `--debug` pour voir ce que le parser extrait réellement.
3. Les règles doivent avoir `Enabled: Yes` et `Action: Block`.

### `psutil.AccessDenied` sur certains processus
Normal pour certains processus protégés Windows (System, services). Le scan continue,
les PIDs concernés s'affichent en `unknown`.

### ImportError / ModuleNotFoundError
Assure-toi d'avoir activé le venv et lancé `pip install -r requirements.txt`.

---

## Avertissement

Cet outil modifie la configuration du pare-feu et peut terminer des processus système.
**À utiliser uniquement sur des machines dont tu es propriétaire ou pour lesquelles tu
disposes d'une autorisation explicite.** Revois toujours les règles appliquées avec
`netsh advfirewall firewall show rule name=all` ou `sudo ufw status numbered`.

---

## Licence

MIT — Voir [LICENSE](LICENSE) si fourni.
