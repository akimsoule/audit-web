# =============================================================================
# CONSTANTES GLOBALES
# =============================================================================

# Nom du conteneur Docker Kali Linux dédié à l'audit
CONTAINER_NAME="kali_audit_web"

# Image Docker Kali officielle
KALI_IMAGE="kalilinux/kali-rolling"

# Liste des outils à installer dans le conteneur (non destructifs uniquement)
TOOLS="nmap nikto curl dnsutils jq python3"

# Ports de bases de données et d'administration à vérifier (lecture seule)
SENSITIVE_PORTS="22,3306,3389,5432,6379,27017"

# Mode réseau Docker (host sur Linux, bridge sur macOS)
DOCKER_NETWORK="host"

# Fichier de configuration optionnel (surcharge les variables ci-dessus)
CONFIG_FILE="./audit_web.conf"

# Timeout global pour l'ensemble du script (secondes)
# 30 min pour les scans API avancés (Nuclei, ZAP) ; ajusté dynamiquement si AUDIT_API_FREE_URL est défini
GLOBAL_TIMEOUT=1800

# Dossier de sortie des rapports (créé automatiquement sur la machine hôte)
OUTPUT_DIR="./audit_reports"

# Fichiers sensibles courants susceptibles d'être exposés par erreur de config
SENSITIVE_FILES=(
    "/.env"
    "/.env.backup"
    "/.env.local"
    "/.git/config"
    "/.git/HEAD"
    "/backup.sql"
    "/backup.tar.gz"
    "/dump.sql"
    "/db.sql"
    "/wp-config.php.bak"
    "/wp-config.php~"
    "/config.php.bak"
    "/.htpasswd"
    "/web.config.bak"
    "/phpinfo.php"
    "/server-status"
    "/elmah.axd"
    "/.DS_Store"
    "/Thumbs.db"
    "/crossdomain.xml"
)
