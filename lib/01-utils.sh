# =============================================================================
# FONCTIONS UTILITAIRES — Couleurs, logs, gestion du rapport texte
# =============================================================================

# ---------------------------------------------------------------------------
# COULEURS POUR LA LISIBILITÉ DU RAPPORT
# ---------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# AFFICHAGE CONSOLE
# ---------------------------------------------------------------------------
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_alert()   { echo -e "${RED}[ALERT]${RESET} $*"; }
log_section() { echo -e "\n${BOLD}========================================${RESET}"; \
                echo -e "${BOLD}  $*${RESET}"; \
                echo -e "${BOLD}========================================${RESET}"; }

# ---------------------------------------------------------------------------
# GESTION DU RAPPORT FICHIER (texte brut, sans codes ANSI)
# ---------------------------------------------------------------------------

# Chemin du fichier rapport — initialisé dans init_rapport()
REPORT_FILE=""

# Écrit une ligne dans le fichier rapport en supprimant les codes couleur ANSI
log_report() {
    echo -e "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "${REPORT_FILE}"
}

# Initialise le dossier et le fichier de rapport pour cette session d'audit
init_rapport() {
    local host_safe
    host_safe=$(echo "${TARGET_HOST}" | tr -cs '[:alnum:].' '_' | tr '.' '_')
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')

    mkdir -p "${OUTPUT_DIR}"

    REPORT_FILE="${OUTPUT_DIR}/audit_${host_safe}_${timestamp}.txt"

    {
        echo "============================================================"
        echo "  RAPPORT D'AUDIT DE SÉCURITÉ WEB — USAGE CONFIDENTIEL"
        echo "============================================================"
        echo "  Cible        : ${TARGET_BASE_URL}"
        echo "  Hôte réseau  : ${TARGET_HOST}"
        echo "  Date / Heure : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  Outil        : audit_web.sh v1.0 — Blue Team / Défense"
        echo "============================================================"
        echo ""
    } >> "${REPORT_FILE}"

    log_info "Rapport d'audit en cours d'écriture → ${REPORT_FILE}"
}

# Affiche un message d'erreur et quitte proprement avec code 1
die() {
    echo -e "${RED}[ERREUR FATALE]${RESET} $*" >&2
    exit 1
}

# Détecte le système d'exploitation pour adapter le mode réseau Docker
detecter_os() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        DOCKER_NETWORK="bridge"
        log_warn "macOS détecté : utilisation du mode réseau 'bridge'"
        log_warn "Les scans réseau (nmap) passent par le réseau Docker, pas le réseau hôte"
    else
        DOCKER_NETWORK="host"
    fi
}

# Nettoie les ressources si le script est interrompu (Ctrl+C, erreur, fin)
nettoyer() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]] && [[ -n "${REPORT_FILE:-}" ]] && [[ -f "$REPORT_FILE" ]]; then
        echo "" >> "${REPORT_FILE}"
        echo "[INTERRUPTION] Script arrêté avec le code ${exit_code}" >> "${REPORT_FILE}"
        echo "Rapport partiellement sauvegardé dans ${REPORT_FILE}"
    fi
}

# ---------------------------------------------------------------------------
# VALIDATION DE L'URL CIBLE
# ---------------------------------------------------------------------------
valider_cible() {
    local url="$1"

    if [[ ! "$url" =~ ^https?:// ]]; then
        die "Format d'URL invalide : '$url'\n" \
            "      Usage : $0 https://exemple.com"
    fi

    TARGET_HOST=$(echo "$url" | sed -E 's|^https?://([^/:]+).*|\1|')
    TARGET_BASE_URL=$(echo "$url" | sed -E 's|(^https?://[^/:]+).*|\1|')

    if [[ -z "$TARGET_HOST" ]]; then
        die "Impossible d'extraire le hostname depuis l'URL : '$url'"
    fi

    log_ok "Cible validée — Host : ${TARGET_HOST} | Base URL : ${TARGET_BASE_URL}"
}
