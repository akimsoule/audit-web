#!/usr/bin/env bash
# =============================================================================
# audit_web.sh — Outil d'audit de sécurité web passif et non destructif
# Auteur  : Blue Team / Défense
# Version : 1.1 (modulaire)
# =============================================================================
# IDEMPOTENCE : Ce script peut être exécuté N fois de suite sans effet de bord :
#   - Le conteneur Docker n'est créé qu'une seule fois.
#   - Les paquets apt ne sont réinstallés que s'ils sont absents.
#   - Aucune action destructive n'est jamais effectuée sur la cible.
# =============================================================================

set -euo pipefail

# Chemins des modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ordre d'import : constantes → utilitaires → config → legal → docker → audits → rapport
source "${SCRIPT_DIR}/lib/00-constants.sh"
source "${SCRIPT_DIR}/lib/01-utils.sh"
source "${SCRIPT_DIR}/lib/08-report.sh"
source "${SCRIPT_DIR}/lib/02-config.sh"
source "${SCRIPT_DIR}/lib/03-legal.sh"
source "${SCRIPT_DIR}/lib/04-docker.sh"
source "${SCRIPT_DIR}/lib/05-audit-files.sh"
source "${SCRIPT_DIR}/lib/06-audit-ports.sh"
source "${SCRIPT_DIR}/lib/07-audit-headers.sh"
source "${SCRIPT_DIR}/lib/09-audit-api.sh"
source "${SCRIPT_DIR}/lib/10-audit-api-free.sh"
source "${SCRIPT_DIR}/lib/11-audit-auth.sh"

# ---------------------------------------------------------------------------
# POINT D'ENTRÉE PRINCIPAL
# ---------------------------------------------------------------------------

main() {
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}Usage :${RESET} $0 <url_cible> [options]"
        echo -e "Exemple : $0 https://www.monsite.com"
        echo ""
        echo -e "Variables d'environnement pour l'audit API :"
        echo -e "  AUDIT_API_URL          URL de l'API à tester (ex: http://localhost:8888)"
        echo -e "  AUDIT_API_TOKEN        Token JWT pour les tests authentifiés"
        echo -e "  AUDIT_API_TOKEN2       Second token JWT (autre utilisateur, pour IDOR)"
        echo -e "  AUDIT_API_PREFIX       Préfixe des routes API (défaut: /api)"
        echo ""
        echo -e "Variables pour l'audit API avancé (Nuclei, ZAP, Arjun, Kiterunner) :"
        echo -e "  AUDIT_API_FREE_URL     URL de l'API à auditer"
        echo -e "  SKIP_ACTIVE_SCAN       1 pour désactiver ZAP (défaut: 1)"
        echo -e "  STAGING_MODE           1 pour activer tous les tests (défaut: 0)"
        echo -e "  NUCLEI_SEVERITY        Filtre sévérité (défaut: critical,high,medium)"
        echo -e "  NUCLEI_TIMEOUT         Timeout Nuclei en secondes (défaut: 300)"
        echo -e "  ZAP_TIMEOUT            Timeout ZAP en secondes (défaut: 600)"
        echo -e "  ARJUN_TIMEOUT          Timeout Arjun en secondes (défaut: 180)"
        echo -e "  GLOBAL_TIMEOUT         Timeout global (défaut: 120, augmenter pour scans API)"
        exit 1
    fi

    local cible="$1"

    trap nettoyer EXIT INT TERM

    afficher_avertissement_legal
    valider_cible "$cible"

    # Définir automatiquement AUDIT_API_FREE_URL depuis la cible si non défini
    if [[ -z "${AUDIT_API_FREE_URL:-}" ]]; then
        export AUDIT_API_FREE_URL="${TARGET_BASE_URL}"
        log_info "AUDIT_API_FREE_URL défini automatiquement : ${TARGET_BASE_URL}"
    fi

    init_rapport
    charger_config
    json_init

    verifier_docker
    gerer_conteneur
    installer_outils

    audit_fichiers_sensibles
    audit_ports_backend
    audit_divulgation_informations

    # Audit API (exfiltration de données) si une URL API est fournie
    if [[ -n "${AUDIT_API_URL:-}" ]]; then
        log_section "AUDIT API — Exfiltration de données"
        API_BASE_URL="${AUDIT_API_URL}"
        API_PATH_PREFIX="${AUDIT_API_PREFIX:-/api}"
        API_ACCESS_TOKEN="${AUDIT_API_TOKEN:-}"
        API_SECOND_USER_TOKEN="${AUDIT_API_TOKEN2:-}"
        audit_api_exfil
    fi

    # Audit API avancé (Nuclei, ZAP, Arjun, Kiterunner) si une URL est fournie
    if [[ -n "${AUDIT_API_FREE_URL:-}" ]]; then
        API_FREE_URL="${AUDIT_API_FREE_URL}"
        API_FREE_TOKEN="${AUDIT_API_TOKEN:-}"
        audit_api_free_exfil
    fi

    # Audit auth (non-destructif) si activé par AUTH_TESTS_ENABLED=1
    audit_auth_security

    json_write_report
    generer_rapport_final
}

# ---------------------------------------------------------------------------
# LANCEMENT — avec timeout global si disponible
# ---------------------------------------------------------------------------
if command -v timeout &>/dev/null && [[ -z "${AUDIT_TIMEOUT_GUARD:-}" ]]; then
    export AUDIT_TIMEOUT_GUARD=1
    timeout "${GLOBAL_TIMEOUT}" bash "$0" "$@"
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        echo -e "${RED}[TIMEOUT GLOBAL]${RESET} Le script a dépassé ${GLOBAL_TIMEOUT}s d'exécution." >&2
    fi
    exit $exit_code
else
    main "$@"
fi
