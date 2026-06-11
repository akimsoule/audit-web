# =============================================================================
# CHARGEMENT DE LA CONFIGURATION EXTERNE (OPTIONNEL)
# =============================================================================
# Si un fichier audit_web.conf existe dans le dossier courant, il est sourcé.
# Cela permet de surcharger SENSITIVE_FILES, SENSITIVE_PORTS, TOOLS, etc.
# sans modifier le script principal.
# =============================================================================

charger_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        log_info "Configuration supplémentaire chargée depuis ${CONFIG_FILE}"
        log_info "Variables surchargées : $(grep -c '^[[:alnum:]_]\+=' "${CONFIG_FILE}") définition(s)"
    fi
}
