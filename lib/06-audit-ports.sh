# =============================================================================
# AUDIT 2 — Ports de services backend / administration exposés
# =============================================================================
# Méthode non destructive : nmap en mode TCP connect scan (-sT).
# On vérifie uniquement si les ports sont OUVERTS, sans tenter de s'y
# connecter ni d'authentifier. Timeout court pour minimiser l'impact.
# =============================================================================

audit_ports_backend() {
    log_section "AUDIT 2 — Ports de services backend / administration exposés"
    log_info "Méthode : nmap scan TCP sur ports ciblés uniquement (sans exploitation)"
    log_info "Ports vérifiés : ${SENSITIVE_PORTS}"
    log_info "Cible : ${TARGET_HOST}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  AUDIT 2 — Ports backend exposés"
    log_report "========================================"
    log_report "Ports vérifiés : ${SENSITIVE_PORTS}"
    log_report "Cible          : ${TARGET_HOST}"
    log_report ""

    local nmap_result
    nmap_result=$(docker exec "${CONTAINER_NAME}" \
        nmap -sT -p "${SENSITIVE_PORTS}" -T3 --open -Pn \
        --host-timeout 30s \
        "${TARGET_HOST}" 2>/dev/null || true)

    echo "$nmap_result"
    log_report "$nmap_result"
    echo ""

    if echo "$nmap_result" | grep -qE "^[0-9]+/tcp\s+open"; then
        log_alert "Des ports de services backend sont ouverts publiquement !"
        log_warn  "Vérifiez que ces services ne sont pas accessibles sans authentification."
        log_report "[ALERTE] Des ports de services backend sont ouverts publiquement !"
        log_report "[AVERT]  Vérifiez que ces services ne sont pas accessibles sans authentification."
        while IFS= read -r line; do
            if [[ "$line" =~ ^[0-9]+/tcp[[:space:]]+open ]]; then
                JSON_OPEN_PORTS+=("$(echo "$line" | awk '{print $1, $2, $3}')")
            fi
        done <<< "$nmap_result"
    else
        log_ok "Aucun port de service backend sensible ouvert publiquement détecté."
        log_report "[OK] Aucun port de service backend sensible ouvert publiquement détecté."
    fi
}
