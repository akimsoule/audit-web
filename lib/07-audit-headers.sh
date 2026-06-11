# =============================================================================
# AUDIT 3 — Divulgation d'informations serveur
# =============================================================================
# Méthode non destructive : On inspecte les en-têtes HTTP retournés par le
# serveur lors d'une requête normale. Ces informations sont déjà envoyées par
# le serveur à chaque visiteur ; on ne fait que les analyser.
# On utilise aussi nikto en mode très limité (-Tuning b) uniquement pour la
# détection de divulgation de version.
# =============================================================================

audit_divulgation_informations() {
    log_section "AUDIT 3 — Divulgation d'informations serveur"
    log_info "Méthode : Analyse des en-têtes HTTP et bannières serveur"
    log_info "Cible   : ${TARGET_BASE_URL}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  AUDIT 3 — Divulgation d'informations"
    log_report "========================================"
    log_report "Cible : ${TARGET_BASE_URL}"
    log_report ""

    # --- Analyse des en-têtes HTTP via curl ---
    log_info "→ Analyse des en-têtes HTTP :"
    log_report "--- En-têtes HTTP bruts ---"
    local headers
    headers=$(docker exec "${CONTAINER_NAME}" \
        curl -s -I -L -m 10 \
        -A "Mozilla/5.0 (Audit-Defensif/1.0)" \
        "${TARGET_BASE_URL}" 2>/dev/null || true)

    echo "$headers" | head -30
    echo "$headers" | head -30 >> "${REPORT_FILE}"
    echo ""
    log_report ""

    # Détection des en-têtes qui révèlent des informations de version
    local divulgations=0
    log_report "--- En-têtes révélateurs de version ---"
    for header_pattern in "Server:" "X-Powered-By:" "X-AspNet-Version:" \
                          "X-Generator:" "X-Drupal-Cache:" "X-WordPress-"; do
        local valeur
        valeur=$(echo "$headers" | grep -i "^${header_pattern}" || true)
        if [[ -n "$valeur" ]]; then
            log_warn "En-tête révélateur détecté : ${valeur}"
            log_report "[AVERT]  En-tête révélateur détecté : ${valeur}"
            JSON_DISCLOSURES+=("${valeur}")
            divulgations=$((divulgations + 1))
        fi
    done

    # Vérifie la présence des en-têtes de sécurité recommandés
    echo ""
    log_info "→ Vérification des en-têtes de sécurité HTTP :"
    log_report ""
    log_report "--- En-têtes de sécurité HTTP ---"
    local security_headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Referrer-Policy"
        "Permissions-Policy"
    )
    for sec_header in "${security_headers[@]}"; do
        if echo "$headers" | grep -qi "^${sec_header}:"; then
            log_ok  "Présent  : ${sec_header}"
            log_report "[OK]     Présent  : ${sec_header}"
        else
            log_warn "ABSENT   : ${sec_header} — Risque de sécurité potentiel"
            log_report "[AVERT]  ABSENT   : ${sec_header} — Risque de sécurité potentiel"
            JSON_MISSING_HEADERS+=("${sec_header}")
            divulgations=$((divulgations + 1))
        fi
    done

    # --- Scan Nikto (détection de divulgation de version uniquement) ---
    echo ""
    log_info "→ Scan Nikto (détection de divulgation de version uniquement) :"
    log_report ""
    log_report "--- Résultats Nikto (divulgation de version) ---"

    local nikto_out
    nikto_out=$(docker exec "${CONTAINER_NAME}" \
        nikto -host "${TARGET_BASE_URL}" \
        -Tuning b \
        -nointeractive \
        -maxtime 60s \
        -Format txt 2>/dev/null \
        | grep -v "^-" \
        | grep -v "^$" \
        | head -40 \
        || echo "[Nikto] Scan non complété (timeout ou hôte inaccessible).")

    echo "$nikto_out"
    log_report "$nikto_out"

    echo ""
    if [[ $divulgations -gt 0 ]]; then
        log_alert "${divulgations} problème(s) de divulgation d'informations ou d'en-têtes de sécurité manquants."
        log_report ""
        log_report "[ALERTE] ${divulgations} problème(s) de divulgation d'informations ou d'en-têtes de sécurité manquants."
    else
        log_ok "Aucune divulgation d'information critique détectée."
        log_report "[OK] Aucune divulgation d'information critique détectée."
    fi
}
