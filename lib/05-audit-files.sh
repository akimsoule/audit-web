# =============================================================================
# AUDIT 1 — Fichiers sensibles exposés
# =============================================================================
# Méthode non destructive : On envoie une requête HTTP GET, on compare la
# taille et le hash du contenu avec la page d'accueil pour filtrer les
# "Soft 404" (SPA mode : toute URL inexistante renvoie la page d'accueil
# avec HTTP 200).
# =============================================================================

audit_fichiers_sensibles() {
    log_section "AUDIT 1 — Fichiers sensibles potentiellement exposés"
    log_info "Méthode : Vérification HTTP + détection des Soft 404"
    log_info "Cible   : ${TARGET_BASE_URL}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  AUDIT 1 — Fichiers sensibles exposés"
    log_report "========================================"
    log_report ""

    # ÉTAPE 1 : Récupérer la signature de la page d'accueil (baseline soft 404)
    log_info "→ Calibration : signature de la page d'accueil..."
    local homepage_size homepage_hash
    homepage_size=$(docker exec "${CONTAINER_NAME}" \
        curl -s -L -m 10 "${TARGET_BASE_URL}/" 2>/dev/null | wc -c)
    homepage_hash=$(docker exec "${CONTAINER_NAME}" \
        bash -c "curl -s -L -m 10 '${TARGET_BASE_URL}/' 2>/dev/null | md5sum | cut -d' ' -f1")

    log_info "   Page d'accueil : ${homepage_size} octets, hash: ${homepage_hash:0:12}..."
    log_report "Baseline Soft-404 : size=${homepage_size}, hash=${homepage_hash:0:12}"

    local found_count=0
    local soft_404_count=0

    for fichier in "${SENSITIVE_FILES[@]}"; do
        local url_test="${TARGET_BASE_URL}${fichier}"

        # Récupérer code HTTP + taille + hash en un seul docker exec (pas de fichier temporaire)
        local http_code content_size content_hash
        local result
        result=$(docker exec "${CONTAINER_NAME}" bash -c "
            response=\$(curl -s -L -m 10 -w '%{http_code}' '${url_test}' 2>/dev/null) || { echo 'ERR|0|'; exit; }
            code=\"\${response: -3}\"
            body=\"\${response:0:-3}\"
            size=\$(echo \"\$body\" | wc -c)
            hash=\$(echo \"\$body\" | md5sum 2>/dev/null | cut -d' ' -f1)
            echo \"\${code}|\${size}|\${hash}\"
        " 2>/dev/null) || result="ERR|0|"

        http_code="${result%%|*}"
        local rest="${result#*|}"
        content_size="${rest%%|*}"
        content_hash="${rest#*|}"

        if [[ "$http_code" == "200" ]]; then
            # DÉTECTION SOFT 404 : comparaison tolérante (±10 octets) du hash et de la taille
            local size_diff=$(( content_size - homepage_size ))
            [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))

            if [[ "$content_hash" == "$homepage_hash" ]] || [[ $size_diff -lt 10 ]]; then
                soft_404_count=$((soft_404_count + 1))
                echo -e "  ${CYAN}[SOFT-404]${RESET} ${fichier} (page d'accueil déguisée)"
                log_report "  [SOFT-404] ${fichier} (faux positif)"
            else
                log_alert "EXPOSÉ [HTTP 200] → ${url_test} (${content_size} octets)"
                log_report "[ALERTE] EXPOSÉ [HTTP 200] → ${url_test} (${content_size} octets)"
                JSON_EXPOSED_FILES+=("${url_test}")
                found_count=$((found_count + 1))
            fi
        elif [[ "$http_code" == "403" ]]; then
            log_warn "PRÉSENT mais protégé [HTTP 403] → ${url_test}"
            log_report "[AVERT]  PRÉSENT mais protégé [HTTP 403] → ${url_test}"
            JSON_PROTECTED_FILES+=("${url_test}")
        elif [[ "$http_code" == "404" ]]; then
            echo -e "  ${GREEN}[404]${RESET} ${fichier}"
            log_report "  [404] ${fichier}"
        else
            echo -e "  ${CYAN}[${http_code}]${RESET} ${fichier}"
            log_report "  [${http_code}] ${fichier}"
        fi
    done

    echo ""
    log_info "Soft 404 filtrés (faux positifs ignorés) : ${soft_404_count}"
    log_report "Soft 404 filtrés : ${soft_404_count}"

    if [[ $found_count -gt 0 ]]; then
        log_alert "${found_count} vrai(s) fichier(s) sensible(s) exposé(s) !"
        log_report "[ALERTE] ${found_count} vrai(s) fichier(s) sensible(s) exposé(s) !"
    else
        log_ok "Aucun fichier sensible réellement exposé (soft 404 exclus)."
        log_report "[OK] Aucun fichier sensible réellement exposé (soft 404 exclus)."
    fi
}
