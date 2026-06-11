# =============================================================================
# AUDIT API AVANCÉ — Outils open-source : Nuclei, ZAP, Arjun, Kiterunner
# =============================================================================
# Ce module utilise des outils gratuits et open-source pour auditer une API :
#   - Nuclei (ProjectDiscovery) : templates de vulnérabilités
#   - OWASP ZAP (headless/API) : spider + scan actif
#   - Arjun : découverte de paramètres cachés
#   - Kiterunner : découverte de routes API
# =============================================================================
# Déclenchement : export AUDIT_API_FREE_URL="https://api.cible.com"
# Sécurité : export SKIP_ACTIVE_SCAN=1 (défaut : désactivé)
#            export STAGING_MODE=1 (force tous les tests, même actifs)
# =============================================================================

# Variables globales (surchargées avant appel)
API_FREE_URL="${AUDIT_API_FREE_URL:-}"
API_FREE_TOKEN="${AUDIT_API_TOKEN:-}"
API_FREE_PREFIX="${AUDIT_API_PREFIX:-/api}"
API_FREE_EXCLUDED="${AUDIT_API_FREE_EXCLUDE:-/admin/*,/api/payments/*,/api/auth/*,/api/health}"

# Timeouts par outil (secondes)
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-300}"
ZAP_TIMEOUT="${ZAP_TIMEOUT:-600}"
ARJUN_TIMEOUT="${ARJUN_TIMEOUT:-180}"
KITERUNNER_TIMEOUT="${KITERUNNER_TIMEOUT:-300}"

# ZAP
ZAP_CONTAINER_NAME="zap_audit_web"
ZAP_API_PORT="${ZAP_API_PORT:-8090}"
ZAP_API_KEY="${ZAP_API_KEY:-audit_web_2024}"

# Nuclei
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-http/cves,http/vulnerabilities,http/misconfiguration,http/exposures}"

# Kiterunner
KR_WORDLIST="${KR_WORDLIST:-/usr/share/kiterunner/routes-large.kite}"

# Vérifie si un scan actif est autorisé
api_free_is_active_allowed() {
    if [[ "${STAGING_MODE:-0}" == "1" ]]; then
        return 0
    fi
    if [[ "${SKIP_ACTIVE_SCAN:-1}" == "1" ]]; then
        return 1
    fi
    return 0
}

# Vérifie si une URL est exclue par pattern
api_free_is_excluded() {
    local url="$1"
    local pattern
    IFS=',' read -ra patterns <<< "$API_FREE_EXCLUDED"
    for pattern in "${patterns[@]}"; do
        pattern="$(echo "$pattern" | xargs)"
        if [[ "$url" == $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Retourne l'IP accessible du conteneur ZAP depuis le conteneur Kali
# (macOS : host.docker.internal, Linux : localhost)
get_zap_host() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
            "${ZAP_CONTAINER_NAME}" 2>/dev/null | grep -v '^$' || echo "host.docker.internal"
    else
        echo "localhost"
    fi
}

# ===========================================================================
# INSTALLATION DES OUTILS DANS LE CONTENEUR KALI
# ===========================================================================

install_nuclei() {
    local present
    present=$(docker exec "${CONTAINER_NAME}" which nuclei 2>/dev/null || true)
    if [[ -n "$present" ]]; then
        log_ok "Nuclei déjà installé → $(basename "$present")"
        return 0
    fi
    log_info "Installation de Nuclei..."
    docker exec "${CONTAINER_NAME}" bash -c '
        NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
            | grep browser_download_url \
            | grep linux_amd64.zip \
            | cut -d"\"" -f4)
        curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip \
            && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
            && rm -f /tmp/nuclei.zip
    ' 2>/dev/null || { log_warn "Échec installation Nuclei" ; return 0; }
    log_ok "Nuclei installé avec succès."
}

install_zap() {
    local existing
    existing=$(docker ps -a --filter "name=^${ZAP_CONTAINER_NAME}$" --format "{{.Names}}" 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        local running
        running=$(docker ps --filter "name=^${ZAP_CONTAINER_NAME}$" --format "{{.Names}}" 2>/dev/null || true)
        if [[ -n "$running" ]]; then
            log_ok "Conteneur ZAP déjà en cours d'exécution."
            return 0
        fi
        log_info "Conteneur ZAP arrêté. Redémarrage..."
        docker start "${ZAP_CONTAINER_NAME}" || { log_warn "Échec redémarrage ZAP" ; return 0; }
        sleep 5
        log_ok "Conteneur ZAP redémarré."
        return 0
    fi
    log_info "Création du conteneur ZAP (ghcr.io/zaproxy/zaproxy:stable)..."
    docker run -d \
        --name "${ZAP_CONTAINER_NAME}" \
        -p "${ZAP_API_PORT}:8080" \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-x.sh -daemon -host 0.0.0.0 -port 8080 \
            -config api.key="${ZAP_API_KEY}" \
            -config api.disablekey=false \
            -config connection.timeoutInSecs=120 2>/dev/null || {
        log_warn "Échec création conteneur ZAP"
        return 0
    }
    log_info "Attente du démarrage de ZAP..."
    local zap_host
    zap_host=$(get_zap_host)
    local i=0
    while [[ $i -lt 60 ]]; do
        if curl -s "http://${zap_host}:${ZAP_API_PORT}" >/dev/null 2>&1; then
            log_ok "ZAP démarré sur ${zap_host}:${ZAP_API_PORT}."
            return 0
        fi
        sleep 2
        i=$((i + 1))
    done
    log_warn "ZAP n'a pas démarré dans le temps imparti (120s)."
    return 0
}

install_arjun() {
    local present
    present=$(docker exec "${CONTAINER_NAME}" which arjun 2>/dev/null || true)
    if [[ -n "$present" ]]; then
        log_ok "Arjun déjà installé → $(basename "$present")"
        return 0
    fi
    log_info "Installation d'Arjun (pip3)..."
    docker exec "${CONTAINER_NAME}" bash -c "
        pip3 install arjun -q 2>/dev/null || pip install arjun -q
    " || {
        log_warn "Échec installation Arjun"
        return 0
    }
    log_ok "Arjun installé avec succès."
}

install_kiterunner() {
    local present
    present=$(docker exec "${CONTAINER_NAME}" which kr 2>/dev/null || true)
    if [[ -n "$present" ]]; then
        log_ok "Kiterunner déjà installé → $(basename "$present")"
        return 0
    fi
    log_info "Installation de Kiterunner..."
    docker exec "${CONTAINER_NAME}" bash -c '
        KR_URL=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest \
            | grep browser_download_url \
            | grep linux_amd64.tar.gz \
            | cut -d"\"" -f4)
        curl -sL "$KR_URL" | tar -xz -C /usr/local/bin/ kr \
            && chmod +x /usr/local/bin/kr
    ' 2>/dev/null || {
        log_warn "Échec installation Kiterunner"
        return 0
    }
    log_info "Téléchargement de la wordlist routes-large.kite..."
    docker exec "${CONTAINER_NAME}" bash -c "
        mkdir -p /usr/share/kiterunner/ \
        && curl -sL https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite \
           -o /usr/share/kiterunner/routes-large.kite 2>/dev/null
    " || log_warn "Wordlist Kiterunner non téléchargée."
    log_ok "Kiterunner installé avec succès."
}

# Installation de tous les outils (idempotente)
install_api_free_tools() {
    log_section "Installation des outils API avancés"

    install_nuclei
    install_arjun
    install_kiterunner

    if api_free_is_active_allowed; then
        install_zap
    else
        log_info "SKIP_ACTIVE_SCAN actif : ZAP ignoré."
    fi
}

# ===========================================================================
# NUCLEI — Scan de vulnérabilités par templates
# ===========================================================================

audit_nuclei() {
    log_section "Nuclei — Scan de vulnérabilités"

    local target="${API_FREE_URL}"
    local severity="${NUCLEI_SEVERITY}"
    local templates="${NUCLEI_TEMPLATES//,/,}"
    local output_json
    output_json=$(docker exec "${CONTAINER_NAME}" mktemp 2>/dev/null || echo "/tmp/nuclei_out.$$")

    log_info "Target : ${target}"
    log_info "Severité : ${severity}"
    log_info "Templates : ${templates}"
    log_report ""
    log_report "========================================"
    log_report "  Nuclei — Résultats"
    log_report "========================================"
    log_report ""

    if [[ -n "${API_FREE_TOKEN}" ]]; then
        log_info "Token d'authentification fourni."
    fi

    log_info "Lancement de Nuclei (timeout: ${NUCLEI_TIMEOUT}s)..."
    local start_time
    start_time=$(date +%s)

    docker exec "${CONTAINER_NAME}" bash -c "
        timeout ${NUCLEI_TIMEOUT} nuclei \
            -u '${target}' \
            -t ${templates} \
            -severity ${severity} \
            -json -o '${output_json}' \
            -rl 50 -timeout 10 -no-color \
            ${API_FREE_TOKEN:+-H 'Authorization: Bearer ${API_FREE_TOKEN}'}
    " 2>/dev/null || {
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_warn "Nuclei a dépassé le timeout (${NUCLEI_TIMEOUT}s)"
        else
            log_warn "Nuclei terminé avec le code ${exit_code}"
        fi
    }

    local duration=$(( $(date +%s) - start_time ))
    log_info "Nuclei terminé en ${duration}s."

    if docker exec "${CONTAINER_NAME}" test -s "${output_json}" 2>/dev/null; then
        local findings_count
        findings_count=$(docker exec "${CONTAINER_NAME}" wc -l < "${output_json}" 2>/dev/null || echo 0)
        findings_count=$(( findings_count + 0 ))

        log_info "Nuclei a trouvé ${findings_count} résultat(s)."

        if [[ $findings_count -gt 0 ]]; then
            while IFS='|' read -r marker sev tid name matched; do
                if [[ "$marker" != "FINDING" ]]; then continue; fi

                local sev_display
                case "${sev}" in
                    critical) sev_display="${RED}CRITICAL${RESET}" ;;
                    high)     sev_display="${RED}HIGH${RESET}" ;;
                    medium)   sev_display="${YELLOW}MEDIUM${RESET}" ;;
                    low)      sev_display="${CYAN}LOW${RESET}" ;;
                    *)        sev_display="${sev}" ;;
                esac

                log_alert "[${sev_display}] ${tid} — ${name} sur ${matched}"
                log_report "[ALERTE] [${sev}] ${tid} — ${name} sur ${matched}"

                API_FREE_NUCLEI_FINDINGS+=("{\"id\":\"${tid}\",\"severity\":\"${sev}\",\"name\":\"${name}\",\"matched\":\"${matched}\"}")
            done < <(docker exec "${CONTAINER_NAME}" bash -c "
                while IFS= read -r line; do
                    template_id=\$(echo \"\$line\" | jq -r '.[\"template-id\"] // empty')
                    severity_level=\$(echo \"\$line\" | jq -r '.info.severity // empty')
                    name=\$(echo \"\$line\" | jq -r '.info.name // empty')
                    matched=\$(echo \"\$line\" | jq -r '.[\"matched-at\"] // empty')
                    echo \"FINDING|\${severity_level}|\${template_id}|\${name}|\${matched}\"
                done < '${output_json}'
            " 2>/dev/null || true)
        fi
    else
        log_ok "Nuclei n'a trouvé aucune vulnérabilité connue."
        log_report "[OK] Aucun résultat Nuclei."
    fi

    docker exec "${CONTAINER_NAME}" rm -f "${output_json}" 2>/dev/null || true
}

# ===========================================================================
# OWASP ZAP — Scan actif via API REST
# ===========================================================================

zap_api() {
    local endpoint="$1"
    local params="${2:-}"
    local zap_host
    zap_host=$(get_zap_host)
    curl -s "http://${zap_host}:${ZAP_API_PORT}/JSON/${endpoint}?apiKey=${ZAP_API_KEY}${params}" 2>/dev/null || true
}

zap_wait_for_scan() {
    local scan_type="$1"
    local scan_id="$2"
    local progress_url
    if [[ "$scan_type" == "spider" ]]; then
        progress_url="spider/view/status/?scanId=${scan_id}"
    else
        progress_url="ascan/view/status/?scanId=${scan_id}"
    fi
    local i=0
    while [[ $i -lt 120 ]]; do
        local status
        status=$(zap_api "${progress_url}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
        if [[ "$status" == "100" ]]; then
            break
        fi
        sleep 3
        i=$((i + 1))
    done
}

audit_zap() {
    log_section "OWASP ZAP — Scan actif"

    local target="${API_FREE_URL}"
    local zap_host
    zap_host=$(get_zap_host)
    log_info "Target : ${target}"
    log_info "API ZAP : http://${zap_host}:${ZAP_API_PORT}"
    log_report ""
    log_report "========================================"
    log_report "  OWASP ZAP — Résultats"
    log_report "========================================"
    log_report ""

    if ! curl -s "http://${zap_host}:${ZAP_API_PORT}" >/dev/null 2>&1; then
        log_warn "ZAP inaccessible sur ${zap_host}:${ZAP_API_PORT}. Scan ignoré."
        log_report "[SKIP] ZAP inaccessible"
        return
    fi

    log_info "Étape 1/3 : Enregistrement de la cible..."
    zap_api "core/action/accessUrl" "&url=${target}" >/dev/null

    log_info "Étape 2/3 : Spider en cours..."
    local spider_id
    spider_id=$(zap_api "spider/action/scan" "&url=${target}&maxChildren=10&recurse=true" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scanId',''))" 2>/dev/null || echo "")
    if [[ -n "$spider_id" ]]; then
        log_info "Spider ID: ${spider_id}"
        zap_wait_for_scan "spider" "${spider_id}"
        log_ok "Spider terminé."
    else
        log_warn "Impossible de lancer le spider ZAP."
    fi

    log_info "Étape 3/3 : Active Scan en cours..."
    local scan_id
    scan_id=$(zap_api "ascan/action/scan" "&url=${target}&recurse=true" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scanId',''))" 2>/dev/null || echo "")
    if [[ -n "$scan_id" ]]; then
        log_info "Active Scan ID: ${scan_id}"
        zap_wait_for_scan "ascanner" "${scan_id}"
        log_ok "Active Scan terminé."
    else
        log_warn "Impossible de lancer l'Active Scan ZAP."
    fi

    log_info "Récupération des alertes..."
    local alerts_json
    alerts_json=$(zap_api "core/view/alerts" "&baseurl=${target}" 2>/dev/null || echo '{}')

    local alert_count
    alert_count=$(echo "$alerts_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('alerts',[])))" 2>/dev/null || echo 0)

    if [[ "$alert_count" != "0" ]] && [[ "$alert_count" != "0" ]]; then
        log_alert "ZAP a détecté ${alert_count} alerte(s) !"
        log_report "[ALERTE] ZAP : ${alert_count} alerte(s)"

        echo "$alerts_json" | python3 -c "import sys,json; [print(json.dumps(a)) for a in json.load(sys.stdin).get('alerts',[])]" 2>/dev/null > /tmp/zap_alerts.$$
        while IFS= read -r alert_line; do
            local risk name uri
            risk=$(echo "$alert_line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('risk','unknown'))" 2>/dev/null || echo "unknown")
            name=$(echo "$alert_line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null || echo "")
            uri=$(echo "$alert_line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('uri',''))" 2>/dev/null || echo "")

            local risk_display
            case "${risk}" in
                High|Critical) risk_display="${RED}${risk}${RESET}" ;;
                Medium)        risk_display="${YELLOW}${risk}${RESET}" ;;
                *)             risk_display="${risk}" ;;
            esac

            log_alert "[${risk_display}] ${name} sur ${uri}"
            log_report "[ALERTE] [${risk}] ${name} sur ${uri}"

            API_FREE_ZAP_FINDINGS+=("{\"risk\":\"${risk}\",\"name\":\"${name}\",\"uri\":\"${uri}\"}")
        done < /tmp/zap_alerts.$$
        rm -f /tmp/zap_alerts.$$
    else
        log_ok "ZAP n'a détecté aucune alerte."
        log_report "[OK] Aucune alerte ZAP."
    fi
}

# ===========================================================================
# ARJUN — Découverte de paramètres cachés
# ===========================================================================

audit_arjun() {
    log_section "Arjun — Découverte de paramètres cachés"

    local target="${API_FREE_URL}"
    local output_json
    output_json=$(docker exec "${CONTAINER_NAME}" mktemp 2>/dev/null || echo "/tmp/arjun_out.$$")

    log_info "Target : ${target}"
    log_report ""
    log_report "========================================"
    log_report "  Arjun — Paramètres découverts"
    log_report "========================================"
    log_report ""

    log_info "Scan des paramètres GET..."
    local start_time
    start_time=$(date +%s)

    docker exec "${CONTAINER_NAME}" bash -c "
        timeout ${ARJUN_TIMEOUT} arjun \
            -u '${target}' --get -oJ -oT 10 -t 20 --timeout 10 \
            ${API_FREE_TOKEN:+-H 'Authorization: Bearer ${API_FREE_TOKEN}'} \
            -o '${output_json}' 2>/dev/null
    " || true

    local duration=$(( $(date +%s) - start_time ))
    log_info "Arjun terminé en ${duration}s."

    local params_count=0
    if docker exec "${CONTAINER_NAME}" test -s "${output_json}" 2>/dev/null; then
        params_count=$(docker exec "${CONTAINER_NAME}" bash -c "
            jq -r '(.results | length) // (.paramList | length) // 0' < '${output_json}' 2>/dev/null || echo 0
        " 2>/dev/null || echo 0)
        params_count=$(( params_count + 0 ))

        if [[ $params_count -gt 0 ]]; then
            log_warn "Arjun a découvert ${params_count} paramètre(s) !"
            log_report "[AVERT] ${params_count} paramètre(s) découverts"

            docker exec "${CONTAINER_NAME}" bash -c "
                jq -c '(.results // .paramList // [])[]' < '${output_json}' 2>/dev/null
            " 2>/dev/null > /tmp/arjun_params.$$
            while IFS= read -r param_line; do
                log_warn "Paramètre : ${param_line}"
                log_report "[AVERT] Paramètre : ${param_line}"
                API_FREE_ARJUN_FINDINGS+=("${param_line}")
            done < /tmp/arjun_params.$$
            rm -f /tmp/arjun_params.$$ || true
        fi
    fi

    if [[ $params_count -eq 0 ]]; then
        log_ok "Aucun paramètre caché découvert."
        log_report "[OK] Aucun paramètre Arjun."
    fi

    docker exec "${CONTAINER_NAME}" rm -f "${output_json}" 2>/dev/null || true
}

# ===========================================================================
# KITERUNNER — Découverte de routes API cachées
# ===========================================================================

audit_kiterunner() {
    log_section "Kiterunner — Découverte de routes API"

    local target="${API_FREE_URL}"
    local wordlist="${KR_WORDLIST}"
    local output_json
    output_json=$(docker exec "${CONTAINER_NAME}" mktemp 2>/dev/null || echo "/tmp/kr_out.$$")

    log_info "Target : ${target}"
    log_info "Wordlist : ${wordlist}"
    log_report ""
    log_report "========================================"
    log_report "  Kiterunner — Routes découvertes"
    log_report "========================================"
    log_report ""

    if ! docker exec "${CONTAINER_NAME}" test -f "${wordlist}" 2>/dev/null; then
        log_warn "Wordlist Kiterunner introuvable : ${wordlist}"
        log_warn "Téléchargement de la wordlist par défaut..."
        docker exec "${CONTAINER_NAME}" bash -c "
            mkdir -p /usr/share/kiterunner/ \
            && curl -sL https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite \
               -o /usr/share/kiterunner/routes-large.kite 2>/dev/null
        " || {
            log_warn "Téléchargement impossible. Scan Kiterunner ignoré."
            log_report "[SKIP] Wordlist Kiterunner absente"
            return
        }
        wordlist="/usr/share/kiterunner/routes-large.kite"
    fi

    local start_time
    start_time=$(date +%s)

    docker exec "${CONTAINER_NAME}" bash -c "
        timeout ${KITERUNNER_TIMEOUT} kr scan '${target}' \
            -w '${wordlist}' -oj \
            ${API_FREE_TOKEN:+-H 'Authorization: Bearer ${API_FREE_TOKEN}'} \
            2>/dev/null | head -50 > '${output_json}'
    " || true

    local duration=$(( $(date +%s) - start_time ))
    log_info "Kiterunner terminé en ${duration}s."

    local routes_count=0
    if docker exec "${CONTAINER_NAME}" test -s "${output_json}" 2>/dev/null; then
        routes_count=$(docker exec "${CONTAINER_NAME}" wc -l < "${output_json}" 2>/dev/null || echo 0)
        routes_count=$(( routes_count + 0 ))

        if [[ $routes_count -gt 0 ]]; then
            log_warn "Kiterunner a découvert ${routes_count} route(s) !"
            log_report "[AVERT] ${routes_count} route(s) API découvertes"

            docker exec "${CONTAINER_NAME}" cat "${output_json}" 2>/dev/null > /tmp/kr_routes.$$
            while IFS= read -r route_line; do
                local route_url status_code
                route_url=$(echo "$route_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url') or d.get('path') or '')" 2>/dev/null || echo "")
                status_code=$(echo "$route_line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")

                if [[ -n "$route_url" ]]; then
                    local status_display
                    if [[ "$status_code" == "200" ]]; then
                        status_display="${RED}${status_code}${RESET}"
                    elif [[ "$status_code" == "403" || "$status_code" == "401" ]]; then
                        status_display="${YELLOW}${status_code}${RESET}"
                    else
                        status_display="${status_code}"
                    fi

                    log_warn "Route : ${route_url} (${status_display})"
                    log_report "[AVERT] Route : ${route_url} (${status_code})"

                    API_FREE_KITERUNNER_FINDINGS+=("{\"url\":\"${route_url}\",\"status\":\"${status_code}\"}")
                fi
            done < /tmp/kr_routes.$$
            rm -f /tmp/kr_routes.$$
        fi
    fi

    if [[ $routes_count -eq 0 ]]; then
        log_ok "Aucune route cachée découverte."
        log_report "[OK] Aucune route Kiterunner."
    fi

    docker exec "${CONTAINER_NAME}" rm -f "${output_json}" 2>/dev/null || true
}

# ===========================================================================
# ORCHESTRATEUR PRINCIPAL
# ===========================================================================

audit_api_free_exfil() {
    local target="${API_FREE_URL}"

    log_section "AUDIT API AVANCÉ — Outils open-source"
    log_info "Target : ${target}"
    log_info "Prefix : ${API_FREE_PREFIX}"
    if api_free_is_active_allowed; then
        log_info "Mode : ACTIF (scans actifs autorisés)"
    else
        log_info "Mode : PASSIF (scans non intrusifs uniquement)"
    fi

    log_report ""
    log_report "============================================================"
    log_report "  AUDIT API AVANCÉ — Outils open-source"
    log_report "============================================================"
    log_report ""

    install_api_free_tools

    audit_nuclei
    audit_arjun
    audit_kiterunner

    if api_free_is_active_allowed; then
        audit_zap
    else
        log_info "SKIP_ACTIVE_SCAN actif : ZAP ignoré."
        log_report "[SKIP] ZAP désactivé (SKIP_ACTIVE_SCAN=1)"
    fi

    log_section "RÉCAPITULATIF AUDIT API AVANCÉ"
    echo -e "  Nuclei             : ${#API_FREE_NUCLEI_FINDINGS[@]} vulnérabilité(s)"
    echo -e "  ZAP                : ${#API_FREE_ZAP_FINDINGS[@]} alerte(s)"
    echo -e "  Arjun              : ${#API_FREE_ARJUN_FINDINGS[@]} paramètre(s) caché(s)"
    echo -e "  Kiterunner         : ${#API_FREE_KITERUNNER_FINDINGS[@]} route(s) découverte(s)"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  RÉCAPITULATIF AUDIT API AVANCÉ"
    log_report "========================================"
    log_report "  Nuclei             : ${#API_FREE_NUCLEI_FINDINGS[@]}"
    log_report "  ZAP                : ${#API_FREE_ZAP_FINDINGS[@]}"
    log_report "  Arjun              : ${#API_FREE_ARJUN_FINDINGS[@]}"
    log_report "  Kiterunner         : ${#API_FREE_KITERUNNER_FINDINGS[@]}"
    log_report ""
}
