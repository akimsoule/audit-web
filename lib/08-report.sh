# =============================================================================
# RAPPORT JSON — Génération d'un rapport structuré au format JSON
# =============================================================================

# Variables globales de tracking des résultats
JSON_TARGET=""
JSON_HOST=""
JSON_DATE=""
JSON_EXPOSED_FILES=()
JSON_PROTECTED_FILES=()
JSON_OPEN_PORTS=()
JSON_MISSING_HEADERS=()
JSON_DISCLOSURES=()
API_AUTH_BYPASS=()
API_IDOR_FINDINGS=()
API_DISCLOSURES=()
API_CORS_ISSUES=()
API_JWT_ISSUES=()
API_RATE_LIMIT_ISSUES=()
API_MASS_ASSIGNMENT=()
API_FREE_NUCLEI_FINDINGS=()
API_FREE_ZAP_FINDINGS=()
API_FREE_ARJUN_FINDINGS=()
API_FREE_KITERUNNER_FINDINGS=()
AUTH_FINDINGS=()

# Initialise les métadonnées du rapport JSON
json_init() {
    JSON_TARGET="${TARGET_BASE_URL:-}"
    JSON_HOST="${TARGET_HOST:-}"
    JSON_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}

# Échappe une chaîne pour une valeur JSON (antislash, guillemets, contrôles)
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    printf "%s" "$str"
}

# Écrit le fichier JSON final à partir des tableaux de tracking
json_write_report() {
    local json_file="${REPORT_FILE%.txt}.json"

    local exposed_json=""
    local first=true
    for f in "${JSON_EXPOSED_FILES[@]+"${JSON_EXPOSED_FILES[@]}"}"; do
        if $first; then first=false; else exposed_json+=","; fi
        exposed_json+="    \"$(json_escape "$f")\""
    done

    local protected_json=""
    first=true
    for f in "${JSON_PROTECTED_FILES[@]+"${JSON_PROTECTED_FILES[@]}"}"; do
        if $first; then first=false; else protected_json+=","; fi
        protected_json+="    \"$(json_escape "$f")\""
    done

    local ports_json=""
    first=true
    for p in "${JSON_OPEN_PORTS[@]+"${JSON_OPEN_PORTS[@]}"}"; do
        if $first; then first=false; else ports_json+=","; fi
        ports_json+="    \"$(json_escape "$p")\""
    done

    local headers_json=""
    first=true
    for h in "${JSON_MISSING_HEADERS[@]+"${JSON_MISSING_HEADERS[@]}"}"; do
        if $first; then first=false; else headers_json+=","; fi
        headers_json+="    \"$(json_escape "$h")\""
    done

    local disclosures_json=""
    first=true
    for d in "${JSON_DISCLOSURES[@]+"${JSON_DISCLOSURES[@]}"}"; do
        if $first; then first=false; else disclosures_json+=","; fi
        disclosures_json+="    \"$(json_escape "$d")\""
    done

    # Résultats API (exfiltration)
    local api_auth_json=""
    first=true
    for a in "${API_AUTH_BYPASS[@]+"${API_AUTH_BYPASS[@]}"}"; do
        if $first; then first=false; else api_auth_json+=","; fi
        api_auth_json+="    \"$(json_escape "$a")\""
    done

    local api_idor_json=""
    first=true
    for i in "${API_IDOR_FINDINGS[@]+"${API_IDOR_FINDINGS[@]}"}"; do
        if $first; then first=false; else api_idor_json+=","; fi
        api_idor_json+="    \"$(json_escape "$i")\""
    done

    local api_disc_json=""
    first=true
    for d in "${API_DISCLOSURES[@]+"${API_DISCLOSURES[@]}"}"; do
        if $first; then first=false; else api_disc_json+=","; fi
        api_disc_json+="    \"$(json_escape "$d")\""
    done

    local api_cors_json=""
    first=true
    for c in "${API_CORS_ISSUES[@]+"${API_CORS_ISSUES[@]}"}"; do
        if $first; then first=false; else api_cors_json+=","; fi
        api_cors_json+="    \"$(json_escape "$c")\""
    done

    local api_jwt_json=""
    first=true
    for j in "${API_JWT_ISSUES[@]+"${API_JWT_ISSUES[@]}"}"; do
        if $first; then first=false; else api_jwt_json+=","; fi
        api_jwt_json+="    \"$(json_escape "$j")\""
    done

    local api_mass_json=""
    first=true
    for m in "${API_MASS_ASSIGNMENT[@]+"${API_MASS_ASSIGNMENT[@]}"}"; do
        if $first; then first=false; else api_mass_json+=","; fi
        api_mass_json+="    \"$(json_escape "$m")\""
    done

    local api_free_nuclei_json=""
    first=true
    for n in "${API_FREE_NUCLEI_FINDINGS[@]+"${API_FREE_NUCLEI_FINDINGS[@]}"}"; do
        if $first; then first=false; else api_free_nuclei_json+=","; fi
        api_free_nuclei_json+="      ${n}"
    done

    local api_free_zap_json=""
    first=true
    for z in "${API_FREE_ZAP_FINDINGS[@]+"${API_FREE_ZAP_FINDINGS[@]}"}"; do
        if $first; then first=false; else api_free_zap_json+=","; fi
        api_free_zap_json+="      ${z}"
    done

    local api_free_arjun_json=""
    first=true
    for a in "${API_FREE_ARJUN_FINDINGS[@]+"${API_FREE_ARJUN_FINDINGS[@]}"}"; do
        if $first; then first=false; else api_free_arjun_json+=","; fi
        api_free_arjun_json+="    \"$(json_escape "$a")\""
    done

    local api_free_kiterunner_json=""
    first=true
    for k in "${API_FREE_KITERUNNER_FINDINGS[@]+"${API_FREE_KITERUNNER_FINDINGS[@]}"}"; do
        if $first; then first=false; else api_free_kiterunner_json+=","; fi
        api_free_kiterunner_json+="      ${k}"
    done

    local auth_findings_json=""
    first=true
    for a in "${AUTH_FINDINGS[@]+"${AUTH_FINDINGS[@]}"}"; do
        if $first; then first=false; else auth_findings_json+=","; fi
        auth_findings_json+="    \"$(json_escape "$a")\""
    done

    local total_alerts=$(( ${#JSON_EXPOSED_FILES[@]} + ${#JSON_OPEN_PORTS[@]} + ${#API_AUTH_BYPASS[@]} + ${#API_IDOR_FINDINGS[@]} + ${#API_FREE_NUCLEI_FINDINGS[@]} + ${#API_FREE_ZAP_FINDINGS[@]} ))
    local total_warnings=$(( ${#JSON_PROTECTED_FILES[@]} + ${#JSON_MISSING_HEADERS[@]} + ${#JSON_DISCLOSURES[@]} + ${#API_DISCLOSURES[@]} + ${#API_CORS_ISSUES[@]} + ${#API_JWT_ISSUES[@]} + ${#API_MASS_ASSIGNMENT[@]} + ${#API_FREE_ARJUN_FINDINGS[@]} + ${#API_FREE_KITERUNNER_FINDINGS[@]} + ${#AUTH_FINDINGS[@]} ))

    local score_info score grade
    score_info=$(calculer_score_securite)
    score="${score_info%%|*}"
    grade="${score_info#*|}"

    cat > "${json_file}" <<- JSONEOF
{
  "tool": "audit_web.sh v1.0",
  "target": "$(json_escape "${JSON_TARGET}")",
  "host": "$(json_escape "${JSON_HOST}")",
  "date": "${JSON_DATE}",
  "findings": {
    "sensitive_files": {
      "exposed": [
${exposed_json}
      ],
      "protected": [
${protected_json}
      ]
    },
    "open_ports": [
${ports_json}
    ],
    "missing_security_headers": [
${headers_json}
    ],
    "information_disclosures": [
${disclosures_json}
    ],
    "api_security": {
      "auth_bypass": [
${api_auth_json}
      ],
      "idor": [
${api_idor_json}
      ],
      "information_disclosure": [
${api_disc_json}
      ],
      "cors": [
${api_cors_json}
      ],
      "jwt": [
${api_jwt_json}
      ],
      "mass_assignment": [
${api_mass_json}
      ]
    },
    "api_free_security": {
      "nuclei": [
${api_free_nuclei_json}
      ],
      "zap": [
${api_free_zap_json}
      ],
      "arjun_params": [
${api_free_arjun_json}
      ],
      "kiterunner_routes": [
${api_free_kiterunner_json}
      ]
    },
    "auth_security": [
${auth_findings_json}
    ]
  },
  "summary": {
    "alerts": ${total_alerts},
    "warnings": ${total_warnings},
    "score": ${score},
    "grade": "${grade}"
  }
}
JSONEOF

    log_info "Rapport JSON généré → ${json_file}"
}

# =============================================================================
# SCORE DE SÉCURITÉ
# =============================================================================

calculer_score_securite() {
    local score=100

    # Fichiers sensibles exposés
    score=$(( score - (${#JSON_EXPOSED_FILES[@]} * 15) ))

    # Auth bypass
    score=$(( score - (${#API_AUTH_BYPASS[@]} * 20) ))

    # IDOR
    score=$(( score - (${#API_IDOR_FINDINGS[@]} * 15) ))

    # Ports sensibles ouverts
    score=$(( score - (${#JSON_OPEN_PORTS[@]} * 10) ))

    # Nuclei : critical/high/medium
    for n in "${API_FREE_NUCLEI_FINDINGS[@]+"${API_FREE_NUCLEI_FINDINGS[@]}"}"; do
        if echo "$n" | grep -qi '"severity":"critical"'; then
            score=$(( score - 20 ))
        elif echo "$n" | grep -qi '"severity":"high"'; then
            score=$(( score - 10 ))
        elif echo "$n" | grep -qi '"severity":"medium"'; then
            score=$(( score - 5 ))
        fi
    done

    # ZAP : High/Critical
    for z in "${API_FREE_ZAP_FINDINGS[@]+"${API_FREE_ZAP_FINDINGS[@]}"}"; do
        if echo "$z" | grep -qi '"risk":"(High|Critical)"'; then
            score=$(( score - 10 ))
        fi
    done

    # CORS
    score=$(( score - (${#API_CORS_ISSUES[@]} * 5) ))

    # JWT
    score=$(( score - (${#API_JWT_ISSUES[@]} * 5) ))

    # Mass assignment
    score=$(( score - (${#API_MASS_ASSIGNMENT[@]} * 10) ))

    # Auth findings
    score=$(( score - (${#AUTH_FINDINGS[@]} * 5) ))

    # Headers manquants / disclosures
    score=$(( score - (${#JSON_MISSING_HEADERS[@]} * 3) ))
    score=$(( score - (${#JSON_DISCLOSURES[@]} * 3) ))
    score=$(( score - (${#API_DISCLOSURES[@]} * 3) ))

    # Rate limiting
    score=$(( score - (${#API_RATE_LIMIT_ISSUES[@]} * 5) ))

    # Arjun / Kiterunner
    score=$(( score - (${#API_FREE_ARJUN_FINDINGS[@]} * 2) ))
    score=$(( score - (${#API_FREE_KITERUNNER_FINDINGS[@]} * 2) ))

    [[ $score -lt 0 ]] && score=0

    local grade="F"
    if [[ $score -ge 90 ]]; then grade="A"
    elif [[ $score -ge 80 ]]; then grade="B"
    elif [[ $score -ge 70 ]]; then grade="C"
    elif [[ $score -ge 50 ]]; then grade="D"
    fi

    echo "${score}|${grade}"
}

# =============================================================================
# RAPPORT FINAL (texte)
# =============================================================================

generer_rapport_final() {
    log_section "RAPPORT FINAL D'AUDIT"
    echo -e "  Cible auditée    : ${BOLD}${TARGET_BASE_URL}${RESET}"
    echo -e "  Hôte réseau      : ${BOLD}${TARGET_HOST}${RESET}"
    echo -e "  Date / Heure     : ${BOLD}$(date '+%Y-%m-%d %H:%M:%S %Z')${RESET}"
    echo -e "  Conteneur Docker : ${BOLD}${CONTAINER_NAME}${RESET}"

    local score_info
    score_info=$(calculer_score_securite)
    local score="${score_info%%|*}"
    local grade="${score_info#*|}"
    echo ""
    echo -e "  ${BOLD}SCORE DE SÉCURITÉ : ${score}/100 — Grade ${grade}${RESET}"

    echo ""
    echo -e "  ${YELLOW}RAPPEL :${RESET} Ce rapport est à usage interne confidentiel uniquement."
    echo -e "  Les vulnérabilités identifiées doivent être traitées selon votre"
    echo -e "  processus de gestion des risques. Ne pas divulguer publiquement."
    echo ""
    log_info "Audit terminé. Aucune exploitation n'a été effectuée sur la cible."

    {
        echo ""
        echo "============================================================"
        echo "  SCORE DE SÉCURITÉ : ${score}/100 — Grade ${grade}"
        echo "============================================================"
        echo ""
        echo "============================================================"
        echo "  FIN DU RAPPORT"
        echo "  Date de fin : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  RAPPEL : Document confidentiel — usage interne uniquement."
        echo "  Aucune exploitation active n'a été effectuée sur la cible."
        echo "============================================================"
    } >> "${REPORT_FILE}"

    echo ""
    echo -e "  ${GREEN}${BOLD}Rapport sauvegardé :${RESET} ${BOLD}${REPORT_FILE}${RESET}"
    echo ""
}
