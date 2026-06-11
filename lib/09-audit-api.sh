# =============================================================================
# AUDIT API — Tests d'exfiltration de données et sécurité applicative
# =============================================================================
# Ce module teste activement la sécurité d'une API REST :
#   - Contournement d'authentification
#   - IDOR (Insecure Direct Object Reference)
#   - Divulgation d'informations sensibles
#   - CORS
#   - Analyse JWT
#   - Rate limiting
#   - Mass assignment
# =============================================================================

# URL de base de l'API (surchargée avant appel)
API_BASE_URL=""
API_PATH_PREFIX=""
API_ACCESS_TOKEN=""
API_SECOND_USER_TOKEN=""

# JSON tracking (peuplé par le module, lu par 08-report.sh)
API_AUTH_BYPASS=()
API_IDOR_FINDINGS=()
API_DISCLOSURES=()
API_CORS_ISSUES=()
API_JWT_ISSUES=()
API_RATE_LIMIT_ISSUES=()
API_MASS_ASSIGNMENT=()

# Extrait une valeur JSON depuis la sortie curl
api_extract_json() {
    local key="$1"
    python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = '${key}'.split('.')
v = d
for k in keys:
    if isinstance(v, dict):
        v = v.get(k)
    else:
        v = None
if v is not None:
    sys.stdout.write(str(v))
" 2>/dev/null
}

# Extrait le payload d'un JWT (lecture depuis stdin)
api_decode_jwt() {
    local token
    token=$(cat)
    [[ -z "$token" ]] && return
    python3 -c "
import sys, json, base64
token = '${token}'
parts = token.split('.')
if len(parts) == 3:
    try:
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        sys.stdout.write(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))
    except:
        pass
" 2>/dev/null
}

# Requête HTTP GET vers l'API
api_get() {
    local path="$1"
    local auth_header="${2:-}"
    local origin="${3:-}"
    if [[ -n "$auth_header" && -n "$origin" ]]; then
        curl -s "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
            -H "Authorization: Bearer $auth_header" \
            -H "Origin: $origin"
    elif [[ -n "$auth_header" ]]; then
        curl -s "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
            -H "Authorization: Bearer $auth_header"
    elif [[ -n "$origin" ]]; then
        curl -s "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
            -H "Origin: $origin"
    else
        curl -s "${API_BASE_URL}${API_PATH_PREFIX}${path}"
    fi
}

# Requête HTTP POST vers l'API
api_post() {
    local path="$1"
    local body="$2"
    local auth_header="${3:-}"
    if [[ -n "$auth_header" ]]; then
        curl -s -X POST "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $auth_header" \
            -d "$body"
    else
        curl -s -X POST "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
            -H "Content-Type: application/json" \
            -d "$body"
    fi
}

# Requête HTTP OPTIONS (CORS preflight)
api_options() {
    local path="$1"
    local origin="$2"
    curl -s -D - -X OPTIONS "${API_BASE_URL}${API_PATH_PREFIX}${path}" \
        -H "Origin: $origin" \
        -H "Access-Control-Request-Method: GET" 2>&1
}

# ===========================================================================
# 1. TEST : Contournement d'authentification
# ===========================================================================
api_test_auth_bypass() {
    log_section "API — Test de contournement d'authentification"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Contournement d'authentification"
    log_report "========================================"
    log_report ""

    local endpoints_proteges=(
        "/admin/stats"
        "/auth/me"
        "/my-commissions"
        "/my-applications"
        "/notifications"
        "/profile"
        "/onboarding/pick-role"
    )

    local bypass_count=0
    for endpoint in "${endpoints_proteges[@]}"; do
        local response
        response=$(api_get "$endpoint")
        local status_code
        status_code=$(echo "$response" | api_extract_json "statusCode" 2>/dev/null)
        local message
        message=$(echo "$response" | api_extract_json "message" 2>/dev/null)

        # Un endpoint qui retourne des données (pas un message d'erreur) est vulnérable
        if [[ "$message" != *"Authentification requise"* ]] && \
           [[ "$message" != *"Non autorisé"* ]] && \
           [[ "$message" != *"introuvable"* ]] && \
           [[ -n "$(echo "$response" | api_extract_json "id" 2>/dev/null)" ]] || \
           [[ -n "$(echo "$response" | api_extract_json "data" 2>/dev/null)" ]] && \
           [[ "$message" != *"Authentification"* ]]; then

            local snippet="${response:0:120}"
            log_alert "BYPASS AUTH [${endpoint}] → Données accessibles sans token"
            log_report "[ALERTE] BYPASS AUTH [${endpoint}] → Données accessibles sans token: ${snippet}"
            API_AUTH_BYPASS+=("${endpoint}")
            bypass_count=$((bypass_count + 1))
        else
            log_ok "Bloqué [${endpoint}] → ${message:-403}"
            log_report "[OK] Bloqué [${endpoint}] → ${message:-403}"
        fi
    done

    echo ""
    if [[ $bypass_count -gt 0 ]]; then
        log_alert "${bypass_count} endpoint(s) vulnérable(s) au contournement d'auth !"
        log_report "[ALERTE] ${bypass_count} endpoint(s) vulnérable(s) au contournement d'auth !"
    else
        log_ok "Tous les endpoints testés sont correctement protégés."
        log_report "[OK] Tous les endpoints testés sont correctement protégés."
    fi
}

# ===========================================================================
# 2. TEST : IDOR (Insecure Direct Object Reference)
# ===========================================================================
api_test_idor() {
    log_section "API — Test IDOR (accès inter-utilisateurs)"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — IDOR (Insecure Direct Object Ref)"
    log_report "========================================"
    log_report ""

    if [[ -z "${API_ACCESS_TOKEN}" ]]; then
        log_warn "Token utilisateur 1 manquant. Test IDOR ignoré."
        log_report "[SKIP] Token utilisateur 1 manquant"
        return
    fi

    # IDs des utilisateurs de test
    local user1_id=""
    local user2_id=""
    user1_id=$(echo "$API_ACCESS_TOKEN" | api_decode_jwt | api_extract_json "userId")
    if [[ -n "${API_SECOND_USER_TOKEN}" ]]; then
        user2_id=$(echo "$API_SECOND_USER_TOKEN" | api_decode_jwt | api_extract_json "userId")
    fi

    log_info "User 1 (DEMANDEUR) ID : ${user1_id}"
    log_info "User 2 (PRESTATAIRE) ID : ${user2_id:-N/A}"

    local idor_count=0

    # Test: User 1 essaie d'accéder au profil de User 2
    if [[ -n "$user2_id" ]]; then
        log_info "→ Test accès profil utilisateur tiers..."
        local response
        response=$(api_get "/credibility/${user2_id}" "${API_ACCESS_TOKEN}")
        local cred_data
        cred_data=$(echo "$response" | api_extract_json "data" 2>/dev/null)
        if [[ -n "$cred_data" ]] && [[ "$cred_data" != "null" ]]; then
            log_warn "Données de crédibilité accessibles pour un autre utilisateur"
            log_report "[AVERT] IDOR crédibilité: données de ${user2_id} accessibles par ${user1_id}"
            API_IDOR_FINDINGS+=("crédibilité: ${user2_id}")
        else
            log_ok "Crédibilité protégée"
            log_report "[OK] Crédibilité protégée"
        fi
    fi

    # Test: User 1 essaie d'accéder aux commissions de User 2
    if [[ -n "$user2_id" ]]; then
        log_info "→ Test accès commissions d'un autre utilisateur..."
        local response
        response=$(api_get "/commissions/user/${user2_id}" "${API_ACCESS_TOKEN}")
        local data
        data=$(echo "$response" | api_extract_json "data" 2>/dev/null)
        local message
        message=$(echo "$response" | api_extract_json "message" 2>/dev/null)

        if [[ -n "$data" ]] && [[ "$data" != "null" ]]; then
            log_alert "IDOR : Commissions d'un autre utilisateur accessibles !"
            log_report "[ALERTE] IDOR commissions: données de ${user2_id} accessibles"
            API_IDOR_FINDINGS+=("commissions/user: ${user2_id}")
            idor_count=$((idor_count + 1))
        else
            log_ok "Commissions protégées"
            log_report "[OK] Commissions protégées"
        fi
    fi

    # Test: User 1 essaie d'accéder aux notifications de User 2
    if [[ -n "$user2_id" ]]; then
        log_info "→ Test accès notifications d'un autre utilisateur..."
        local response
        response=$(api_get "/notifications?userId=${user2_id}" "${API_ACCESS_TOKEN}")
        local data
        data=$(echo "$response" | api_extract_json "data" 2>/dev/null)

        if [[ -n "$data" ]] && [[ "$data" != "null" ]]; then
            local count
            count=$(echo "$data" | api_extract_json "length" 2>/dev/null)
            if [[ -n "$count" ]] && [[ "$count" -gt 0 ]]; then
                log_alert "IDOR : Notifications d'un autre utilisateur accessibles !"
                log_report "[ALERTE] IDOR notifications: données de ${user2_id} accessibles (${count})"
                API_IDOR_FINDINGS+=("notifications: ${user2_id}")
                idor_count=$((idor_count + 1))
            else
                log_ok "Aucune notification trouvée (endpoint protégé ou vide)"
                log_report "[OK] Aucune notification trouvée"
            fi
        else
            log_ok "Notifications protégées"
            log_report "[OK] Notifications protégées"
        fi
    fi

    echo ""
    if [[ $idor_count -gt 0 ]]; then
        log_alert "${idor_count} vulnérabilité(s) IDOR détectée(s) !"
        log_report "[ALERTE] ${idor_count} vulnérabilité(s) IDOR détectée(s) !"
    else
        log_ok "Aucune vulnérabilité IDOR critique détectée."
        log_report "[OK] Aucune vulnérabilité IDOR critique détectée."
    fi
}

# ===========================================================================
# 3. TEST : Divulgation d'informations
# ===========================================================================
api_test_information_disclosure() {
    log_section "API — Test de divulgation d'informations"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Divulgation d'informations"
    log_report "========================================"
    log_report ""

    local disclosure_count=0

    # Test: En-têtes X-Powered-By
    local headers
    headers=$(curl -s -I "${API_BASE_URL}${API_PATH_PREFIX}/health" 2>&1)
    if echo "$headers" | grep -qi "x-powered-by"; then
        local value
        value=$(echo "$headers" | grep -i "x-powered-by" | tr -d '\r' || true)
        log_warn "En-tête X-Powered-By divulgué : ${value}"
        log_report "[AVERT] X-Powered-By divulgué : ${value}"
        API_DISCLOSURES+=("X-Powered-By: ${value}")
        disclosure_count=$((disclosure_count + 1))
    fi

    # Test: Informations dans le sitemap
    local sitemap
    sitemap=$(curl -s "${API_BASE_URL}/sitemap.xml" 2>&1)
    if echo "$sitemap" | grep -qi "api\|admin\|internal"; then
        log_warn "Sitemap contient des endpoints potentiellement sensibles"
        log_report "[AVERT] Sitemap avec endpoints sensibles"
        API_DISCLOSURES+=("Sitemap expose endpoints internes")
        disclosure_count=$((disclosure_count + 1))
    fi

    # Test: stack trace dans les erreurs
    local error_response
    error_response=$(api_get "/auth/me" "" 2>&1)
    if echo "$error_response" | grep -qi "stack\|Error\|at \|node_modules\|file://"; then
        log_alert "Les erreurs divulguent des stack traces !"
        log_report "[ALERTE] Stack traces dans les réponses d'erreur"
        API_DISCLOSURES+=("Stack traces exposées dans les erreurs")
        disclosure_count=$((disclosure_count + 1))
    fi

    # Test: Version Express dans les en-têtes
    if echo "$headers" | grep -qi "^server:.*[0-9]"; then
        local server_val
        server_val=$(echo "$headers" | grep -i "^server:" | tr -d '\r' || true)
        log_warn "Version serveur divulguée : ${server_val}"
        log_report "[AVERT] Version serveur : ${server_val}"
        API_DISCLOSURES+=("${server_val}")
        disclosure_count=$((disclosure_count + 1))
    fi

    echo ""
    if [[ $disclosure_count -gt 0 ]]; then
        log_alert "${disclosure_count} divulgation(s) d'informations détectée(s) !"
        log_report "[ALERTE] ${disclosure_count} divulgation(s) d'informations détectée(s) !"
    else
        log_ok "Aucune divulgation d'information critique."
        log_report "[OK] Aucune divulgation d'information critique."
    fi
}

# ===========================================================================
# 4. TEST : CORS
# ===========================================================================
api_test_cors() {
    log_section "API — Test CORS (Cross-Origin Resource Sharing)"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Test CORS"
    log_report "========================================"
    log_report ""

    local origins_to_test=(
        "https://evil.com"
        "https://notorios.app"
        "null"
    )

    local cors_issues=0
    for origin in "${origins_to_test[@]}"; do
        local opt_response
        opt_response=$(api_options "/health" "$origin")
    local acao
    acao=$(echo "$opt_response" | grep -i "access-control-allow-origin" | tr -d '\r' || true)
    local acac
    acac=$(echo "$opt_response" | grep -i "access-control-allow-credentials" | tr -d '\r' || true)

        if [[ -n "$acao" ]]; then
            local acao_value
            acao_value=$(echo "$acao" | sed 's/.*: //')
            if [[ "$acao_value" == "*" ]]; then
                log_alert "CORS permissif ! Origin '${origin}' → ACAO: *"
                log_report "[ALERTE] CORS permissif pour ${origin}: ACAO=${acao_value}"
                API_CORS_ISSUES+=("ACAO=* pour ${origin}")
                cors_issues=$((cors_issues + 1))
            elif [[ "$acao_value" == "$origin" ]] && [[ -n "$acac" ]]; then
                log_alert "CORS avec credentials ! Origin '${origin}' → ACAO: ${acao_value}, ACAC présent"
                log_report "[ALERTE] CORS credentials pour ${origin}"
                API_CORS_ISSUES+=("CORS+credentials: ${origin}")
                cors_issues=$((cors_issues + 1))
            else
                log_ok "CORS restreint pour ${origin}: ${acao_value}"
                log_report "[OK] CORS restreint pour ${origin}"
            fi
        else
            log_ok "Pas d'en-tête CORS pour ${origin} (comportement par défaut)"
            log_report "[OK] Pas de CORS pour ${origin}"
        fi
    done

    # Test GET with Origin
    local get_response
    get_response=$(curl -s -D - -H "Origin: https://evil.com" "${API_BASE_URL}${API_PATH_PREFIX}/health" 2>&1)
    local get_acao
    get_acao=$(echo "$get_response" | grep -i "access-control-allow-origin" | tr -d '\r' || true)
    local vary
    vary=$(echo "$get_response" | grep -i "^vary:" | tr -d '\r' || true)

    if [[ -z "$get_acao" ]]; then
        log_ok "Pas d'en-tête CORS sur GET (sécurisé)"
        log_report "[OK] Pas de CORS sur GET"
    fi

    echo ""
    if [[ $cors_issues -gt 0 ]]; then
        log_alert "${cors_issues} problème(s) CORS détecté(s) !"
        log_report "[ALERTE] ${cors_issues} problème(s) CORS détecté(s) !"
    else
        log_ok "Configuration CORS sécurisée."
        log_report "[OK] Configuration CORS sécurisée."
    fi
}

# ===========================================================================
# 5. TEST : Analyse JWT
# ===========================================================================
api_test_jwt() {
    log_section "API — Analyse des tokens JWT"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Analyse JWT"
    log_report "========================================"
    log_report ""

    if [[ -z "${API_ACCESS_TOKEN}" ]]; then
        log_warn "Token manquant. Analyse JWT ignorée."
        log_report "[SKIP] Token manquant"
        return
    fi

    local jwt_payload
    jwt_payload=$(echo "$API_ACCESS_TOKEN" | api_decode_jwt)
    local jwt_header
    jwt_header=$(echo "$API_ACCESS_TOKEN" | python3 -c "
import sys, json, base64
token = '${API_ACCESS_TOKEN}'
parts = token.split('.')
if len(parts) == 3:
    try:
        payload = parts[0]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        sys.stdout.write(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))
    except:
        pass
" 2>/dev/null)

    log_info "Header JWT : ${jwt_header}"
    log_info "Payload JWT: ${jwt_payload}"
    log_report "Header JWT: ${jwt_header}"
    log_report "Payload JWT: ${jwt_payload}"

    local alg
    alg=$(echo "$jwt_header" | api_extract_json "alg" 2>/dev/null)
    if [[ "$alg" == "none" ]]; then
        log_alert "JWT sans signature (alg=none) !"
        log_report "[ALERTE] JWT sans signature (alg=none)"
        API_JWT_ISSUES+=("alg=none (pas de signature)")
    elif [[ -n "$alg" ]]; then
        log_ok "Algorithme JWT : ${alg}"
        log_report "[OK] Algorithme JWT : ${alg}"
    fi

    # Vérifier les claims
    local exp
    exp=$(echo "$jwt_payload" | api_extract_json "exp" 2>/dev/null)
    local iat
    iat=$(echo "$jwt_payload" | api_extract_json "iat" 2>/dev/null)

    if [[ -n "$exp" ]] && [[ -n "$iat" ]]; then
        local duration=$((exp - iat))
        log_info "Durée de validité du token : ${duration}s ($((duration / 60)) min)"
        log_report "[OK] Durée JWT: ${duration}s"

        if [[ $duration -gt 86400 ]]; then
            log_warn "Token JWT avec une durée de vie très longue (>24h)"
            log_report "[AVERT] JWT durée excessive: ${duration}s"
            API_JWT_ISSUES+=("JWT durée excessive: ${duration}s")
        fi
    fi

    echo ""
    if [[ ${#API_JWT_ISSUES[@]} -gt 0 ]]; then
        log_alert "${#API_JWT_ISSUES[@]} problème(s) JWT détecté(s) !"
        log_report "[ALERTE] ${#API_JWT_ISSUES[@]} problème(s) JWT"
    else
        log_ok "JWT correctement configuré."
        log_report "[OK] JWT correctement configuré."
    fi
}

# ===========================================================================
# 6. TEST : Rate Limiting
# ===========================================================================
api_test_rate_limit() {
    log_section "API — Test du Rate Limiting"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Test Rate Limiting"
    log_report "========================================"
    log_report ""

    log_info "Envoi de 15 requêtes rapides à /health..."
    local blocked_count=0
    local total_requests=15

    for i in $(seq 1 $total_requests); do
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE_URL}${API_PATH_PREFIX}/health" 2>/dev/null)
        if [[ "$status_code" == "429" ]]; then
            blocked_count=$((blocked_count + 1))
        fi
    done

    if [[ $blocked_count -gt 0 ]]; then
        log_ok "Rate limiting actif : ${blocked_count}/${total_requests} requêtes bloquées"
        log_report "[OK] Rate limiting actif (${blocked_count}/${total_requests} bloquées)"
    else
        log_warn "Aucun rate limiting détecté sur /health (0/${total_requests} bloquées)"
        log_report "[AVERT] Rate limiting absent sur /health"
        API_RATE_LIMIT_ISSUES+=("Pas de rate limit sur /health")
    fi

    # Test OTP rate limiting
    log_info "Test rate limiting OTP..."
    local otp_blocked=0
    for i in $(seq 1 10); do
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "${API_BASE_URL}${API_PATH_PREFIX}/auth/otp/request" \
            -H "Content-Type: application/json" \
            -d '{"email":"ratelimit@test.com"}' 2>/dev/null)
        if [[ "$status_code" == "429" ]]; then
            otp_blocked=$((otp_blocked + 1))
        fi
    done

    if [[ $otp_blocked -gt 0 ]]; then
        log_ok "Rate limiting OTP actif : ${otp_blocked}/10 bloquées"
        log_report "[OK] Rate limiting OTP actif"
    else
        log_warn "Aucun rate limiting OTP détecté"
        log_report "[AVERT] Rate limiting OTP absent"
        API_RATE_LIMIT_ISSUES+=("Pas de rate limit sur OTP")
    fi

    echo ""
}

# ===========================================================================
# 7. TEST : Mass Assignment / Privilege Escalation
# ===========================================================================
api_test_mass_assignment() {
    log_section "API — Test Mass Assignment / Escalade de privilèges"
    log_info "Cible : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  API — Mass Assignment"
    log_report "========================================"
    log_report ""

    if [[ -z "${API_ACCESS_TOKEN}" ]]; then
        log_warn "Token manquant. Test mass assignment ignoré."
        log_report "[SKIP] Token manquant"
        return
    fi

    # Test: Tentative de changer le rôle via update profile
    local role_before
    role_before=$(echo "$API_ACCESS_TOKEN" | api_decode_jwt | api_extract_json "role" 2>/dev/null)
    log_info "Rôle actuel : ${role_before}"

    # Essaie de se promouvoir ADMIN via le profil
    local response
    response=$(api_post "/profile/edit" \
        '{"role":"ADMIN","nom":"Hacked User"}' \
        "${API_ACCESS_TOKEN}")
    local message
    message=$(echo "$response" | api_extract_json "message" 2>/dev/null)
    local data_role
    data_role=$(echo "$response" | api_extract_json "data.role" 2>/dev/null)

    if [[ "$data_role" == "ADMIN" ]]; then
        log_alert "Mass assignment : promotion ADMIN réussie via profile/edit !"
        log_report "[ALERTE] Mass assignment: promotion ADMIN via profile/edit"
        API_MASS_ASSIGNMENT+=("Profile edit: role escalade ADMIN")
    else
        log_ok "Changement de rôle bloqué : ${message:-refusé}"
        log_report "[OK] Changement de rôle protégé: ${message:-refusé}"
    fi

    echo ""
}

# ===========================================================================
# POINT D'ENTRÉE
# ===========================================================================
audit_api_exfil() {
    log_section "AUDIT API — Tests d'exfiltration de données"
    log_info "Cible API : ${API_BASE_URL}${API_PATH_PREFIX}"
    echo ""

    log_report ""
    log_report "================================================================"
    log_report "  AUDIT API — Tests d'exfiltration de données et sécurité"
    log_report "================================================================"
    log_report ""

    api_test_auth_bypass
    api_test_information_disclosure
    api_test_cors
    api_test_jwt
    api_test_rate_limit
    api_test_mass_assignment
    api_test_idor

    # Rapport récapitulatif API
    log_section "RÉCAPITULATIF API"
    echo -e "  Auth bypass      : ${#API_AUTH_BYPASS[@]} endpoint(s) vulnérable(s)"
    echo -e "  IDOR             : ${#API_IDOR_FINDINGS[@]} vulnérabilité(s)"
    echo -e "  Disclosure       : ${#API_DISCLOSURES[@]} divulgation(s)"
    echo -e "  CORS             : ${#API_CORS_ISSUES[@]} problème(s)"
    echo -e "  JWT              : ${#API_JWT_ISSUES[@]} problème(s)"
    echo -e "  Rate Limiting    : ${#API_RATE_LIMIT_ISSUES[@]} problème(s)"
    echo -e "  Mass Assignment  : ${#API_MASS_ASSIGNMENT[@]} problème(s)"
    echo ""

    log_report ""
    log_report "========================================"
    log_report "  RÉCAPITULATIF API"
    log_report "========================================"
    log_report "  Auth bypass      : ${#API_AUTH_BYPASS[@]}"
    log_report "  IDOR             : ${#API_IDOR_FINDINGS[@]}"
    log_report "  Disclosure       : ${#API_DISCLOSURES[@]}"
    log_report "  CORS             : ${#API_CORS_ISSUES[@]}"
    log_report "  JWT              : ${#API_JWT_ISSUES[@]}"
    log_report "  Rate Limiting    : ${#API_RATE_LIMIT_ISSUES[@]}"
    log_report "  Mass Assignment  : ${#API_MASS_ASSIGNMENT[@]}"
    log_report ""
}
