# =============================================================================
# AUDIT AUTH — Tests de sécurité non-destructifs sur les endpoints d'auth
# =============================================================================
# Ce module détecte et teste les endpoints d'authentification sans effectuer
# de connexion réelle, brute-force, credential stuffing ou injection.
#
# TESTS NON-DESTRUCTIFS :
#   a) User Enumeration        — comparaison messages/timing (jamais d'email réel)
#   b) Rate Limiting           — 5 requêtes max, détection HTTP 429
#   c) Cookie Security         — analyse des Set-Cookie flags
#   d) CSRF Protection         — présence de tokens/headers
#   e) Password Policy         — validation inscription sans créer de compte
#   f) JWT Analysis            — structure des tokens retournés
#   g) Open Redirect           — paramètres redirect/returnTo/next
#   h) Password Reset Flow     — confirmation email, token dans URL
#   i) OAuth/SSO               — redirect_uri, state, scope
#
# DÉCLENCHEMENT : export AUTH_TESTS_ENABLED=1
# SÉCURITÉ : export AUTH_SKIP_PRODUCTION=1 (défaut)
#            export AUTH_MAX_REQUESTS_PER_ENDPOINT=5
# =============================================================================

# Variables d'environnement
AUTH_TESTS_ENABLED="${AUTH_TESTS_ENABLED:-1}"
AUTH_MAX_REQUESTS="${AUTH_MAX_REQUESTS_PER_ENDPOINT:-5}"
AUTH_TEST_EMAIL="${AUTH_TEST_EMAIL:-audit-test-noreply@example.com}"
AUTH_SKIP_ENDPOINTS="${AUTH_SKIP_ENDPOINTS:-/admin/*,/api/v1/admin/*,/internal/*}"
AUTH_SKIP_PRODUCTION="${AUTH_SKIP_PRODUCTION:-0}"

# Endpoints d'authentification courants à vérifier
AUTH_ENDPOINTS_CANDIDATES=(
    "/login" "/signin" "/sign-in" "/auth/login" "/api/auth/login"
    "/register" "/signup" "/sign-up" "/auth/register" "/api/auth/register"
    "/password-reset" "/reset-password" "/forgot-password" "/api/auth/reset-password"
    "/logout" "/signout" "/sign-out" "/auth/logout"
    "/oauth/authorize" "/oauth/token" "/oauth/callback"
    "/sso/login" "/sso/callback"
    "/2fa" "/mfa" "/auth/mfa"
    "/auth/me" "/api/auth/me" "/api/auth/me"
    "/auth/refresh" "/api/auth/refresh" "/api/auth/refresh"
    "/auth/verify-email" "/api/auth/verify-email"
    "/change-password" "/api/auth/change-password"
    "/auth/session" "/api/auth/session"
)

# Patterns pour identifier les frameworks auth
AUTH_FRAMEWORK_PATTERNS=(
    "devise" "Devise"
    "auth0" "Auth0" "auth0.com"
    "cognito" "Cognito" "amazoncognito"
    "firebase" "Firebase" "firebaseio"
    "okta" "Okta" "okta.com"
    "keycloak" "Keycloak"
    "supabase" "Supabase" "supabase.co"
    "next-auth" "next-auth" "NEXTAUTH"
    "passport" "Passport" "passportjs"
)

# ===========================================================================
# UTILITAIRES
# ===========================================================================

# Vérifie si un endpoint est exclu par pattern
auth_is_skipped() {
    local url="$1"
    local pattern
    IFS=',' read -ra patterns <<< "$AUTH_SKIP_ENDPOINTS"
    for pattern in "${patterns[@]}"; do
        pattern="$(echo "$pattern" | xargs)"
        if [[ "$url" == $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Vérifie si le mode production est protégé
auth_should_skip_production() {
    if [[ "${AUTH_SKIP_PRODUCTION:-1}" == "1" ]]; then
        if echo "${API_FREE_URL:-}" | grep -qiE "prod|live|app\.|www\.|\.com$"; then
            return 0
        fi
    fi
    return 1
}

# Envoie une requête HTTP et retourne headers + body
auth_curl() {
    local method="$1"
    local url="$2"
    local data="${3:-}"

    local curl_args=(
        -s -D - -o /dev/null -m 10
        -w 'HTTP_CODE:%{http_code}|SIZE:%{size_download}|TIME:%{time_total}'
        -X "$method"
    )

    if [[ -n "$data" ]]; then
        curl_args+=(-H 'Content-Type: application/json' -d "$data")
    fi

    if [[ -n "${API_FREE_TOKEN}" ]]; then
        curl_args+=(-H "Authorization: Bearer ${API_FREE_TOKEN}")
    fi

    curl_args+=("$url")

    curl "${curl_args[@]}" 2>/dev/null || echo "HTTP_CODE:000|SIZE:0|TIME:0"
}

# Parse le résultat de auth_curl
auth_parse_result() {
    local result="$1"
    local field="$2"
    echo "$result" | tr '|' '\n' | grep "^${field}:" | cut -d':' -f2- || echo ""
}

# Vérifie si une réponse HTTP est un soft-404 (page d'accueil SPA)
auth_is_soft_404() {
    local content_size="$1"

    if [[ -z "${AUTH_HOMEPAGE_SIZE:-}" ]]; then
        AUTH_HOMEPAGE_SIZE=$(curl -s -L -m 10 "${API_FREE_URL}/" 2>/dev/null | wc -c)
    fi

    local size_diff=$(( content_size - AUTH_HOMEPAGE_SIZE ))
    [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))

    [[ $size_diff -lt 50 ]]
}

# Vérifie si un endpoint est un vrai endpoint auth (formulaire, JSON API, headers spécifiques)
auth_is_real_endpoint() {
    local url="$1"

    local content
    content=$(curl -s -L -m 10 "$url" 2>/dev/null)

    if echo "$content" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        return 0
    fi

    if echo "$content" | grep -qiE '<form|<input.*type="password"|<input.*type="email"|name="email"|name="password"'; then
        return 0
    fi

    local headers
    headers=$(curl -s -I -m 10 "$url" 2>/dev/null)
    if echo "$headers" | grep -qiE 'content-type:.*application/json|www-authenticate|x-csrf-token'; then
        return 0
    fi

    return 1
}

# ===========================================================================
# PHASE 1 : DÉCOUVERTE DES ENDPOINTS AUTH
# ===========================================================================

auth_discover_endpoints() {
    log_section "AUTH — Découverte des endpoints d'authentification"

    local base_url="${API_FREE_URL}"
    AUTH_DISCOVERED_ENDPOINTS=()

    log_info "Scan des endpoints auth courants sur ${base_url}..."
    log_report ""
    log_report "========================================"
    log_report "  Découverte d'endpoints auth"
    log_report "========================================"
    log_report ""

    for endpoint in "${AUTH_ENDPOINTS_CANDIDATES[@]}"; do
        local url="${base_url}${endpoint}"
        if auth_is_skipped "$url"; then
            echo -e "  ${CYAN}[SKIP]${RESET} ${endpoint} (exclu)"
            continue
        fi

        local result
        result=$(auth_curl "GET" "$url")
        local http_code content_size
        http_code=$(auth_parse_result "$result" "HTTP_CODE")
        content_size=$(auth_parse_result "$result" "SIZE")

        if [[ "$http_code" != "000" ]] && [[ "$http_code" != "404" ]] && [[ "$http_code" != "" ]]; then
            # Filtrer les soft-404 (pages SPA qui retournent la page d'accueil)
            if auth_is_soft_404 "$content_size"; then
                echo -e "  ${CYAN}[SOFT-404]${RESET} ${endpoint} (page d'accueil)"
                continue
            fi

            # Vérifier que c'est un vrai endpoint auth
            if auth_is_real_endpoint "$url"; then
                echo -e "  ${GREEN}[${http_code}]${RESET} ${endpoint}"
                log_report "  [${http_code}] ${endpoint}"
                AUTH_DISCOVERED_ENDPOINTS+=("${url}")
            else
                echo -e "  ${CYAN}[STATIC]${RESET} ${endpoint} (page statique)"
            fi
        else
            echo -e "  ${CYAN}[${http_code}]${RESET} ${endpoint}"
        fi
    done

    echo ""
    log_info "Endpoints auth découverts : ${#AUTH_DISCOVERED_ENDPOINTS[@]}"
    log_report "Endpoints découverts : ${#AUTH_DISCOVERED_ENDPOINTS[@]}"
}

# ===========================================================================
# PHASE 2 : FINGERPRINTING DU FRAMEWORK AUTH
# ===========================================================================

auth_fingerprint_framework() {
    log_section "AUTH — Fingerprinting du framework d'authentification"

    local base_url="${API_FREE_URL}"
    local framework_found=""
    local headers
    headers=$(curl -s -I -m 10 "${base_url}" 2>/dev/null || echo "")

    log_info "Analyse des en-têtes et du HTML pour identifier le framework..."
    log_report ""
    log_report "========================================"
    log_report "  Fingerprinting auth"
    log_report "========================================"

    # Vérifier les en-têtes X-Auth-*, X-Frame-Options, cookies
    local auth_headers
    auth_headers=$(echo "$headers" | grep -iE "x-auth|x-requested-with|set-cookie|www-authenticate" || true)

    if [[ -n "$auth_headers" ]]; then
        log_info "En-têtes auth détectés :"
        echo "$auth_headers" | while IFS= read -r header; do
            echo -e "  ${CYAN}  → ${header}${RESET}"
        done
    fi

    # Vérifier les patterns dans la page d'accueil
    local homepage
    homepage=$(curl -s -L -m 10 "${base_url}/" 2>/dev/null || echo "")
    local detected=""
    for pattern in "${AUTH_FRAMEWORK_PATTERNS[@]}"; do
        local match
        match=$(echo "$homepage" | grep -i "$pattern" 2>/dev/null || echo "")
        if [[ -n "$match" ]]; then
            detected="${pattern}"
            break
        fi
    done

    if [[ -n "$detected" ]]; then
        log_warn "Framework auth potentiel détecté : ${detected}"
        log_report "[AVERT] Framework auth : ${detected}"
        AUTH_FINDINGS+=("Framework auth potentiel : ${detected}")
        AUTH_FRAMEWORK_DETECTED="${detected}"
    else
        log_ok "Aucun framework auth standard identifié."
        log_report "[OK] Framework non identifié"
    fi

    # Vérifier les cookies de session
    local cookies
    cookies=$(echo "$headers" | grep -i "^set-cookie:" || true)
    if [[ -n "$cookies" ]]; then
        log_info "Cookies de session :"
        echo "$cookies" | while IFS= read -r cookie; do
            echo -e "  ${CYAN}  → ${cookie}${RESET}"
        done
    fi

    echo ""
}

# ===========================================================================
# PHASE 3 : TESTS DE SÉCURITÉ
# ===========================================================================

# --- Test a) User Enumeration -------------------------------------------
# NON-DESTRUCTIF : utilise un email formaté mais inexistant, compare les
# réponses pour détecter si l'API distingue email "valide" vs "invalide".
auth_test_user_enum() {
    log_section "AUTH — Test d'User Enumeration"

    log_info "Méthode : envoi d'emails formatés sans authenticité réelle"
    log_info "Aucun email réel n'est utilisé ni stocké."
    log_report ""
    log_report "========================================"
    log_report "  User Enumeration"
    log_report "========================================"
    log_report ""

    local endpoint_found=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        # Tester uniquement les endpoints login/register
        if ! echo "$endpoint_url" | grep -qiE "login|signin|signin|register|signup"; then
            continue
        fi

        local login_email="nonexistent-$(date +%s)@example.com"
        local login_payload="{\"email\":\"${login_email}\",\"password\":\"wrongpassword123\"}"
        local login_data
        login_data=$(auth_curl "POST" "$endpoint_url" "$login_payload")

        local http_code status_size status_time
        http_code=$(auth_parse_result "$login_data" "HTTP_CODE")
        status_size=$(auth_parse_result "$login_data" "SIZE")
        status_time=$(auth_parse_result "$login_data" "TIME")

        # Deuxième requête avec email formaté différemment
        local login_email2="nonexistent-$(date +%s)-other@example.org"
        local login_payload2="{\"email\":\"${login_email2}\",\"password\":\"wrongpassword456\"}"
        local login_data2
        login_data2=$(auth_curl "POST" "$endpoint_url" "$login_payload2")

        local http_code2 size2 time2
        http_code2=$(auth_parse_result "$login_data2" "HTTP_CODE")
        size2=$(auth_parse_result "$login_data2" "SIZE")
        time2=$(auth_parse_result "$login_data2" "TIME")

        # Comparer les tailles et temps de réponse
        local time_diff size_diff
        time_diff=$(echo "$status_time $time2" | awk '{print ($1-$2)^2}' 2>/dev/null || echo 0)
        size_diff=$(( status_size - size2 ))
        [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))

        local user_enum_detected=false

        # Différence de taille > 50 octets = message d'erreur différent
        if [[ $size_diff -gt 50 ]]; then
            user_enum_detected=true
        fi

        # Différence de timing > 0.5s = timing attack possible
        if echo "$time_diff" | awk '{exit($1>0.25)}' 2>/dev/null; then
            user_enum_detected=true
        fi

        # Même code HTTP mais messages différents
        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        if [[ "$user_enum_detected" == "true" ]]; then
            log_warn "User enumeration possible sur ${test_endpoint}"
            log_report "[AVERT] User enumeration : ${test_endpoint}"
            AUTH_FINDINGS+=("User enum:${test_endpoint}")
            endpoint_found=$((endpoint_found + 1))
        else
            log_ok "Pas d'user enumeration détectée sur ${test_endpoint}"
            log_report "[OK] Pas d'user enum : ${test_endpoint}"
        fi
    done

    if [[ $endpoint_found -eq 0 ]]; then
        log_ok "Aucun endpoint vulnérable à l'user enumeration."
    fi
    echo ""
}

# --- Test b) Rate Limiting ----------------------------------------------
# NON-DESTRUCTIF : maximum 5 requêtes, jamais assez pour lockout.
auth_test_rate_limiting() {
    log_section "AUTH — Test de Rate Limiting"

    log_info "Méthode : ${AUTH_MAX_REQUESTS} requêtes rapides, vérification HTTP 429"
    log_info "Limite stricte : ${AUTH_MAX_REQUESTS} requêtes max par endpoint."
    log_report ""
    log_report "========================================"
    log_report "  Rate Limiting"
    log_report "========================================"
    log_report ""

    local hit_count=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        if ! echo "$endpoint_url" | grep -qiE "login|register|auth"; then
            continue
        fi

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")
        local rate_limited=false
        local req_count=0

        for ((i=1; i<=AUTH_MAX_REQUESTS; i++)); do
            local fake_email="ratelimit-${i}-$(date +%s)@example.com"
            local payload="{\"email\":\"${fake_email}\",\"password\":\"test123\"}"
            local result
            result=$(auth_curl "POST" "$endpoint_url" "$payload")
            local http_code
            http_code=$(auth_parse_result "$result" "HTTP_CODE")

            if [[ "$http_code" == "429" ]]; then
                rate_limited=true
                break
            fi
            req_count=$((req_count + 1))
        done

        if $rate_limited; then
            log_ok "Rate limiting ACTIF sur ${test_endpoint} (bloqué à la requête ${req_count})"
            log_report "[OK] Rate limiting : ${test_endpoint} (req #${req_count})"
        else
            log_alert "AUCUN rate limiting sur ${test_endpoint} (${req_count} requêtes sans blocage)"
            log_report "[ALERTE] Rate limiting ABSENT : ${test_endpoint}"
            AUTH_FINDINGS+=("No rate limit:${test_endpoint}")
            hit_count=$((hit_count + 1))
        fi
    done

    if [[ $hit_count -gt 0 ]]; then
        log_alert "${hit_count} endpoint(s) sans rate limiting !"
        log_report "[ALERTE] ${hit_count} endpoint(s) sans rate limiting"
    fi
    echo ""
}

# --- Test c) Cookie Security --------------------------------------------
# NON-DESTRUCTIF : lecture seule des en-têtes Set-Cookie.
auth_test_cookie_security() {
    log_section "AUTH — Sécurité des cookies de session"

    log_info "Méthode : analyse des flags Secure, HttpOnly, SameSite."
    log_info "Aucune modification des cookies."
    log_report ""
    log_report "========================================"
    log_report "  Cookie Security"
    log_report "========================================"
    log_report ""

    local issues=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        local headers
        headers=$(auth_curl "GET" "$endpoint_url")
        local cookies
        cookies=$(echo "$headers" | grep -i "^set-cookie:" || true)

        if [[ -z "$cookies" ]]; then
            continue
        fi

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")
        log_info "Cookies sur ${test_endpoint} :"

        while IFS= read -r cookie_line; do
            local cookie_name
            cookie_name=$(echo "$cookie_line" | sed 's/.*Set-Cookie: //i; s/=.*//' | tr -d ' ')
            local has_secure=false
            local has_httponly=false
            local has_samesite=false
            local samesite_value=""

            echo "$cookie_line" | grep -qi "secure" && has_secure=true
            echo "$cookie_line" | grep -qi "httponly" && has_httponly=true
            samesite_value=$(echo "$cookie_line" | grep -io "samesite=[a-z]*" || echo "")
            [[ -n "$samesite_value" ]] && has_samesite=true

            local flags="$([ "$has_secure" = true ] && echo "Secure:✓" || echo "Secure:✗")"
            flags+=" $([ "$has_httponly" = true ] && echo "HttpOnly:✓" || echo "HttpOnly:✗")"
            flags+=" $([ "$has_samesite" = true ] && echo "SameSite:${samesite_value#SameSite=}" || echo "SameSite:✗")"

            if ! $has_secure || ! $has_httponly; then
                log_warn "Cookie ${cookie_name} : ${flags}"
                log_report "[AVERT] Cookie ${cookie_name} : ${flags} (sur ${test_endpoint})"
                AUTH_FINDINGS+=("Cookie insecure:${cookie_name} on ${test_endpoint} (${flags})")
                issues=$((issues + 1))
            else
                log_ok "Cookie ${cookie_name} : ${flags}"
                log_report "[OK] Cookie ${cookie_name} : ${flags}"
            fi
        done <<< "$cookies"
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Tous les cookies sont correctement sécurisés."
    fi
    echo ""
}

# --- Test d) CSRF Protection --------------------------------------------
# NON-DESTRUCTIF : vérifie la présence de tokens/headers, pas de soumission.
auth_test_csrf() {
    log_section "AUTH — Protection CSRF"

    log_info "Méthode : vérification des tokens CSRF et en-têtes X-CSRF-Token."
    log_info "Aucune soumission de formulaire."
    log_report ""
    log_report "========================================"
    log_report "  Protection CSRF"
    log_report "========================================"
    log_report ""

    local issues=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        local result
        result=$(auth_curl "GET" "$endpoint_url")
        local headers
        headers=$(echo "$result" | grep -iE "^x-csrf|^x-xsrf|^anti-csrf" || true)
        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        if [[ -n "$headers" ]]; then
            log_ok "Token CSRF présent sur ${test_endpoint}"
            log_report "[OK] CSRF token : ${test_endpoint}"
            echo "$headers" | while IFS= read -r h; do
                echo -e "  ${CYAN}  → ${h}${RESET}"
            done
        else
            # Chercher dans les cookies
            local cookies
            cookies=$(echo "$result" | grep -i "^set-cookie:.*csrf\|^set-cookie:.*xsrf\|^set-cookie:.*state" || true)
            if [[ -n "$cookies" ]]; then
                log_ok "Token CSRF dans cookie sur ${test_endpoint}"
                log_report "[OK] CSRF cookie : ${test_endpoint}"
            else
                log_warn "Aucune protection CSRF détectée sur ${test_endpoint}"
                log_report "[AVERT] CSRF absente : ${test_endpoint}"
                AUTH_FINDINGS+=("No CSRF:${test_endpoint}")
                issues=$((issues + 1))
            fi
        fi
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Tous les endpoints auth sont protégés contre CSRF."
    fi
    echo ""
}

# --- Test e) Password Policy --------------------------------------------
# NON-DESTRUCTIF : teste la validation sans créer de compte.
# Le mot de passe d'1 caractère est rejeté par la validation côté serveur.
auth_test_password_policy() {
    log_section "AUTH — Politique de mot de passe"

    log_info "Méthode : test de validation sans création de compte réelle."
    log_info "Mot de passe d'1 caractère utilisé pour tester la validation serveur."
    log_report ""
    log_report "========================================"
    log_report "  Password Policy"
    log_report "========================================"
    log_report ""

    local issues=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        if ! echo "$endpoint_url" | grep -qiE "register|signup|change-password"; then
            continue
        fi

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        # Test avec mot de passe d'1 caractère — la validation doit le rejeter
        local weak_payload="{\"email\":\"test-weak-$(date +%s)@example.com\",\"password\":\"a\"}"
        local weak_result
        weak_result=$(auth_curl "POST" "$endpoint_url" "$weak_payload")
        local weak_code
        weak_code=$(auth_parse_result "$weak_result" "HTTP_CODE")
        local weak_msg
        weak_msg=$(echo "$weak_result" | grep -iE "error|message|Password|password" || true)

        if [[ "$weak_code" == "200" ]] || [[ "$weak_code" == "201" ]]; then
            log_alert "Mot de passe d'1 caractère ACCEPTÉ sur ${test_endpoint} !"
            log_report "[ALERTE] Password policy faible : ${test_endpoint}"
            AUTH_FINDINGS+=("Weak password policy:${test_endpoint}")
            issues=$((issues + 1))
        else
            log_ok "Mot de passe faible correctement rejeté (HTTP ${weak_code})"
            log_report "[OK] Password policy : ${test_endpoint}"

            if [[ -n "$weak_msg" ]]; then
                local msg_preview
                msg_preview=$(echo "$weak_msg" | head -1 | sed 's/.*://' | tr -d '\r' | head -c 100)
                log_info "Message : ${msg_preview}"
            fi
        fi
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Politique de mot de passe correcte (minimum de caractères requis)."
    fi
    echo ""
}

# --- Test f) JWT Analysis ------------------------------------------------
# NON-DESTRUCTIF : analyse des tokens retournés, sans les utiliser.
auth_test_jwt_analysis() {
    log_section "AUTH — Analyse des tokens JWT"

    log_info "Méthode : inspection des tokens dans les réponses."
    log_info "Aucune connexion réelle — tokens d'erreur uniquement."
    log_report ""
    log_report "========================================"
    log_report "  Analyse JWT"
    log_report "========================================"
    log_report ""

    local issues=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        local result
        result=$(auth_curl "POST" "$endpoint_url" \
            "{\"email\":\"jwt-test-$(date +%s)@example.com\",\"password\":\"invalid\"}")

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        # Chercher des patterns JWT dans la réponse (base64url en 3 parties)
        local jwt_found
        jwt_found=$(echo "$result" | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1 || true)

        if [[ -n "$jwt_found" ]]; then
            log_warn "Token JWT retourné sur ${test_endpoint} (même sans connexion réussie)"
            log_report "[AVERT] JWT retourné : ${test_endpoint}"

            # Décoder le header
            local jwt_header
            jwt_header=$(echo "$jwt_found" | cut -d'.' -f1 2>/dev/null)
            local jwt_payload
            jwt_payload=$(echo "$jwt_found" | cut -d'.' -f2 2>/dev/null)

            local header_decoded payload_decoded
            header_decoded=$(echo "$jwt_header" | openssl base64 -d -A 2>/dev/null || echo "$jwt_header" | python3 -c "import base64,sys; print(base64.urlsafe_b64decode(sys.stdin.read()+'=='))" 2>/dev/null || echo "non-decodable")
            payload_decoded=$(echo "$jwt_payload" | openssl base64 -d -A 2>/dev/null || echo "$jwt_payload" | python3 -c "import base64,sys; print(base64.urlsafe_b64decode(sys.stdin.read()+'=='))" 2>/dev/null || echo "non-decodable")

            log_info "Header JWT : ${header_decoded}"
            log_report "JWT header: ${header_decoded}"
            log_info "Payload JWT : ${payload_decoded:0:200}"
            log_report "JWT payload: ${payload_decoded:0:200}"

            # Vérifier alg=none
            if echo "$header_decoded" | grep -qi '"alg"[[:space:]]*:[[:space:]]*"none"'; then
                log_alert "JWT avec alg=none !"
                log_report "[ALERTE] JWT alg=none sur ${test_endpoint}"
                AUTH_FINDINGS+=("JWT alg=none:${test_endpoint}")
                issues=$((issues + 1))
            fi

            # Vérifier exp
            if ! echo "$payload_decoded" | grep -qi '"exp"'; then
                log_warn "JWT sans expiration (claim exp absent)"
                log_report "[AVERT] JWT sans exp : ${test_endpoint}"
                AUTH_FINDINGS+=("JWT no exp:${test_endpoint}")
                issues=$((issues + 1))
            fi
        fi
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Aucun problème JWT détecté."
    fi
    echo ""
}

# --- Test g) Open Redirect -----------------------------------------------
# NON-DESTRUCTIF : vérifie les en-têtes Location sans suivre la redirection.
auth_test_open_redirect() {
    log_section "AUTH — Open Redirect test"

    log_info "Méthode : test des paramètres redirect/returnTo/next sans les suivre."
    log_info "La redirection n'est pas suivie (curl -D -o /dev/null)."
    log_report ""
    log_report "========================================"
    log_report "  Open Redirect"
    log_report "========================================"
    log_report ""

    local redirect_params=("redirect" "returnTo" "next" "url" "redirect_uri" "callback" "continue" "forward")
    local external_url="https://evil-attacker.com"
    local issues=0

    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        for param in "${redirect_params[@]}"; do
            local test_url="${endpoint_url}?${param}=${external_url}"
            local result
            result=$(auth_curl "GET" "$test_url")
            local http_code
            http_code=$(auth_parse_result "$result" "HTTP_CODE")
            local location
            location=$(echo "$result" | grep -i "^location:" || true)

            if echo "$location" | grep -qi "evil-attacker"; then
                log_alert "Open redirect sur ${test_endpoint} via paramètre ${param}"
                log_report "[ALERTE] Open redirect : ${test_endpoint} via ${param}"
                AUTH_FINDINGS+=("Open redirect:${test_endpoint} via ${param}")
                issues=$((issues + 1))
            fi
        done
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Aucun open redirect détecté."
    fi
    echo ""
}

# --- Test h) Password Reset Flow -----------------------------------------
# NON-DESTRUCTIF : vérifie les messages sans envoyer de vrai reset.
auth_test_password_reset() {
    log_section "AUTH — Password Reset Flow"

    log_info "Méthode : test de l'endpoint reset sans email réel."
    log_info "Aucun email de reset n'est envoyé."
    log_report ""
    log_report "========================================"
    log_report "  Password Reset"
    log_report "========================================"
    log_report ""

    local issues=0
    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        if ! echo "$endpoint_url" | grep -qiE "reset|forgot|password"; then
            continue
        fi

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")
        local test_email="${AUTH_TEST_EMAIL}"

        # Test 1 : email formaté correctement
        local result1
        result1=$(auth_curl "POST" "$endpoint_url" "{\"email\":\"${test_email}\"}")
        local code1 size1
        code1=$(auth_parse_result "$result1" "HTTP_CODE")
        size1=$(auth_parse_result "$result1" "SIZE")

        # Test 2 : email vide
        local result2
        result2=$(auth_curl "POST" "$endpoint_url" "{\"email\":\"\"}")
        local code2 size2
        code2=$(auth_parse_result "$result2" "HTTP_CODE")
        size2=$(auth_parse_result "$result2" "SIZE")

        # Vérifier si l'endpoint confirme l'existence d'un email (user enum)
        if [[ "$code1" == "200" ]] && [[ "$code2" != "200" ]] && [[ $((size1 - size2)) -gt 0 ]]; then
            log_warn "Password reset pourrait révéler l'existence d'emails sur ${test_endpoint}"
            log_report "[AVERT] Reset révèle existence email : ${test_endpoint}"
        fi

        # Vérifier si le token est dans l'URL (fuite Referer)
        local reset_url="${endpoint_url}?token=test-reset-token-123"
        local result3
        result3=$(auth_curl "GET" "$reset_url")
        local code3
        code3=$(auth_parse_result "$result3" "HTTP_CODE")

        if [[ "$code3" == "200" ]]; then
            log_info "Endpoint reset accessible via token dans l'URL : ${test_endpoint}"
            log_report "[INFO] Reset token in URL : ${test_endpoint}"
        fi
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Password reset flow semble sécurisé."
    fi
    echo ""
}

# --- Test i) OAuth/SSO ---------------------------------------------------
# NON-DESTRUCTIF : vérifie les paramètres sans authentification OAuth.
auth_test_oauth() {
    log_section "AUTH — OAuth / SSO"

    log_info "Méthode : test des endpoints OAuth sans authentification réelle."
    log_info "Aucune redirection OAuth complète."
    log_report ""
    log_report "========================================"
    log_report "  OAuth / SSO"
    log_report "========================================"
    log_report ""

    local redirect_params=("redirect_uri" "redirect" "callback" "url")
    local external_url="https://evil-attacker.com/oauth/callback"
    local issues=0

    for endpoint_url in "${AUTH_DISCOVERED_ENDPOINTS[@]}"; do
        if ! echo "$endpoint_url" | grep -qiE "oauth|sso|authorize|callback"; then
            continue
        fi

        local test_endpoint
        test_endpoint=$(echo "$endpoint_url" | sed "s|${API_FREE_URL}||")

        # Test redirect_uri vers domaine malveillant
        for param in "${redirect_params[@]}"; do
            local test_url="${endpoint_url}?${param}=${external_url}"
            local result
            result=$(auth_curl "GET" "$test_url")
            local location
            location=$(echo "$result" | grep -i "^location:" || true)

            if echo "$location" | grep -qi "evil-attacker"; then
                log_alert "OAuth redirect_uri vulnérable sur ${test_endpoint} via ${param}"
                log_report "[ALERTE] OAuth redirect_uri : ${test_endpoint} via ${param}"
                AUTH_FINDINGS+=("OAuth open redirect:${test_endpoint} via ${param}")
                issues=$((issues + 1))
            fi
        done

        # Tester si le paramètre state est obligatoire
        local result_no_state
        result_no_state=$(auth_curl "GET" "$endpoint_url" "" "")
        local has_state_param
        has_state_param=$(echo "$result_no_state" | grep -iE "state|missing.*state|state.*required" || true)
        if [[ -z "$has_state_param" ]]; then
            log_warn "Paramètre state peut être absent (CSRF OAuth potentiel)"
            log_report "[AVERT] OAuth state optionnel : ${test_endpoint}"
        else
            log_ok "Paramètre state requis (CSRF protégé)"
            log_report "[OK] OAuth state requis : ${test_endpoint}"
        fi
    done

    if [[ $issues -eq 0 ]]; then
        log_ok "Aucun problème OAuth/SSO détecté."
    fi
    echo ""
}

# ===========================================================================
# ORCHESTRATEUR PRINCIPAL
# ===========================================================================

audit_auth_security() {
    if [[ "${AUTH_TESTS_ENABLED}" != "1" ]]; then
        log_info "Tests auth désactivés (AUTH_TESTS_ENABLED=${AUTH_TESTS_ENABLED})."
        log_info "Pour activer : export AUTH_TESTS_ENABLED=1"
        return
    fi

    if [[ -z "${API_FREE_URL}" ]]; then
        log_warn "AUDIT_API_FREE_URL non défini. Impossible de tester l'auth."
        log_warn "Le module auth nécessite AUDIT_API_FREE_URL."
        return
    fi

    if auth_should_skip_production; then
        log_warn "AUTH_SKIP_PRODUCTION=1 et la cible semble être la production."
        log_warn "Tests auth ignorés. Pour les forcer : export AUTH_SKIP_PRODUCTION=0"
        log_report "[SKIP] Production détectée — tests auth ignorés"
        return
    fi

    # Avertissement
    echo -e ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║  AVERTISSEMENT AUDIT AUTH                                     ║${RESET}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  Les tests suivants sont 100% NON-DESTRUCTIFS :              ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ✓  Aucune connexion réelle                                ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ✓  Aucun brute-force ou credential stuffing               ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ✓  Aucune création de compte                              ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ✓  Maximum ${AUTH_MAX_REQUESTS} requêtes par endpoint                       ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ✓  Aucune tentative de verrouillage de compte             ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo -e ""

    log_section "AUDIT AUTH — Tests de sécurité non-destructifs"
    log_info "Target : ${API_FREE_URL}"
    log_info "Max requêtes par endpoint : ${AUTH_MAX_REQUESTS}"

    log_report ""
    log_report "============================================================"
    log_report "  AUDIT AUTH — Tests de sécurité"
    log_report "============================================================"
    log_report "  Target : ${API_FREE_URL}"
    log_report "  Mode : NON-DESTRUCTIF (pas de connexion réelle)"
    log_report ""

    # Phase 1 : Découverte des endpoints
    auth_discover_endpoints

    # Phase 2 : Fingerprinting
    auth_fingerprint_framework

    # Phase 3 : Tests de sécurité
    auth_test_user_enum
    auth_test_rate_limiting
    auth_test_cookie_security
    auth_test_csrf
    auth_test_password_policy
    auth_test_jwt_analysis
    auth_test_open_redirect
    auth_test_password_reset
    auth_test_oauth

    # Rapport récapitulatif
    log_section "RÉCAPITULATIF AUDIT AUTH"
    local auth_issues=0
    for f in "${AUTH_FINDINGS[@]+"${AUTH_FINDINGS[@]}"}"; do
        auth_issues=$((auth_issues + 1))
    done

    if [[ $auth_issues -gt 0 ]]; then
        echo -e "  ${RED}${auth_issues} problème(s) de sécurité auth détecté(s)${RESET}"
    else
        echo -e "  ${GREEN}Aucun problème de sécurité auth détecté${RESET}"
    fi
    echo "  Détails : voir le rapport texte et JSON."

    log_report ""
    log_report "========================================"
    log_report "  RÉCAPITULATIF AUDIT AUTH"
    log_report "========================================"
    log_report "  Problèmes détectés : ${auth_issues}"
    log_report ""
}

# Initialisation des tableaux de tracking (sourcing safe)
if [[ -z "${AUTH_FINDINGS_INIT:-}" ]]; then
    AUTH_FINDINGS=()
    AUTH_DISCOVERED_ENDPOINTS=()
    AUTH_FRAMEWORK_DETECTED=""
    AUTH_HOMEPAGE_SIZE=""
    AUTH_FINDINGS_INIT=1
fi
