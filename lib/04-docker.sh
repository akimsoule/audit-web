# =============================================================================
# GESTION DOCKER — Vérification, conteneur, outils
# =============================================================================

verifier_docker() {
    log_section "Vérification des prérequis"

    if ! command -v docker &>/dev/null; then
        die "Docker n'est pas installé ou n'est pas dans le PATH.\n" \
            "      Installez Docker : https://docs.docker.com/engine/install/"
    fi
    log_ok "Docker est disponible : $(docker --version)"

    if ! docker info &>/dev/null; then
        die "Le daemon Docker ne répond pas. Vérifiez qu'il est démarré.\n" \
            "      Essayez : sudo systemctl start docker"
    fi
    log_ok "Daemon Docker opérationnel."
}

gerer_conteneur() {
    log_section "Gestion du conteneur Kali Linux"

    local conteneur_existe
    conteneur_existe=$(docker ps -a --filter "name=^${CONTAINER_NAME}$" --format "{{.Names}}" 2>/dev/null || true)

    if [[ -z "$conteneur_existe" ]]; then
        log_info "Conteneur '${CONTAINER_NAME}' absent. Création en cours..."
        detecter_os
        docker run -d \
            --name "${CONTAINER_NAME}" \
            --network "${DOCKER_NETWORK}" \
            "${KALI_IMAGE}" \
            sleep infinity \
            || die "Échec de la création du conteneur Kali."
        log_ok "Conteneur '${CONTAINER_NAME}' créé et démarré."
    else
        local conteneur_running
        conteneur_running=$(docker ps --filter "name=^${CONTAINER_NAME}$" --format "{{.Names}}" 2>/dev/null || true)

        if [[ -z "$conteneur_running" ]]; then
            log_info "Conteneur '${CONTAINER_NAME}' arrêté. Démarrage..."
            docker start "${CONTAINER_NAME}" \
                || die "Échec du démarrage du conteneur '${CONTAINER_NAME}'."
            log_ok "Conteneur '${CONTAINER_NAME}' redémarré."
        else
            log_ok "Conteneur '${CONTAINER_NAME}' déjà en cours d'exécution. Aucune action requise."
        fi
    fi
}

installer_outils() {
    log_section "Vérification / Installation des outils d'audit"

    local outils_a_installer=""
    for outil in $TOOLS; do
        local present
        present=$(docker exec "${CONTAINER_NAME}" which "$outil" 2>/dev/null || true)
        if [[ -z "$present" ]]; then
            log_info "Outil manquant détecté : ${outil}"
            outils_a_installer="${outils_a_installer} ${outil}"
        else
            log_ok "${outil} déjà installé → $(basename "$present")"
        fi
    done

    if [[ -n "$outils_a_installer" ]]; then
        log_info "Installation des outils manquants :${outils_a_installer}"
        docker exec "${CONTAINER_NAME}" bash -c \
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
             apt-get install -y -qq ${outils_a_installer}" \
            || die "Échec de l'installation des outils. Vérifiez la connectivité du conteneur."
        log_ok "Installation terminée."
    else
        log_ok "Tous les outils sont déjà présents. Aucune installation nécessaire."
    fi
}
