# =============================================================================
# AVERTISSEMENT LÉGAL ET ÉTHIQUE
# =============================================================================
# Raison de sécurité : Tout outil d'audit, même passif, peut générer du
# trafic réseau et des entrées dans les journaux de la cible. Son utilisation
# sans autorisation écrite constitue une infraction pénale dans la plupart
# des juridictions (CFAA aux USA, directive NIS2 en Europe, etc.).
# =============================================================================

afficher_avertissement_legal() {
    clear
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║           ⚠️  AVERTISSEMENT LÉGAL ET ÉTHIQUE OBLIGATOIRE ⚠️           ║"
    echo "╠══════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                      ║"
    echo "║  CET OUTIL EST RÉSERVÉ EXCLUSIVEMENT À UN USAGE DÉFENSIF AUTORISÉ.  ║"
    echo "║                                                                      ║"
    echo "║  AVANT TOUTE UTILISATION, VOUS DEVEZ :                              ║"
    echo "║                                                                      ║"
    echo "║  ✔  Posséder une AUTORISATION ÉCRITE ET EXPLICITE du propriétaire   ║"
    echo "║     légal de l'application web cible.                               ║"
    echo "║                                                                      ║"
    echo "║  ✔  Vous assurer que l'exécution de cet audit ne compromettra PAS  ║"
    echo "║     la DISPONIBILITÉ ni l'INTÉGRITÉ de l'environnement de           ║"
    echo "║     production (préférer une fenêtre de maintenance).               ║"
    echo "║                                                                      ║"
    echo "║  ✔  Informer les équipes opérationnelles (SOC/NOC) avant le lancement║"
    echo "║     afin d'éviter de déclencher des alertes de sécurité non prévues.║"
    echo "║                                                                      ║"
    echo "║  INTERDICTIONS ABSOLUES :                                            ║"
    echo "║  ✗  Usage sur des systèmes tiers sans consentement = DÉLIT PÉNAL.   ║"
    echo "║  ✗  Ce script ne contient aucune exploitation active, bruteforce,   ║"
    echo "║     injection ou tentative de connexion. Toute modification visant  ║"
    echo "║     à contourner cette limitation engage votre responsabilité.       ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    read -r -p "$(echo -e "${BOLD}Confirmez-vous posséder une autorisation écrite ? [oui/NON] :${RESET} ")" REPONSE
    if [[ "${REPONSE}" != "oui" ]]; then
        die "Audit annulé. Vous devez confirmer disposer d'une autorisation écrite."
    fi
    echo ""
}
