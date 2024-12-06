#!/bin/bash

# Script pour scanner un réseau avec Nmap et récupérer des informations sur les vulnérabilités CVE
# Utilisation : ./nmap_scan.sh

# Couleurs pour l'affichage
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Vérifier si Nmap est installé
if ! command -v nmap &> /dev/null
then
    echo -e "${RED}Nmap n'est pas installé. Veuillez l'installer pour continuer.${NC}"
    exit
fi

# Vérifier si curl est installé
if ! command -v curl &> /dev/null
then
    echo -e "${RED}curl n'est pas installé. Veuillez l'installer pour continuer.${NC}"
    exit
fi

# Découvrir tous les hôtes sur le réseau
network_range="$(ip -o -f inet addr show | awk '/scope global/ {print $4}')"
echo -e "${GREEN}Recherche des hôtes sur le réseau : $network_range ...${NC}"
nmap -sn "$network_range" -oG - | awk '/Up$/{print $2}' > hosts.txt

# Lire tous les hôtes détectés
hosts=( $(cat hosts.txt) )
if [ ${#hosts[@]} -eq 0 ]; then
    echo -e "${RED}Aucun hôte trouvé sur le réseau.${NC}"
    exit
fi

echo -e "${GREEN}Hôtes trouvés :${NC}"
for host in "${hosts[@]}"; do
    echo -e "${BLUE}- $host${NC}"
done

# Scanner chaque hôte pour obtenir des informations détaillées
for host in "${hosts[@]}"; do
    echo -e "${GREEN}\nAnalyse de l'hôte : $host ...${NC}"
    output=$(nmap -sS -sV -O "$host")
    echo -e "${BLUE}-------------------------------${NC}"
    echo -e "${GREEN}Adresse IP : ${NC}$host"
    echo -e "${GREEN}Ports ouverts :${NC}"
    echo "$output" | grep -E "^[0-9]+/tcp.*open" | awk '{printf "  - Port: %-5s | Service: %-15s | Version: %s\n", $1, $3, $4}'
    echo -e "${GREEN}Système d'exploitation détecté :${NC}"
    os=$(echo "$output" | grep "OS details")
    if [ -n "$os" ]; then
        echo "$os" | sed 's/OS details: //'
    else
        echo -e "${RED}Non détecté${NC}"
    fi
    echo -e "${BLUE}-------------------------------${NC}"
    echo "$output" > "scan_$host.txt"
    echo -e "${GREEN}Résultats enregistrés dans scan_$host.txt${NC}"
    cat "scan_$host.txt"
done

# Fonction pour obtenir des CVE à partir de NVD
get_cve() {
    local service_name=$1
    echo -e "${GREEN}\nRecherche de vulnérabilités pour le service : ${service_name}${NC}"
    cve_data=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$service_name")

    # Vérifier si la réponse JSON est valide
    if echo "$cve_data" | jq . &>/dev/null; then
        vulnerabilities=$(echo "$cve_data" | jq '.result.CVE_Items[]? | {id: .cve.CVE_data_meta.ID, description: .cve.description.description_data[0].value}')
        if [ -n "$vulnerabilities" ]; then
            echo "$vulnerabilities" | jq -r '. | "- CVE: \(.id) - \(.description)"'
        else
            echo -e "${RED}Aucune vulnérabilité trouvée pour ce service.${NC}"
        fi
    else
        echo -e "${RED}Erreur lors de la récupération des données pour le service : ${service_name}.${NC}"
    fi
}


# Option pour détecter les failles communes
read -p "Voulez-vous vérifier les failles communes (CVE) pour les services détectés ? (y/n): " check_vulns
if [ "$check_vulns" == "y" ]; then
    for host in "${hosts[@]}"; do
        echo -e "${GREEN}\nRecherche de failles potentielles pour l'hôte : $host ...${NC}"
        services=$(grep -Eo "^[0-9]+/tcp.*open.*" "scan_$host.txt" | awk '{print $3}')
        for service in $services; do
            get_cve "$service"
        done
    done
fi

# Nettoyage
rm hosts.txt

echo -e "${GREEN}\nAnalyse réseau terminée.${NC}"
exit 0
