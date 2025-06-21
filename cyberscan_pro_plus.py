
# =============================
# CYBERSCAN PRO+ – Scanner de sécurité réseau local
# =============================

import socket
import subprocess
import os
import datetime
import time
import sys

# 🔧 Variables globales
invalid_count = 0
historique_file = "historique.txt"

# 📄 Fonction pour écrire dans le fichier d'historique
def enregistrer_historique(message):
    with open(historique_file, "a", encoding="utf-8") as file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp} - {message}\n")

# 🖊 Fonction pour écrire un rapport unique pour le domaine
def ecrire_rapport(domaine, contenu):
    nom_fichier = f"rapport_{domaine.replace('.', '_')}.txt"
    with open(nom_fichier, "w", encoding="utf-8") as f:
        f.write(contenu)

# 🧪 Fonction de scan de ports et lecture de bannières
def scanner_ports(ip, ports=[22, 80, 443, 3306]):
    resultat = ""
    ouverts = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                ouverts.append(port)
                resultat += f"✅ Port {port} ouvert\n"
                try:
                    bannière = s.recv(1024).decode(errors="ignore").strip()
                    if bannière:
                        resultat += f"    Bannière : {bannière}\n"
                except:
                    resultat += f"    Aucune bannière détectée\n"
        except:
            resultat += f"❌ Port {port} fermé\n"
    return resultat, ouverts

# 🌐 Vérification HTTPS
def verifier_https(ip):
    try:
        with socket.create_connection((ip, 443), timeout=3):
            return True
    except:
        return False

# 🌍 Reverse DNS
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

# 🔁 Boucle principale
while True:
    domaine = input("Entrez un nom de domaine (ou 'exit' pour quitter) : ")

    if domaine.lower() == "exit":
        print("Fin du programme.")
        break

    try:
        # Résolution IP
        ip = socket.gethostbyname(domaine)
        print(f"✅ IP de {domaine} : {ip}")
        enregistrer_historique(f"Résolution IP : {domaine} → {ip}")
        invalid_count = 0

        # Ping
        if sys.platform.startswith("win"):
            ping_option = "-n"
        else:
            ping_option = "-c"

        cmd = ["ping", ping_option, "3", domaine]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        sortie_ping = result.stdout
        perte = "inconnue"
        for ligne in sortie_ping.splitlines():
            if "perte" in ligne or "loss" in ligne.lower():
                perte = ligne.strip()
                break
        print(f"📡 Résultat du ping :\n{sortie_ping}")
        enregistrer_historique(f"Ping → {perte}")

        # Analyse TTL
        ttl_detecte = None
        for ligne in sortie_ping.splitlines():
            if "TTL=" in ligne.upper():
                mots = ligne.replace("=", " ").split()
                for i, mot in enumerate(mots):
                    if mot.upper() == "TTL":
                        try:
                            ttl_detecte = int(mots[i + 1])
                            break
                        except:
                            pass
                if ttl_detecte:
                    break
        os_estime = "Inconnu"
        if ttl_detecte:
            if ttl_detecte <= 64:
                os_estime = "Linux/Unix"
            elif ttl_detecte <= 128:
                os_estime = "Windows"
            elif ttl_detecte <= 255:
                os_estime = "Cisco/Routeur"
        print(f"🔍 TTL : {ttl_detecte} → OS estimé : {os_estime}")
        enregistrer_historique(f"TTL {ttl_detecte} → OS estimé : {os_estime}")

        # Reverse DNS
        nom_machine = reverse_dns(ip)
        print(f"🔁 Nom de machine (reverse DNS) : {nom_machine}")
        enregistrer_historique(f"Reverse DNS : {ip} → {nom_machine}")

        # Scan de ports et bannières
        scan_resultat, ports_ouverts = scanner_ports(ip)
        print(scan_resultat)
        enregistrer_historique(f"Scan ports :\n{scan_resultat.strip()}")

        # Test HTTP GET manuel
        try:
            with socket.create_connection((ip, 80), timeout=3) as s:
                requete = f"GET / HTTP/1.1\r\nHost: {domaine}\r\n\r\n"
                s.sendall(requete.encode())
                reponse_http = s.recv(2048).decode(errors="ignore")
                print(f"🌐 Réponse HTTP brute :\n{reponse_http.splitlines()[0]}")
                enregistrer_historique(f"HTTP GET → {reponse_http.splitlines()[0]}")
        except:
            print("❌ Échec requête HTTP GET")
            enregistrer_historique("Échec requête HTTP GET")

        # Vérification HTTPS
        if verifier_https(ip):
            print("🔒 HTTPS actif (port 443 ouvert)")
            enregistrer_historique("HTTPS : actif")
        else:
            print("🔓 HTTPS inactif (port 443 fermé)")
            enregistrer_historique("HTTPS : inactif")

        # Scan de sous-domaines basiques
        sous_domaines = ["www", "mail", "admin", "webmail", "ftp"]
        print("🔎 Scan de sous-domaines :")
        for sub in sous_domaines:
            fqdn = f"{sub}.{domaine}"
            try:
                ip_sub = socket.gethostbyname(fqdn)
                print(f"  ✅ {fqdn} → {ip_sub}")
                enregistrer_historique(f"Sous-domaine trouvé : {fqdn} → {ip_sub}")
            except:
                print(f"  ❌ {fqdn} introuvable")

        # Rapport texte
        ascii_graph = "".join(["■ " if p in ports_ouverts else "□ " for p in [22, 80, 443, 3306]])
        contenu_rapport = f"""Rapport CYBERSCAN PRO+ – {domaine}
Adresse IP : {ip}
Nom de machine : {nom_machine}
OS estimé : {os_estime}
Résultat du ping : {perte}
Ports scannés :
{scan_resultat}
HTTPS : {"actif" if 443 in ports_ouverts else "inactif"}
Graphique ASCII ports : {ascii_graph}
""" 
        ecrire_rapport(domaine, contenu_rapport)
        print("📝 Rapport généré.")

    except socket.gaierror:
        invalid_count += 1
        print(f"❌ Domaine invalide : {domaine}")
        enregistrer_historique(f"Échec résolution DNS : {domaine}")
        if invalid_count >= 3:
            print("⚠️ 3 domaines invalides consécutifs. Arrêt.")
            break
