"""
Module VulnScan Pro : port_scanner
Scan TCP des 20 ports les plus courants sur le serveur cible.
Évalue le niveau de risque selon les services exposés.
"""
import sys
import json
import argparse
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

sys.path.insert(0, '..')
from core.base_module import BaseModule


# Ports à scanner avec leur service et sévérité associés
PORTS = {
    21:   {"service": "FTP",         "severity": "HIGH",     "cvss": 7.5,
           "desc": "FTP (port 21) est ouvert. Ce protocole transmet les données et identifiants en clair."},
    22:   {"service": "SSH",         "severity": "MEDIUM",   "cvss": 5.3,
           "desc": "SSH (port 22) est ouvert. Bien que chiffré, une exposition publique augmente la surface d'attaque (brute-force)."},
    23:   {"service": "Telnet",      "severity": "CRITICAL", "cvss": 9.8,
           "desc": "Telnet (port 23) est ouvert. Ce protocole transmet tout en clair, y compris les mots de passe."},
    25:   {"service": "SMTP",        "severity": "MEDIUM",   "cvss": 5.3,
           "desc": "SMTP (port 25) est ouvert. Peut être utilisé pour du spam ou de l'énumération d'utilisateurs."},
    80:   {"service": "HTTP",        "severity": "LOW",      "cvss": 3.1,
           "desc": "HTTP (port 80) est ouvert. Le trafic n'est pas chiffré (pas de HTTPS)."},
    443:  {"service": "HTTPS",       "severity": "LOW",      "cvss": 0.0,
           "desc": "HTTPS (port 443) est ouvert. Trafic chiffré — service attendu."},
    3306: {"service": "MySQL",       "severity": "CRITICAL", "cvss": 9.8,
           "desc": "MySQL (port 3306) est accessible depuis l'extérieur. La base de données ne devrait jamais être exposée sur Internet."},
    5432: {"service": "PostgreSQL",  "severity": "CRITICAL", "cvss": 9.8,
           "desc": "PostgreSQL (port 5432) est accessible depuis l'extérieur. La base de données ne devrait jamais être exposée sur Internet."},
    6379: {"service": "Redis",       "severity": "CRITICAL", "cvss": 9.8,
           "desc": "Redis (port 6379) est accessible sans authentification par défaut. Exposition critique."},
    8080: {"service": "HTTP-Alt",    "severity": "MEDIUM",   "cvss": 5.3,
           "desc": "Port HTTP alternatif (8080) ouvert. Peut exposer une interface d'administration."},
    8443: {"service": "HTTPS-Alt",   "severity": "LOW",      "cvss": 3.1,
           "desc": "Port HTTPS alternatif (8443) ouvert."},
    27017:{"service": "MongoDB",     "severity": "CRITICAL", "cvss": 9.8,
           "desc": "MongoDB (port 27017) est accessible depuis l'extérieur. Souvent sans authentification par défaut."},
    1433: {"service": "MSSQL",       "severity": "CRITICAL", "cvss": 9.8,
           "desc": "Microsoft SQL Server (port 1433) est accessible depuis l'extérieur."},
    3389: {"service": "RDP",         "severity": "HIGH",     "cvss": 8.8,
           "desc": "RDP (port 3389) est ouvert. Cible fréquente d'attaques par brute-force et d'exploits."},
    4444: {"service": "Backdoor",    "severity": "CRITICAL", "cvss": 10.0,
           "desc": "Port 4444 ouvert — port classique de backdoor (Metasploit, etc.)."},
    5900: {"service": "VNC",         "severity": "HIGH",     "cvss": 8.8,
           "desc": "VNC (port 5900) est accessible. Accès bureau à distance potentiellement non sécurisé."},
    11211:{"service": "Memcached",   "severity": "HIGH",     "cvss": 7.5,
           "desc": "Memcached (port 11211) est accessible. Peut exposer des données en cache et être utilisé dans des attaques DDoS par amplification."},
    2181: {"service": "Zookeeper",   "severity": "HIGH",     "cvss": 7.5,
           "desc": "Zookeeper (port 2181) est accessible. Peut exposer la configuration de clusters distribués."},
    9200: {"service": "Elasticsearch","severity": "CRITICAL","cvss": 9.8,
           "desc": "Elasticsearch (port 9200) est accessible. Souvent sans authentification, expose toutes les données indexées."},
    9300: {"service": "Elasticsearch-Cluster","severity": "HIGH","cvss": 7.5,
           "desc": "Port de clustering Elasticsearch (9300) accessible depuis l'extérieur."},
}


def _check_port(host: str, port: int, timeout: float) -> bool:
    """Retourne True si le port TCP est ouvert."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start        = time.time()
        vulns        = []
        port_timeout = 2.0  # timeout par port (suffisant pour la plupart des firewalls)

        try:
            parsed = urlparse(url)
            host   = parsed.hostname
            if not host:
                return self.error("port_scanner", f"Impossible d'extraire l'hôte de l'URL : {url}", 0)

            ports_to_scan = list(PORTS.keys())
            open_ports    = []

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(_check_port, host, port, port_timeout): port
                           for port in ports_to_scan}
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                    except Exception:
                        pass

                    # Stop anticipé si timeout global dépassé
                    if (time.time() - start) > (timeout - 5):
                        break

            # Générer une vulnérabilité par port ouvert (sauf HTTPS qui est normal)
            for port in sorted(open_ports):
                info = PORTS[port]
                if port == 443:
                    continue  # HTTPS ouvert = normal, pas de vuln
                vulns.append(self.vuln(
                    name           = f"Port ouvert : {info['service']} ({port}/tcp)",
                    severity       = info["severity"],
                    cvss_score     = info["cvss"],
                    endpoint       = f"{host}:{port}",
                    description    = info["desc"],
                    recommendation = (
                        f"Si le service {info['service']} n'est pas nécessaire, "
                        f"fermer le port {port} dans le pare-feu. "
                        "Restreindre l'accès aux IP de confiance uniquement."
                    ),
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("port_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("port_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Port Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout global en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
