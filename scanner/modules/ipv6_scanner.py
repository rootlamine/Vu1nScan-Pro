"""
Module VulnScan Pro : ipv6_scanner
Résout l'enregistrement AAAA DNS de la cible et scanne les ports courants
sur l'adresse IPv6 pour détecter une exposition IPv6 non sécurisée.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import socket
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


IPV6_PORTS = [
    (80,   "HTTP"),
    (443,  "HTTPS"),
    (22,   "SSH"),
    (21,   "FTP"),
    (25,   "SMTP"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-alt"),
    (27017,"MongoDB"),
]

IPV6_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html",
]

SENSITIVE_PORTS = {3306, 5432, 6379, 27017, 22}


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 5)

        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]

            # 1. Resolve IPv6 (AAAA record)
            ipv6_addr = None
            try:
                results = socket.getaddrinfo(host, None, socket.AF_INET6)
                if results:
                    ipv6_addr = results[0][4][0]
            except (socket.gaierror, OSError):
                pass

            if not ipv6_addr:
                duration = int((time.time() - start) * 1000)
                return self.result("ipv6_scanner", [], duration)

            # 2. IPv6 accessible — report it
            vulns.append(self.vuln(
                name=f"Hôte accessible en IPv6 : {ipv6_addr}",
                severity="MEDIUM",
                cvss_score=4.5,
                endpoint=f"[{ipv6_addr}]",
                description=(
                    f"La cible '{host}' est accessible en IPv6 via l'adresse '{ipv6_addr}'. "
                    "Si les règles de pare-feu ne couvrent pas explicitement IPv6, "
                    "des services qui devraient être protégés peuvent être accessibles "
                    "en contournant les règles IPv4."
                ),
                recommendation=(
                    "Appliquer les mêmes règles de filtrage en IPv6 qu'en IPv4. "
                    "Désactiver IPv6 si non utilisé. "
                    "Auditer régulièrement les règles de pare-feu pour couvrir IPv4 et IPv6. "
                    "Utiliser des outils de scan IPv6 dans les audits de sécurité."
                ),
                references=IPV6_REFS,
            ))

            # 3. Scan ports on IPv6 address
            ports = IPV6_PORTS[:5] if depth == "fast" else IPV6_PORTS

            for port, service in ports:
                if (time.time() - start) > timeout * 0.85:
                    break
                try:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    result = sock.connect_ex((ipv6_addr, port, 0, 0))
                    sock.close()
                    if result == 0:
                        is_sensitive = port in SENSITIVE_PORTS
                        severity = "HIGH" if is_sensitive else "MEDIUM"
                        cvss = 7.5 if is_sensitive else 4.5
                        vulns.append(self.vuln(
                            name=f"Port {port}/{service} ouvert en IPv6",
                            severity=severity,
                            cvss_score=cvss,
                            endpoint=f"[{ipv6_addr}]:{port}",
                            description=(
                                f"Le port {port}/tcp ({service}) est ouvert sur l'adresse IPv6 '{ipv6_addr}'. "
                                f"{'Ce service sensible peut être exposé si les règles IPv6 ne sont pas configurées.' if is_sensitive else 'Ce port est accessible via IPv6.'}"
                            ),
                            recommendation=(
                                f"Vérifier que les règles de pare-feu IPv6 bloquent le port {port} si non nécessaire. "
                                "Implémenter ip6tables ou équivalent avec les mêmes règles qu'IPv4."
                            ),
                            references=IPV6_REFS,
                        ))
                except Exception:
                    pass

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("ipv6_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("ipv6_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — IPv6 Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
