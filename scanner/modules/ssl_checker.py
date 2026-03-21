"""
Module VulnScan Pro : ssl_checker
Vérifie le certificat SSL/TLS, la version du protocole et les chiffrements faibles.
"""
import sys
import json
import argparse
import time
import socket
import ssl
from datetime import datetime

sys.path.insert(0, '..')
from core.base_module import BaseModule


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if parsed.scheme != "https":
                # Site non HTTPS
                vulns.append(self.vuln(
                    name="HTTPS non utilisé",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    endpoint=url,
                    description="Le site n'utilise pas HTTPS. Les données transitent en clair sur le réseau.",
                    recommendation="Configurer un certificat SSL/TLS et rediriger HTTP vers HTTPS.",
                ))
                duration = int((time.time() - start) * 1000)
                return self.result("ssl_checker", vulns, duration)

            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            try:
                with socket.create_connection((hostname, port), timeout=min(timeout, 10)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        proto = ssock.version()
                        cipher = ssock.cipher()

                        # Vérifier expiration
                        not_after_str = cert.get("notAfter", "")
                        if not_after_str:
                            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (not_after - datetime.utcnow()).days
                            if days_left < 0:
                                vulns.append(self.vuln(
                                    name="Certificat SSL expiré",
                                    severity="CRITICAL",
                                    cvss_score=9.0,
                                    endpoint=url,
                                    description=f"Le certificat SSL a expiré le {not_after_str}.",
                                    recommendation="Renouveler immédiatement le certificat SSL/TLS.",
                                ))
                            elif days_left < 30:
                                vulns.append(self.vuln(
                                    name="Certificat SSL expire bientôt",
                                    severity="MEDIUM",
                                    cvss_score=5.3,
                                    endpoint=url,
                                    description=f"Le certificat SSL expire dans {days_left} jours.",
                                    recommendation="Renouveler le certificat SSL/TLS avant expiration.",
                                ))

                        # Vérifier version TLS obsolète
                        if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                            vulns.append(self.vuln(
                                name=f"Version TLS obsolète ({proto})",
                                severity="MEDIUM",
                                cvss_score=5.3,
                                endpoint=url,
                                description=f"Le serveur utilise {proto}, une version obsolète et vulnérable.",
                                recommendation="Configurer le serveur pour utiliser TLS 1.2 ou TLS 1.3 uniquement.",
                            ))

                        # Chiffrement faible
                        if cipher and any(weak in (cipher[0] or "") for weak in ["RC4", "DES", "NULL", "EXPORT", "MD5"]):
                            vulns.append(self.vuln(
                                name="Chiffrement SSL faible détecté",
                                severity="MEDIUM",
                                cvss_score=5.3,
                                endpoint=url,
                                description=f"Le serveur accepte le chiffrement faible : {cipher[0]}.",
                                recommendation="Désactiver les suites de chiffrement faibles et n'autoriser que AES-GCM.",
                            ))

            except ssl.SSLCertVerificationError as e:
                vulns.append(self.vuln(
                    name="Certificat SSL invalide ou non vérifié",
                    severity="HIGH",
                    cvss_score=7.5,
                    endpoint=url,
                    description=f"La vérification du certificat a échoué : {e}",
                    recommendation="Obtenir un certificat signé par une CA reconnue (ex: Let's Encrypt).",
                ))
            except ssl.SSLError as e:
                vulns.append(self.vuln(
                    name="Erreur SSL/TLS",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    endpoint=url,
                    description=f"Erreur lors de la connexion SSL : {e}",
                    recommendation="Vérifier la configuration SSL du serveur.",
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("ssl_checker", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("ssl_checker", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — SSL/TLS Checker")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
