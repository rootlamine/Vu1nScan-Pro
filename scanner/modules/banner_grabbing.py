"""
Module VulnScan Pro : banner_grabbing
Connexion TCP/HTTP sur les ports ouverts pour récupérer les banners de service
et détecter les versions exposées.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import socket
import re
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


TARGET_PORTS = [
    (21,   "FTP"),
    (22,   "SSH"),
    (23,   "Telnet"),
    (25,   "SMTP"),
    (80,   "HTTP"),
    (110,  "POP3"),
    (143,  "IMAP"),
    (443,  "HTTPS"),
    (445,  "SMB"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (27017,"MongoDB"),
]

VERSION_PATTERNS = [
    (r"OpenSSH[_\-](\d+\.\d+)", "SSH", "OpenSSH"),
    (r"Apache[/ ](\d+\.\d+\.\d+)", "HTTP", "Apache"),
    (r"nginx[/ ](\d+\.\d+\.\d+)", "HTTP", "nginx"),
    (r"IIS[/ ](\d+\.\d+)", "HTTP", "IIS"),
    (r"MySQL.*(\d+\.\d+\.\d+)", "MySQL", "MySQL"),
    (r"PostgreSQL (\d+\.\d+)", "PostgreSQL", "PostgreSQL"),
    (r"Redis server v=(\d+\.\d+\.\d+)", "Redis", "Redis"),
    (r"ProFTPD (\d+\.\d+\.\d+)", "FTP", "ProFTPD"),
    (r"vsftpd (\d+\.\d+\.\d+)", "FTP", "vsftpd"),
    (r"Exim (\d+\.\d+)", "SMTP", "Exim"),
    (r"Postfix", "SMTP", "Postfix"),
    (r"Microsoft-IIS/(\d+\.\d+)", "HTTP", "Microsoft IIS"),
    (r"lighttpd/(\d+\.\d+\.\d+)", "HTTP", "lighttpd"),
    (r"(Mongo\w* \d+\.\d+\.\d+)", "MongoDB", "MongoDB"),
]

BANNER_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://www.sans.org/white-papers/33",
]


class Module(BaseModule):

    def _grab_banner_socket(self, host: str, port: int, timeout: float) -> str:
        """Attempt to grab a service banner via raw socket."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                # Send a probe for HTTP
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif port == 21:
                    pass  # FTP sends banner immediately
                elif port == 25:
                    sock.sendall(b"EHLO vulnscan.local\r\n")
                elif port == 6379:
                    sock.sendall(b"INFO server\r\n")
                elif port == 3306:
                    pass  # MySQL sends banner on connect
                try:
                    return sock.recv(1024).decode("utf-8", errors="ignore")
                except Exception:
                    return ""
        except Exception:
            return ""

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 5)
        socket_timeout = 3.0

        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]

            ports = TARGET_PORTS[:8] if depth == "fast" else TARGET_PORTS

            for port, service in ports:
                if (time.time() - start) > timeout * 0.85:
                    break
                banner = self._grab_banner_socket(host, port, socket_timeout)
                if not banner:
                    continue

                # Check for version information in banner
                version_found = None
                for pattern, proto, name in VERSION_PATTERNS:
                    m = re.search(pattern, banner, re.IGNORECASE)
                    if m:
                        version_found = (name, m.group(0)[:50])
                        break

                if version_found or len(banner.strip()) > 5:
                    svc_name, version_str = version_found if version_found else (service, banner.strip()[:40])
                    vulns.append(self.vuln(
                        name=f"Banner de service exposé : {svc_name} sur port {port}",
                        severity="MEDIUM",
                        cvss_score=5.0,
                        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-200",
                        endpoint=f"{host}:{port}",
                        description=(
                            f"Le service {service} (port {port}/tcp) expose son banner de version : "
                            f"'{version_str}'. "
                            "Les informations de version permettent à un attaquant de cibler des CVEs "
                            "spécifiques à cette version du logiciel."
                        ),
                        impact="Reconnaissance facilitée, ciblage de CVEs connus pour la version exposée.",
                        evidence=f"Banner reçu sur {host}:{port} : '{version_str}'.",
                        recommendation=(
                            "Masquer ou supprimer les banners de service. "
                            "Apache : ServerTokens Prod, ServerSignature Off. "
                            "Nginx : server_tokens off. "
                            "OpenSSH : supprimer la version dans sshd_config. "
                            "Mettre à jour tous les services vers les dernières versions."
                        ),
                        references=BANNER_REFS,
                    ))

            # Also grab HTTP headers for version info
            try:
                resp = requests.get(url, timeout=req_timeout, verify=False)
                server = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")
                for hdr_val in [server, x_powered]:
                    if not hdr_val:
                        continue
                    for pattern, proto, name in VERSION_PATTERNS:
                        m = re.search(pattern, hdr_val, re.IGNORECASE)
                        if m:
                            vulns.append(self.vuln(
                                name=f"Version de serveur exposée dans les en-têtes HTTP : {name}",
                                severity="MEDIUM",
                                cvss_score=5.0,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cwe_id="CWE-200",
                                endpoint=url,
                                description=(
                                    f"L'en-tête HTTP révèle la version du serveur : '{hdr_val}'. "
                                    "Cette information aide un attaquant à identifier les vulnérabilités connues."
                                ),
                                impact="Fingerprinting du stack technique, ciblage de CVEs connus.",
                                evidence=f"En-tête HTTP exposant la version : '{hdr_val}'.",
                                recommendation=(
                                    "Supprimer ou masquer les en-têtes Server et X-Powered-By. "
                                    "Apache : ServerTokens Prod. Nginx : server_tokens off. "
                                    "PHP : expose_php = Off dans php.ini."
                                ),
                                references=BANNER_REFS,
                            ))
                            break
            except Exception:
                pass

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("banner_grabbing", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("banner_grabbing", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Banner Grabbing")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
