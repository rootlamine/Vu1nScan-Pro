"""
Module VulnScan Pro : sensitive_files
Détecte les fichiers sensibles exposés publiquement sur le serveur.
"""
import sys
import json
import argparse
import time
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule

SENSITIVE_FILES_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
    "https://cwe.mitre.org/data/definitions/538.html",
    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
]


SENSITIVE_FILES = [
    ("/robots.txt",          "Fichier robots.txt exposé",     "LOW",    3.1, ["Disallow", "Allow", "User-agent"]),
    ("/sitemap.xml",         "Sitemap XML exposé",            "INFO",   0.0, ["<urlset", "<sitemapindex"]),
    ("/backup.zip",          "Archive de sauvegarde exposée", "CRITICAL", 9.8, [None]),
    ("/backup.tar.gz",       "Archive de sauvegarde exposée", "CRITICAL", 9.8, [None]),
    ("/backup.sql",          "Dump SQL exposé",               "CRITICAL", 9.8, ["INSERT INTO", "CREATE TABLE"]),
    ("/database.sql",        "Dump SQL exposé",               "CRITICAL", 9.8, ["INSERT INTO", "CREATE TABLE"]),
    ("/db.sql",              "Dump SQL exposé",               "CRITICAL", 9.8, ["INSERT INTO", "CREATE TABLE"]),
    ("/dump.sql",            "Dump SQL exposé",               "CRITICAL", 9.8, ["INSERT INTO", "CREATE TABLE"]),
    ("/config.bak",          "Fichier de config sauvegardé",  "HIGH",   8.0, [None]),
    ("/wp-config.php.bak",   "Config WordPress sauvegardée",  "CRITICAL", 9.8, [None]),
    ("/id_rsa",              "Clé privée SSH exposée",        "CRITICAL", 9.8, ["PRIVATE KEY", "RSA"]),
    ("/id_rsa.pub",          "Clé publique SSH exposée",      "MEDIUM",  5.8, ["ssh-rsa"]),
    ("/.htaccess",           "Fichier .htaccess exposé",      "MEDIUM",  5.8, ["RewriteRule", "Options", "AuthType"]),
    ("/crossdomain.xml",     "crossdomain.xml permissif",     "MEDIUM",  5.8, ["allow-access-from"]),
    ("/clientaccesspolicy.xml","clientaccesspolicy.xml exposé","LOW",    3.1, [None]),
    ("/README.md",           "README exposé (infos projet)",  "LOW",    3.1, [None]),
    ("/CHANGELOG.md",        "CHANGELOG exposé (versions)",   "LOW",    3.7, [None]),
    ("/composer.json",       "composer.json exposé",          "MEDIUM",  5.8, ["require"]),
    ("/package.json",        "package.json exposé",           "MEDIUM",  5.8, ["dependencies"]),
    ("/yarn.lock",           "yarn.lock exposé",              "LOW",    3.1, [None]),
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []

        base_url = url.rstrip('/')
        session = requests.Session()
        session.headers["User-Agent"] = "VulnScan-Pro/1.0"

        files_to_check = SENSITIVE_FILES if depth == "deep" else SENSITIVE_FILES[:12]
        per_req_timeout = min(timeout // max(len(files_to_check), 1), 5)

        try:
            for path, label, severity, cvss, signatures in files_to_check:
                if severity == "INFO" or cvss == 0.0:
                    continue  # Skip informational
                target = base_url + path
                try:
                    resp = session.get(target, timeout=per_req_timeout, allow_redirects=False)

                    if resp.status_code == 200:
                        content = resp.text[:2000]

                        # If signatures defined, verify content matches
                        if signatures and any(s is not None for s in signatures):
                            if not any(sig and sig.lower() in content.lower() for sig in signatures if sig):
                                continue  # False positive, content doesn't match

                        cvss_vector = (
                            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity == "CRITICAL"
                            else "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "HIGH"
                            else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                        )
                        vulns.append(self.vuln(
                            name=label,
                            severity=severity,
                            cvss_score=cvss,
                            cvss_vector=cvss_vector,
                            cwe_id="CWE-538",
                            endpoint=target,
                            description=(
                                f"Le fichier '{path}' est accessible publiquement (HTTP 200). "
                                "Ce fichier peut contenir des informations sensibles exploitables par un attaquant."
                            ),
                            evidence=f"Fichier '{path}' accessible, HTTP 200, contenu correspondant aux signatures attendues.",
                            impact="Fuite de credentials, clés SSH, dumps de base de données, configuration applicative.",
                            recommendation=(
                                f"Supprimer ou restreindre l'accès au fichier '{path}'. "
                                "Configurer le serveur web pour bloquer l'accès aux fichiers sensibles. "
                                "Ne jamais déployer de fichiers de sauvegarde sur un serveur de production."
                            ),
                            references=SENSITIVE_FILES_REFS,
                        ))

                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("sensitive_files", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("sensitive_files", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Sensitive Files")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
