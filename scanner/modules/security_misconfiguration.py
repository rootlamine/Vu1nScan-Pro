"""
Module VulnScan Pro : security_misconfiguration
Détecte les pages d'administration exposées et les mauvaises configurations courantes.
"""
import sys
import json
import argparse
import time
import requests
from urllib.parse import urljoin, urlparse

sys.path.insert(0, '..')
from core.base_module import BaseModule

SECURITY_MISC_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/",
    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "https://www.sans.org/white-papers/33",
]


ADMIN_PATHS = [
    ("/admin",           "Interface d'administration",    "HIGH",   7.2),
    ("/admin/",          "Interface d'administration",    "HIGH",   7.2),
    ("/administrator",   "Interface d'administration",    "HIGH",   7.2),
    ("/phpmyadmin",      "phpMyAdmin exposé",             "CRITICAL", 9.0),
    ("/pma",             "phpMyAdmin exposé",             "CRITICAL", 9.0),
    ("/wp-admin",        "WordPress Admin exposé",        "HIGH",   7.2),
    ("/wp-login.php",    "WordPress Login exposé",        "MEDIUM", 5.3),
    ("/.env",            "Fichier .env exposé",           "CRITICAL", 9.8),
    ("/.git",            "Dépôt Git exposé",              "HIGH",   8.0),
    ("/.git/config",     "Configuration Git exposée",     "HIGH",   8.0),
    ("/config.php",      "Fichier de configuration exposé","HIGH",  7.5),
    ("/web.config",      "Configuration IIS exposée",     "HIGH",   7.5),
    ("/server-status",   "Apache server-status exposé",   "MEDIUM", 5.3),
    ("/server-info",     "Apache server-info exposé",     "MEDIUM", 5.3),
    ("/phpinfo.php",     "PHPInfo exposé",                "HIGH",   7.5),
    ("/info.php",        "PHPInfo exposé",                "HIGH",   7.5),
    ("/console",         "Console d'administration",      "HIGH",   7.2),
    ("/actuator",        "Spring Boot Actuator exposé",   "HIGH",   7.5),
    ("/actuator/env",    "Spring Actuator /env exposé",   "CRITICAL", 9.1),
]

SENSITIVE_SIGNATURES = {
    "/.env":         ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "DATABASE_URL"],
    "/.git/config":  ["[core]", "[remote"],
    "/phpinfo.php":  ["PHP Version", "phpinfo()"],
    "/info.php":     ["PHP Version", "phpinfo()"],
    "/actuator/env": ["propertySources"],
}


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        found = set()

        base_url = url.rstrip('/')
        session = requests.Session()
        session.headers["User-Agent"] = "VulnScan-Pro/1.0"

        paths_to_check = ADMIN_PATHS if depth in ("normal", "deep") else ADMIN_PATHS[:8]
        per_req_timeout = min(timeout // max(len(paths_to_check), 1), 6)

        try:
            for path, label, severity, cvss in paths_to_check:
                target = base_url + path
                if target in found:
                    continue
                try:
                    resp = session.get(target, timeout=per_req_timeout, allow_redirects=False)

                    if resp.status_code in (200, 403):
                        found.add(target)
                        body_lower = resp.text.lower()

                        # Check if it's really sensitive content
                        if resp.status_code == 403 and path not in ("/.env", "/.git", "/.git/config"):
                            # 403 on admin paths still means the resource exists
                            description = (
                                f"La ressource '{path}' retourne HTTP {resp.status_code}. "
                                f"L'{label} est accessible depuis Internet."
                            )
                        else:
                            description = (
                                f"La ressource '{path}' est accessible (HTTP {resp.status_code}). "
                                f"{label} exposé publiquement."
                            )

                        # Check for sensitive content signatures
                        sigs = SENSITIVE_SIGNATURES.get(path, [])
                        if sigs and any(s.lower() in body_lower for s in sigs):
                            description += " Des informations sensibles sont visibles dans la réponse."
                            if severity == "HIGH":
                                severity = "CRITICAL"
                                cvss = 9.1

                        vulns.append(self.vuln(
                            name=f"{label} accessible",
                            severity=severity,
                            cvss_score=cvss,
                            endpoint=target,
                            description=description,
                            recommendation=(
                                f"Restreindre l'accès à '{path}' par IP, authentification forte, "
                                "ou le supprimer du serveur de production. "
                                "Configurer le pare-feu applicatif pour bloquer ces chemins."
                            ),
                            references=SECURITY_MISC_REFS,
                        ))

                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("security_misconfiguration", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("security_misconfiguration", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Security Misconfiguration")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
