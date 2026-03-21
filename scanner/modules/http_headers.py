"""
Module VulnScan Pro : http_headers
Vérifie les en-têtes de sécurité HTTP de la cible.
"""
import sys
import json
import argparse
import time
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


HTTP_HEADERS_REFS = [
    "https://owasp.org/www-project-secure-headers/",
    "https://securityheaders.com/",
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
]

HEADERS_TO_CHECK = [
    {
        "header": "Content-Security-Policy",
        "name":   "En-tête Content-Security-Policy manquant",
        "severity": "HIGH",
        "cvss":   7.5,
        "cve":    None,
        "desc":   "L'en-tête Content-Security-Policy (CSP) est absent. "
                  "Cela expose l'application aux attaques XSS et à l'injection de contenu.",
        "rec":    "Configurer une politique CSP stricte : "
                  "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    {
        "header": "Strict-Transport-Security",
        "name":   "En-tête HSTS manquant",
        "severity": "MEDIUM",
        "cvss":   6.1,
        "cve":    None,
        "desc":   "L'en-tête HTTP Strict Transport Security (HSTS) est absent. "
                  "Le navigateur peut se connecter en HTTP non chiffré.",
        "rec":    "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "header": "X-Frame-Options",
        "name":   "En-tête X-Frame-Options manquant",
        "severity": "MEDIUM",
        "cvss":   5.4,
        "cve":    None,
        "desc":   "L'en-tête X-Frame-Options est absent, ce qui permet l'inclusion "
                  "de la page dans une iframe et facilite les attaques de clickjacking.",
        "rec":    "Ajouter : X-Frame-Options: DENY  ou  X-Frame-Options: SAMEORIGIN",
    },
    {
        "header": "X-Content-Type-Options",
        "name":   "En-tête X-Content-Type-Options manquant",
        "severity": "LOW",
        "cvss":   3.7,
        "cve":    None,
        "desc":   "L'en-tête X-Content-Type-Options est absent. "
                  "Le navigateur peut interpréter les fichiers avec un type MIME incorrect.",
        "rec":    "Ajouter : X-Content-Type-Options: nosniff",
    },
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []

        try:
            response = requests.get(
                url,
                timeout=min(timeout, 15),
                allow_redirects=True,
                headers={"User-Agent": "VulnScan-Pro/1.0"},
            )
            resp_headers = {k.lower(): v for k, v in response.headers.items()}

            for check in HEADERS_TO_CHECK:
                if check["header"].lower() not in resp_headers:
                    vulns.append(self.vuln(
                        name           = check["name"],
                        severity       = check["severity"],
                        cvss_score     = check["cvss"],
                        endpoint       = url,
                        description    = check["desc"],
                        recommendation = check["rec"],
                        cve_id         = check["cve"],
                        references     = HTTP_HEADERS_REFS,
                    ))

        except requests.exceptions.Timeout:
            duration = int((time.time() - start) * 1000)
            return self.error("http_headers", f"Timeout après {timeout}s", duration)
        except requests.exceptions.ConnectionError as e:
            duration = int((time.time() - start) * 1000)
            return self.error("http_headers", f"Connexion impossible : {e}", duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("http_headers", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("http_headers", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — HTTP Headers checker")
    parser.add_argument("--url",     required=True,         help="URL cible")
    parser.add_argument("--depth",   default="normal",      help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30,  help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
