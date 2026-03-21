"""
Module VulnScan Pro : csrf_scanner
Détecte l'absence de protection CSRF dans les formulaires HTML.
"""
import sys
import json
import argparse
import time
import re
import requests
from urllib.parse import urljoin

sys.path.insert(0, '..')
from core.base_module import BaseModule


CSRF_TOKEN_PATTERNS = [
    r'csrf', r'_token', r'authenticity_token', r'csrfmiddlewaretoken',
    r'xsrf', r'__requestverificationtoken', r'nonce',
]

FORM_ACTION_IGNORE = ['get']


class Module(BaseModule):

    def _has_csrf_token(self, form_html: str) -> bool:
        form_lower = form_html.lower()
        for pattern in CSRF_TOKEN_PATTERNS:
            if re.search(pattern, form_lower):
                return True
        return False

    def _extract_forms(self, html: str) -> list:
        return re.findall(r'<form[^>]*>.*?</form>', html, re.IGNORECASE | re.DOTALL)

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
            html = response.text
            forms = self._extract_forms(html)

            vulnerable_forms = 0
            for form in forms:
                method_match = re.search(r'method=["\']?(\w+)', form, re.IGNORECASE)
                method = method_match.group(1).lower() if method_match else "post"
                if method == "get":
                    continue  # GET forms are not CSRF-vulnerable
                if not self._has_csrf_token(form):
                    vulnerable_forms += 1

            if vulnerable_forms > 0:
                vulns.append(self.vuln(
                    name="Protection CSRF manquante",
                    severity="MEDIUM",
                    cvss_score=6.5,
                    endpoint=url,
                    description=(
                        f"{vulnerable_forms} formulaire(s) POST sans token CSRF détecté(s). "
                        "Un attaquant peut forger des requêtes au nom de l'utilisateur authentifié."
                    ),
                    recommendation=(
                        "Implémenter des tokens CSRF synchronisés (Synchronizer Token Pattern). "
                        "Utiliser les attributs SameSite=Strict sur les cookies de session."
                    ),
                ))

            # Vérifier l'en-tête SameSite sur les cookies
            cookies = response.cookies
            for cookie in cookies:
                if not hasattr(cookie, '_rest') or 'SameSite' not in str(cookie._rest):
                    if cookie.name.lower() in ['session', 'sessionid', 'phpsessid', 'jsessionid', 'auth']:
                        vulns.append(self.vuln(
                            name="Cookie de session sans attribut SameSite",
                            severity="MEDIUM",
                            cvss_score=5.4,
                            endpoint=url,
                            parameter=cookie.name,
                            description=f"Le cookie '{cookie.name}' n'a pas l'attribut SameSite, facilitant les attaques CSRF.",
                            recommendation="Ajouter SameSite=Strict ou SameSite=Lax sur tous les cookies de session.",
                        ))
                        break

        except requests.exceptions.Timeout:
            duration = int((time.time() - start) * 1000)
            return self.error("csrf_scanner", f"Timeout", duration)
        except requests.exceptions.ConnectionError as e:
            duration = int((time.time() - start) * 1000)
            return self.error("csrf_scanner", f"Connexion impossible : {e}", duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("csrf_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("csrf_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — CSRF Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
