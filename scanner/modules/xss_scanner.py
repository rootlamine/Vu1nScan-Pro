"""
Module VulnScan Pro : xss_scanner
Détecte les vulnérabilités XSS réfléchi en testant :
  1. Les paramètres GET de l'URL cible
  2. Les formulaires HTML trouvés sur la page

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import requests
from bs4 import BeautifulSoup

sys.path.insert(0, '..')
from core.base_module import BaseModule


XSS_REFS = [
    "https://owasp.org/www-community/attacks/xss/",
    "https://cwe.mitre.org/data/definitions/79.html",
    "https://portswigger.net/web-security/cross-site-scripting",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 60) -> dict:
        start       = time.time()
        vulns       = []
        seen        = set()
        req_timeout = min(timeout, 15)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"

            # ── 1. Test des paramètres GET ────────────────────────────────
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for param in params:
                key = f"GET:{param}"
                if key in seen:
                    continue
                for payload in XSS_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = session.get(test_url, timeout=req_timeout, allow_redirects=True)
                        if payload in resp.text:
                            seen.add(key)
                            vulns.append(self.vuln(
                                name           = "Cross-Site Scripting (XSS) réfléchi — paramètre GET",
                                severity       = "HIGH",
                                cvss_score     = 7.2,
                                cvss_vector    = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                cwe_id         = "CWE-79",
                                endpoint       = url,
                                parameter      = param,
                                description    = (
                                    f"Le paramètre GET '{param}' réfléchit le payload XSS "
                                    f"« {payload} » sans encodage, permettant l'exécution "
                                    "de code JavaScript arbitraire dans le navigateur de la victime."
                                ),
                                payload        = payload,
                                impact         = "Vol de cookies de session, redirection malveillante, défacement de page, phishing ciblé.",
                                evidence       = f"Payload '{payload}' retrouvé tel quel dans la réponse HTTP sans encodage.",
                                recommendation = (
                                    "Encoder toutes les sorties HTML avec htmlspecialchars() ou équivalent. "
                                    "Valider et filtrer les entrées côté serveur. "
                                    "Implémenter une politique Content-Security-Policy (CSP) stricte."
                                ),
                                references     = XSS_REFS,
                            ))
                            break
                    except requests.exceptions.RequestException:
                        continue

            # ── 2. Test des formulaires HTML ──────────────────────────────
            if depth != "fast":
                try:
                    base_resp = session.get(url, timeout=req_timeout, allow_redirects=True)
                    soup      = BeautifulSoup(base_resp.text, 'html.parser')
                    forms     = soup.find_all('form')

                    for form in forms:
                        action = form.get('action', '')
                        method = form.get('method', 'get').lower()

                        # Construire l'URL cible du formulaire
                        if not action or action.startswith('?'):
                            form_url = url if not action else url.split('?')[0] + action
                        elif action.startswith('http'):
                            form_url = action
                        else:
                            form_url = f"{parsed.scheme}://{parsed.netloc}/{action.lstrip('/')}"

                        # Collecter les champs
                        inputs = form.find_all(['input', 'textarea', 'select'])
                        form_data = {}
                        for inp in inputs:
                            name = inp.get('name')
                            if not name:
                                continue
                            inp_type = inp.get('type', 'text').lower()
                            if inp_type in ('submit', 'button', 'image', 'reset', 'hidden'):
                                form_data[name] = inp.get('value', '')
                            else:
                                form_data[name] = 'test'

                        if not form_data:
                            continue

                        # Injecter les payloads dans chaque champ texte
                        for field in list(form_data.keys()):
                            key = f"FORM:{form_url}:{field}"
                            if key in seen:
                                continue
                            original = form_data.copy()
                            for payload in XSS_PAYLOADS[:2]:  # 2 payloads suffisent par champ
                                test_data = original.copy()
                                test_data[field] = payload
                                try:
                                    if method == 'post':
                                        resp = session.post(form_url, data=test_data, timeout=req_timeout)
                                    else:
                                        resp = session.get(form_url, params=test_data, timeout=req_timeout)

                                    if payload in resp.text:
                                        seen.add(key)
                                        vulns.append(self.vuln(
                                            name           = "Cross-Site Scripting (XSS) réfléchi — formulaire",
                                            severity       = "HIGH",
                                            cvss_score     = 7.2,
                                            cvss_vector    = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                            cwe_id         = "CWE-79",
                                            endpoint       = form_url,
                                            parameter      = field,
                                            description    = (
                                                f"Le champ '{field}' du formulaire ({method.upper()}) "
                                                f"réfléchit le payload XSS « {payload} » sans encodage."
                                            ),
                                            payload        = payload,
                                            impact         = "Vol de cookies de session, redirection malveillante, défacement de page, phishing ciblé.",
                                            evidence       = f"Payload '{payload}' retrouvé tel quel dans la réponse HTTP sans encodage.",
                                            recommendation = (
                                                "Encoder toutes les sorties HTML. "
                                                "Valider les entrées côté serveur. "
                                                "Mettre en place une CSP stricte."
                                            ),
                                            references     = XSS_REFS,
                                        ))
                                        break
                                except requests.exceptions.RequestException:
                                    continue

                except Exception:
                    pass  # L'analyse des formulaires est best-effort

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("xss_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("xss_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — XSS Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
