"""
Module VulnScan Pro : open_redirect
Détecte les vulnérabilités de redirection ouverte non validée.
"""
import sys
import json
import argparse
import time
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, '..')
from core.base_module import BaseModule

OPEN_REDIRECT_REFS = [
    "https://cwe.mitre.org/data/definitions/601.html",
    "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
]


REDIRECT_PARAMS = [
    'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url',
    'returnto', 'next', 'url', 'target', 'dest', 'destination',
    'go', 'goto', 'link', 'forward', 'continue', 'ref',
]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%40legit.com",
    "/\\/evil.com",
]


class Module(BaseModule):

    def _is_redirected_to_external(self, response: requests.Response, payload: str) -> bool:
        # Check final URL after redirects
        final_url = response.url
        if "evil.com" in final_url:
            return True
        # Check Location header in history
        for resp in response.history:
            location = resp.headers.get("Location", "")
            if "evil.com" in location or location.startswith("//evil"):
                return True
        return False

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        found_params = set()

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.max_redirects = 5

            parsed = urlparse(url)
            url_params = parse_qs(parsed.query, keep_blank_values=True)

            # Identify redirect parameters in the URL
            params_to_test = []
            for param in url_params:
                if param.lower() in REDIRECT_PARAMS:
                    params_to_test.append(param)

            # Also test common redirect params even if not in URL
            if depth in ("normal", "deep"):
                for rp in REDIRECT_PARAMS[:5]:
                    if rp not in url_params and rp not in params_to_test:
                        params_to_test.append(rp)

            for param in params_to_test:
                if param in found_params:
                    continue
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in url_params.items()}
                    test_params[param] = payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        resp = session.get(
                            test_url,
                            timeout=min(timeout // max(len(params_to_test), 1), 8),
                            allow_redirects=True,
                        )
                        if self._is_redirected_to_external(resp, payload):
                            found_params.add(param)
                            vulns.append(self.vuln(
                                name="Redirection ouverte détectée",
                                severity="MEDIUM",
                                cvss_score=6.1,
                                endpoint=test_url,
                                parameter=param,
                                payload=payload,
                                description=(
                                    f"Le paramètre '{param}' permet une redirection vers un domaine externe arbitraire. "
                                    "Peut être exploité pour le phishing ou le vol de tokens OAuth."
                                ),
                                recommendation=(
                                    "Valider les URLs de redirection par rapport à une liste blanche de domaines autorisés. "
                                    "Ne jamais utiliser directement les entrées utilisateur comme URL de redirection."
                                ),
                                references=OPEN_REDIRECT_REFS,
                            ))
                            break
                    except requests.exceptions.TooManyRedirects:
                        continue
                    except Exception:
                        continue

        except requests.exceptions.Timeout:
            duration = int((time.time() - start) * 1000)
            return self.error("open_redirect", "Timeout", duration)
        except requests.exceptions.ConnectionError as e:
            duration = int((time.time() - start) * 1000)
            return self.error("open_redirect", f"Connexion impossible : {e}", duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("open_redirect", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("open_redirect", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Open Redirect")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
