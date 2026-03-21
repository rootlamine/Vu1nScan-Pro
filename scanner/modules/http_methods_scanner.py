"""
Module VulnScan Pro : http_methods_scanner
Teste les méthodes HTTP activées sur le serveur (PUT, DELETE, TRACE, CONNECT, OPTIONS)
et signale les méthodes dangereuses.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


DANGEROUS_METHODS = {
    "PUT":     ("MEDIUM", 6.5, "Permet de téléverser ou modifier des fichiers sur le serveur."),
    "DELETE":  ("MEDIUM", 6.5, "Permet de supprimer des ressources sur le serveur."),
    "TRACE":   ("LOW",    4.3, "Peut être exploité pour des attaques Cross-Site Tracing (XST) et révèle les en-têtes de requête."),
    "CONNECT": ("MEDIUM", 5.8, "Peut être exploité pour créer des tunnels à travers le serveur (proxy abuse)."),
    "PATCH":   ("LOW",    3.5, "Peut permettre de modifier partiellement des ressources si non sécurisé."),
}

HTTP_METHODS_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
    "https://cwe.mitre.org/data/definitions/650.html",
    "https://developer.mozilla.org/fr/docs/Web/HTTP/Methods",
    "https://portswigger.net/web-security/request-smuggling",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 10)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 1. OPTIONS request to get allowed methods
            allowed_from_options = set()
            try:
                resp = session.options(url, timeout=req_timeout)
                allow_header = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
                if allow_header:
                    allowed_from_options = {m.strip().upper() for m in allow_header.split(",")}
            except requests.exceptions.RequestException:
                pass

            # 2. Probe each dangerous method
            for method, (severity, cvss, impact_desc) in DANGEROUS_METHODS.items():
                if (time.time() - start) > timeout * 0.8:
                    break
                method_found = method in allowed_from_options
                if not method_found:
                    # Try directly
                    try:
                        resp = session.request(
                            method, url, timeout=req_timeout, allow_redirects=False,
                            data="VulnScan-Pro-test" if method in ("PUT", "PATCH") else None,
                        )
                        # 200, 201, 204 = method accepted; 401/403 = exists but auth required
                        if resp.status_code not in (404, 405, 501, 503):
                            method_found = True
                    except requests.exceptions.RequestException:
                        pass

                if method_found:
                    cvss_vector = (
                        "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" if method in ("PUT", "DELETE")
                        else "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"
                    )
                    vulns.append(self.vuln(
                        name=f"Méthode HTTP dangereuse activée : {method}",
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector=cvss_vector,
                        cwe_id="CWE-650",
                        endpoint=url,
                        payload=f"{method} {url} HTTP/1.1",
                        description=(
                            f"La méthode HTTP {method} est activée sur le serveur. "
                            f"{impact_desc} "
                            "Cela représente une surface d'attaque inutile si non requise par l'application."
                        ),
                        impact=impact_desc,
                        evidence=f"Méthode {method} acceptée par le serveur (non retournée 405/404/501).",
                        recommendation=(
                            f"Désactiver la méthode {method} si elle n'est pas nécessaire. "
                            "Dans Apache : utilisez <LimitExcept GET POST>. "
                            "Dans Nginx : utilisez 'limit_except GET POST { deny all; }'. "
                            "Restreindre les méthodes autorisées au strict minimum (GET, POST, HEAD)."
                        ),
                        references=HTTP_METHODS_REFS,
                    ))

            # 3. TRACE method — special check (XST)
            if depth != "fast":
                try:
                    resp = session.request("TRACE", url, timeout=req_timeout)
                    if resp.status_code == 200 and "TRACE" in resp.text:
                        key = "TRACE_XST"
                        if key not in {v["name"] for v in vulns}:
                            vulns.append(self.vuln(
                                name="TRACE HTTP activé — risque Cross-Site Tracing (XST)",
                                severity="LOW",
                                cvss_score=4.3,
                                cvss_vector="AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
                                cwe_id="CWE-16",
                                endpoint=url,
                                payload="TRACE / HTTP/1.1",
                                description=(
                                    "La méthode TRACE est activée et le serveur renvoie la requête en echo. "
                                    "Cela peut permettre à un attaquant de lire des cookies HttpOnly "
                                    "via une attaque Cross-Site Tracing (XST)."
                                ),
                                impact="Lecture de cookies HttpOnly via XST en combinaison avec XSS.",
                                evidence="Méthode TRACE retourne HTTP 200 avec le corps de la requête en echo.",
                                recommendation=(
                                    "Désactiver la méthode TRACE. "
                                    "Apache : TraceEnable off. "
                                    "Nginx : 'if ($request_method = TRACE) { return 405; }'"
                                ),
                                references=HTTP_METHODS_REFS,
                            ))
                except requests.exceptions.RequestException:
                    pass

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("http_methods_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("http_methods_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — HTTP Methods Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
