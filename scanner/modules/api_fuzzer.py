"""
Module VulnScan Pro : api_fuzzer
Fuzz les endpoints API courants (/api/v1/, /graphql, /swagger, /admin, etc.)
sans token d'authentification pour détecter des accès non autorisés.

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


API_PATHS = [
    # API versioning
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/users", "/api/v1/admin", "/api/v1/config",
    "/api/v2/users", "/api/v2/admin",
    # Documentation
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/spec", "/spec.json",
    # GraphQL
    "/graphql", "/api/graphql", "/gql",
    # Admin
    "/admin", "/api/admin", "/api/v1/admin", "/admin/api",
    "/management", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    # Common endpoints
    "/api/users", "/api/accounts", "/api/profile",
    "/api/health", "/api/status", "/api/ping",
    "/api/config", "/api/settings", "/api/version",
    "/api/debug", "/api/test", "/api/internal",
    # Auth
    "/api/auth", "/api/login", "/api/register",
    "/api/token", "/api/refresh",
    # Files
    "/api/upload", "/api/files", "/api/export",
    # Debug
    "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",
]

SENSITIVE_PATHS = {
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/config", "/api/settings", "/api/debug",
    "/api/internal", "/admin",
}

API_FUZZER_REFS = [
    "https://owasp.org/www-project-api-security/",
    "https://cwe.mitre.org/data/definitions/285.html",
    "https://portswigger.net/web-security/api-testing",
    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 8)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            paths = API_PATHS[:20] if depth == "fast" else API_PATHS

            for path in paths:
                if (time.time() - start) > timeout * 0.85:
                    break
                target = f"{base_url}{path}"
                try:
                    resp = session.get(target, timeout=req_timeout, allow_redirects=True)
                    code = resp.status_code

                    # Accessible without auth (200, 201) — or auth required but endpoint exists (401)
                    if code in (200, 201):
                        is_sensitive = path in SENSITIVE_PATHS
                        severity = "HIGH" if is_sensitive else "MEDIUM"
                        cvss = 8.0 if is_sensitive else 5.3

                        # Check if response contains interesting data
                        content = resp.text[:500]
                        has_data = any(kw in content.lower() for kw in [
                            "user", "email", "token", "config", "password",
                            "secret", "key", "admin", "debug", "error",
                            "swagger", "openapi", "graphql", "schema",
                        ])

                        if has_data or is_sensitive:
                            vulns.append(self.vuln(
                                name=f"Endpoint API accessible sans authentification : {path}",
                                severity=severity,
                                cvss_score=cvss,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if is_sensitive else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cwe_id="CWE-285",
                                endpoint=target,
                                description=(
                                    f"L'endpoint '{path}' répond avec HTTP {code} sans token d'authentification. "
                                    f"{'Il expose des données ou configurations sensibles.' if has_data else 'Cet endpoint administratif est directement accessible.'}"
                                ),
                                impact="Accès non autorisé aux données utilisateurs, configuration, secrets applicatifs.",
                                evidence=f"HTTP {code} retourné sur '{path}' sans en-tête Authorization.",
                                recommendation=(
                                    "Protéger tous les endpoints API avec une authentification (JWT, OAuth2). "
                                    "Implémenter une autorisation basée sur les rôles (RBAC). "
                                    "Désactiver les endpoints de debug/actuator en production. "
                                    "Auditer régulièrement la surface d'attaque API."
                                ),
                                references=API_FUZZER_REFS,
                            ))
                    elif code == 401:
                        # Endpoint exists but requires auth — lower severity
                        if path in SENSITIVE_PATHS:
                            vulns.append(self.vuln(
                                name=f"Endpoint API sensible détecté (auth requise) : {path}",
                                severity="MEDIUM",
                                cvss_score=5.3,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cwe_id="CWE-285",
                                endpoint=target,
                                description=(
                                    f"L'endpoint sensible '{path}' existe et retourne HTTP 401. "
                                    "L'authentification est requise mais l'endpoint est exposé, "
                                    "ce qui révèle la surface d'attaque."
                                ),
                                impact="Énumération de la surface d'attaque, tentatives de brute-force sur les credentials.",
                                evidence=f"HTTP 401 retourné sur '{path}' — endpoint sensible confirmé.",
                                recommendation=(
                                    "Masquer ou renommer les endpoints administratifs. "
                                    "Implémenter une authentification forte. "
                                    "Envisager d'exposer ces endpoints uniquement sur un réseau interne."
                                ),
                                references=API_FUZZER_REFS,
                            ))

                except requests.exceptions.RequestException:
                    continue

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("api_fuzzer", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("api_fuzzer", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — API Fuzzer")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
