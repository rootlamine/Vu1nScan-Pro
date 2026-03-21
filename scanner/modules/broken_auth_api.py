"""
Module VulnScan Pro : broken_auth_api
Teste les vulnérabilités d'authentification et d'autorisation sur les APIs :
IDOR sur /api/users/1, /api/users/2, accès sans token, tokens invalides/expirés.

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


IDOR_PATHS = [
    "/api/users/1", "/api/users/2", "/api/users/3",
    "/api/user/1", "/api/user/2",
    "/api/accounts/1", "/api/accounts/2",
    "/api/profile/1", "/api/profile/2",
    "/api/v1/users/1", "/api/v1/users/2",
    "/api/orders/1", "/api/orders/2",
    "/api/admin/users/1",
]

UNAUTH_PATHS = [
    "/api/users", "/api/user", "/api/accounts",
    "/api/v1/users", "/api/v2/users",
    "/api/admin/users", "/api/admin/stats",
    "/api/me", "/api/profile",
]

INVALID_TOKENS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIiwicm9sZSI6IkFETUlOIn0.",
    "invalid_token_12345",
    "null",
    "undefined",
    "Bearer ",
]

BROKEN_AUTH_REFS = [
    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "https://cwe.mitre.org/data/definitions/284.html",
    "https://portswigger.net/web-security/access-control/idor",
    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
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

            # 1. IDOR test — access resource IDs sequentially
            idor_found = []
            for path in IDOR_PATHS[:8 if depth == "fast" else len(IDOR_PATHS)]:
                if (time.time() - start) > timeout * 0.4:
                    break
                target = f"{base_url}{path}"
                try:
                    resp = session.get(target, timeout=req_timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        content = resp.text[:300]
                        if any(kw in content.lower() for kw in ["id", "user", "email", "name", "role"]):
                            idor_found.append((path, resp.status_code))
                except requests.exceptions.RequestException:
                    continue

            if len(idor_found) >= 2:
                # Multiple sequential IDs accessible = IDOR confirmed
                paths_str = ", ".join(p for p, _ in idor_found[:3])
                vulns.append(self.vuln(
                    name="IDOR (Insecure Direct Object Reference) détecté",
                    severity="HIGH",
                    cvss_score=8.8,
                    cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-639",
                    endpoint=f"{base_url}/api/users/{{id}}",
                    description=(
                        f"Les endpoints {paths_str} retournent des données sans vérification "
                        "d'autorisation (accessible sans token). Un attaquant peut énumérer "
                        "les IDs pour accéder aux données de tous les utilisateurs."
                    ),
                    impact="Accès non autorisé aux données de tous les utilisateurs par énumération d'ID.",
                    evidence=f"Endpoints {paths_str} retournent HTTP 200 avec données utilisateur sans token d'auth.",
                    recommendation=(
                        "Implémenter un contrôle d'accès basé sur l'identité authentifiée. "
                        "Vérifier que l'utilisateur connecté possède le droit d'accès à la ressource. "
                        "Utiliser des UUIDs non-séquentiels comme identifiants. "
                        "Ne jamais supposer qu'un client ne devinera pas les IDs."
                    ),
                    references=BROKEN_AUTH_REFS,
                ))

            # 2. Unauthorized access — endpoints without any token
            for path in UNAUTH_PATHS[:8 if depth == "fast" else len(UNAUTH_PATHS)]:
                if (time.time() - start) > timeout * 0.7:
                    break
                target = f"{base_url}{path}"
                try:
                    resp = session.get(target, timeout=req_timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        content = resp.text
                        is_json = "application/json" in resp.headers.get("Content-Type", "")
                        has_user_data = any(kw in content.lower() for kw in
                                           ["email", "password", "token", "role", "admin", "users"])
                        if is_json and has_user_data:
                            vulns.append(self.vuln(
                                name=f"Accès non authentifié à des données sensibles : {path}",
                                severity="HIGH",
                                cvss_score=8.8,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-284",
                                endpoint=target,
                                description=(
                                    f"L'endpoint '{path}' expose des données utilisateur sensibles "
                                    "sans authentification requise. "
                                    "N'importe quelle personne peut accéder à ces informations."
                                ),
                                impact="Fuite massive de données utilisateur (emails, rôles, tokens) sans authentification.",
                                evidence=f"HTTP 200 sur '{path}' sans Authorization header, réponse JSON contenant des données sensibles.",
                                recommendation=(
                                    "Requérir un token JWT valide pour tous les endpoints sensibles. "
                                    "Implémenter un middleware d'authentification sur toutes les routes API. "
                                    "Auditer régulièrement les endpoints non protégés."
                                ),
                                references=BROKEN_AUTH_REFS,
                            ))
                except requests.exceptions.RequestException:
                    continue

            # 3. Invalid/expired token test
            if depth != "fast":
                for token in INVALID_TOKENS[:3]:
                    for path in ["/api/me", "/api/profile", "/api/users"]:
                        target = f"{base_url}{path}"
                        try:
                            headers = {"Authorization": f"Bearer {token}"}
                            resp = session.get(target, timeout=req_timeout, headers=headers)
                            if resp.status_code == 200:
                                vulns.append(self.vuln(
                                    name="Token JWT invalide accepté (auth bypassée)",
                                    severity="HIGH",
                                    cvss_score=8.8,
                                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    cwe_id="CWE-287",
                                    endpoint=target,
                                    payload=f"Authorization: Bearer {token[:30]}…",
                                    description=(
                                        f"L'endpoint '{path}' accepte un token JWT invalide/malformé "
                                        f"('{token[:20]}…') et retourne des données. "
                                        "La validation du token est défaillante."
                                    ),
                                    impact="Contournement total de l'authentification, accès aux ressources protégées.",
                                    evidence=f"HTTP 200 retourné sur '{path}' avec token JWT invalide '{token[:20]}…'.",
                                    recommendation=(
                                        "Valider strictement les signatures JWT (algorithme, expiration, issuer). "
                                        "Rejeter les algorithmes 'none'. "
                                        "Utiliser une librairie JWT reconnue et à jour."
                                    ),
                                    references=BROKEN_AUTH_REFS,
                                ))
                                break
                        except requests.exceptions.RequestException:
                            continue
                    if (time.time() - start) > timeout * 0.9:
                        break

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("broken_auth_api", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("broken_auth_api", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Broken Auth API Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
