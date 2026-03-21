"""
Module VulnScan Pro : rate_limit_tester
Envoie 20 requêtes rapides sur /api/auth/login et détecte si le serveur
bloque ou limite les tentatives (protection contre brute force).

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


AUTH_ENDPOINTS = [
    "/api/auth/login",
    "/api/login",
    "/api/v1/auth/login",
    "/login",
    "/api/auth",
    "/api/token",
    "/api/v1/login",
    "/auth/login",
    "/api/signin",
    "/signin",
]

RATE_LIMIT_REFS = [
    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "https://cwe.mitre.org/data/definitions/307.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
]

TEST_PAYLOAD = json.dumps({"email": "test@test.com", "password": "wrongpassword123"})


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 5)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.headers["Content-Type"] = "application/json"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            num_requests = 20
            delay_between = 0.05  # 50ms between requests

            for endpoint in AUTH_ENDPOINTS:
                if (time.time() - start) > timeout * 0.9:
                    break
                target = f"{base_url}{endpoint}"

                # Quick check: does endpoint exist?
                try:
                    probe = session.post(target, data=TEST_PAYLOAD, timeout=req_timeout)
                    if probe.status_code in (404, 501, 503):
                        continue
                except requests.exceptions.RequestException:
                    continue

                # Flood test
                statuses = []
                blocked_at = None
                start_flood = time.time()

                for i in range(num_requests):
                    try:
                        r = session.post(target, data=TEST_PAYLOAD, timeout=req_timeout)
                        statuses.append(r.status_code)
                        if r.status_code in (429, 503) and blocked_at is None:
                            blocked_at = i + 1
                    except requests.exceptions.Timeout:
                        statuses.append(408)
                    except requests.exceptions.RequestException:
                        break
                    time.sleep(delay_between)

                if not statuses:
                    continue

                flood_duration = time.time() - start_flood

                if blocked_at:
                    # Rate limiting IS in place — good, but note at what threshold
                    if blocked_at > 10:
                        vulns.append(self.vuln(
                            name=f"Rate limiting insuffisant : bloqué après {blocked_at} tentatives",
                            severity="MEDIUM",
                            cvss_score=5.3,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-307",
                            endpoint=target,
                            description=(
                                f"L'endpoint '{endpoint}' implémente un rate limiting mais "
                                f"seulement après {blocked_at} tentatives ({num_requests} testées). "
                                "Un attaquant peut effectuer de nombreuses tentatives avant d'être bloqué."
                            ),
                            impact="Attaque brute force possible sur les identifiants, credential stuffing.",
                            evidence=f"Endpoint '{endpoint}' bloque uniquement après {blocked_at} tentatives.",
                            recommendation=(
                                "Réduire le seuil de blocage à 5-10 tentatives par IP. "
                                "Implémenter un délai exponentiel. "
                                "Utiliser des CAPTCHA après plusieurs échecs. "
                                "Logger et alerter sur les tentatives multiples."
                            ),
                            references=RATE_LIMIT_REFS,
                        ))
                else:
                    # No rate limiting detected
                    rate_200 = statuses.count(200)
                    rate_4xx = sum(1 for s in statuses if 400 <= s < 500 and s != 429)
                    if rate_200 + rate_4xx >= num_requests * 0.8:
                        vulns.append(self.vuln(
                            name="Absence de rate limiting sur l'endpoint d'authentification",
                            severity="MEDIUM",
                            cvss_score=5.3,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-307",
                            endpoint=target,
                            description=(
                                f"{num_requests} requêtes envoyées sur '{endpoint}' en "
                                f"{flood_duration:.1f}s sans aucun blocage (HTTP 429). "
                                "L'absence de rate limiting permet les attaques par force brute "
                                "et credential stuffing sur l'authentification."
                            ),
                            impact="Brute force illimité sur les credentials, credential stuffing, déni de service applicatif.",
                            evidence=f"{num_requests} requêtes POST sur '{endpoint}' en {flood_duration:.1f}s, aucun HTTP 429 reçu.",
                            recommendation=(
                                "Implémenter un rate limiting sur les endpoints d'authentification "
                                "(ex: 5 tentatives par IP par 15 minutes). "
                                "Utiliser des solutions comme express-rate-limit, fail2ban. "
                                "Ajouter un délai de réponse après échec. "
                                "Implémenter MFA pour les comptes sensibles."
                            ),
                            references=RATE_LIMIT_REFS,
                        ))
                # Only test the first working endpoint
                break

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("rate_limit_tester", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("rate_limit_tester", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Rate Limit Tester")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
