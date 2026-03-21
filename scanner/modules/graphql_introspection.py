"""
Module VulnScan Pro : graphql_introspection
Détecte les endpoints GraphQL et teste si l'introspection est activée,
ce qui expose le schéma complet de l'API GraphQL.

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


GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/api/gql",
    "/query",
    "/api/query",
    "/v1/graphql",
    "/api/v1/graphql",
    "/graphiql",
]

INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
INTROSPECTION_FULL = (
    '{"query":"{ __schema { queryType { name } mutationType { name } '
    'subscriptionType { name } types { name kind description } } }"}'
)

GRAPHQL_REFS = [
    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://graphql.org/learn/introspection/",
    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 10)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.headers["Content-Type"] = "application/json"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in GRAPHQL_ENDPOINTS:
                if (time.time() - start) > timeout * 0.85:
                    break
                target = f"{base_url}{path}"
                try:
                    # Quick probe to see if endpoint exists
                    probe = session.post(target, data=INTROSPECTION_QUERY, timeout=req_timeout)
                    if probe.status_code in (200, 400):
                        try:
                            data = probe.json()
                        except Exception:
                            continue

                        # 200 with __schema data = introspection enabled
                        if probe.status_code == 200 and "data" in data:
                            schema_data = data.get("data", {})
                            if "__schema" in str(schema_data):
                                type_count = 0
                                if isinstance(schema_data.get("__schema", {}).get("types"), list):
                                    type_count = len(schema_data["__schema"]["types"])

                                vulns.append(self.vuln(
                                    name="GraphQL Introspection activée",
                                    severity="MEDIUM",
                                    cvss_score=5.3,
                                    endpoint=target,
                                    payload=INTROSPECTION_QUERY,
                                    description=(
                                        f"L'endpoint GraphQL '{path}' a l'introspection activée. "
                                        f"Le schéma complet ({type_count} types) est accessible publiquement, "
                                        "révélant tous les types, champs, mutations et queries disponibles. "
                                        "Cela facilite grandement la reconnaissance pour un attaquant."
                                    ),
                                    recommendation=(
                                        "Désactiver l'introspection en production. "
                                        "Apollo Server: introspection: false. "
                                        "GraphQL Yoga: disableIntrospection(). "
                                        "Implémenter un contrôle d'accès sur les queries introspection. "
                                        "Utiliser query depth limiting et complexity analysis."
                                    ),
                                    references=GRAPHQL_REFS,
                                ))
                                break

                        # 400 with graphql error = endpoint exists but introspection disabled
                        elif probe.status_code == 400 or "errors" in data:
                            errors = data.get("errors", [])
                            if errors and any("introspection" in str(e).lower() for e in errors):
                                # Introspection explicitly disabled — good, but endpoint discovered
                                continue
                            elif errors:
                                # GraphQL endpoint found but responding — note as info
                                vulns.append(self.vuln(
                                    name="Endpoint GraphQL détecté (introspection désactivée)",
                                    severity="MEDIUM",
                                    cvss_score=5.3,
                                    endpoint=target,
                                    payload=INTROSPECTION_QUERY,
                                    description=(
                                        f"Un endpoint GraphQL a été détecté sur '{path}'. "
                                        "L'introspection semble désactivée, mais l'existence de l'endpoint "
                                        "est connue et peut être ciblée par des attaques de force brute "
                                        "de champs ou des injections GraphQL."
                                    ),
                                    recommendation=(
                                        "Implémenter un rate limiting sur les requêtes GraphQL. "
                                        "Activer query depth limiting et complexity analysis. "
                                        "Valider et sanitiser tous les arguments. "
                                        "Auditer les permissions sur chaque resolver."
                                    ),
                                    references=GRAPHQL_REFS,
                                ))
                                break

                except requests.exceptions.RequestException:
                    continue

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("graphql_introspection", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("graphql_introspection", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — GraphQL Introspection Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
