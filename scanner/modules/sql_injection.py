"""
Module VulnScan Pro : sql_injection
Teste les paramètres GET de la cible avec des payloads SQL courants
et détecte les messages d'erreur SQL dans les réponses.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées (ex: testphp.vulnweb.com).
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


SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "1 AND 1=2",
]

SQL_ERROR_PATTERNS = [
    r"mysql_fetch",
    r"mysql_num_rows",
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlstate",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"pg::syntaxerror",
    r"unterminated string literal",
    r"supplied argument is not a valid mysql",
]

SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 60) -> dict:
        start   = time.time()
        vulns   = []
        seen    = set()
        req_timeout = min(timeout, 15)

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                duration = int((time.time() - start) * 1000)
                return self.result("sql_injection", [], duration)

            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"

            for param in params:
                if param in seen:
                    continue

                for payload in SQL_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = session.get(test_url, timeout=req_timeout, allow_redirects=True)
                        if SQL_ERROR_RE.search(resp.text):
                            seen.add(param)
                            vulns.append(self.vuln(
                                name           = "Injection SQL détectée",
                                severity       = "CRITICAL",
                                cvss_score     = 9.8,
                                endpoint       = url,
                                parameter      = param,
                                description    = (
                                    f"Injection SQL confirmée via le paramètre '{param}'. "
                                    f"Le payload « {payload} » provoque un message d'erreur "
                                    "révélant la technologie de base de données."
                                ),
                                payload        = payload,
                                recommendation = (
                                    "Utiliser des requêtes préparées (prepared statements) "
                                    "avec des paramètres liés. Ne jamais concaténer "
                                    "les entrées utilisateur dans les requêtes SQL."
                                ),
                                cve_id         = None,
                            ))
                            break

                    except requests.exceptions.RequestException:
                        continue

                    if depth == "fast" and (time.time() - start) > 20:
                        break

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("sql_injection", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("sql_injection", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — SQL Injection scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
