"""
Google Dorks — génère des requêtes de recherche avancées sur le domaine cible.
Utilise DuckDuckGo HTML (sans API key) pour récupérer les résultats.
"""
import sys, os, argparse, time, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]

DORKS = [
    ("filetype:pdf",      "Documents PDF exposés",            "MEDIUM", 4.3),
    ("filetype:sql",      "Dumps SQL exposés",                "HIGH",   7.5),
    ("filetype:log",      "Fichiers de logs exposés",         "HIGH",   7.2),
    ("filetype:env",      "Fichiers .env exposés",            "CRITICAL", 9.1),
    ("filetype:bak",      "Fichiers de sauvegarde exposés",   "HIGH",   7.5),
    ("inurl:admin",       "Pages admin indexées",             "HIGH",   7.0),
    ("inurl:login",       "Pages de connexion indexées",      "MEDIUM", 4.5),
    ("inurl:config",      "Fichiers de config indexés",       "HIGH",   7.5),
    ("inurl:backup",      "Répertoires backup indexés",       "HIGH",   7.5),
    ("intext:password",   "Pages contenant 'password'",       "HIGH",   7.0),
    ("intext:username",   "Pages contenant 'username'",       "MEDIUM", 5.0),
    ("intext:api_key",    "Pages contenant 'api_key'",        "CRITICAL", 9.0),
    ("intext:secret_key", "Pages contenant 'secret_key'",     "CRITICAL", 9.0),
    ("site:github.com",   "Code source sur GitHub",           "MEDIUM", 5.5),
]

CRED_PATTERNS = [
    r"password\s*[=:]\s*\S+",
    r"api[_\-]?key\s*[=:]\s*\S+",
    r"secret[_\-]?key\s*[=:]\s*\S+",
    r"access[_\-]?token\s*[=:]\s*\S+",
]


class GoogleDorks(BaseModule):

    def _search_ddg(self, query: str, session, timeout: int) -> list:
        """Recherche sur DuckDuckGo HTML et retourne les URLs trouvées."""
        try:
            r = session.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query, "kl": "fr-fr"},
                timeout=timeout,
                allow_redirects=True,
            )
            if r.status_code != 200:
                return []
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            results = []
            for a in soup.select("a.result__url"):
                href = a.get("href") or a.get_text(strip=True)
                if href:
                    results.append(href)
            return results[:5]
        except Exception:
            return []

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "google_dorks"
        try:
            import requests
            from urllib.parse import urlparse
            import warnings
            warnings.filterwarnings("ignore")

            parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
            domain = (parsed.netloc or parsed.path).split(":")[0].lstrip("www.")

            session = requests.Session()
            session.headers["User-Agent"] = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            session.verify = False

            dork_list = DORKS if depth in ("normal", "deep") else DORKS[:6]
            vulns = []

            for dork_suffix, label, severity, cvss in dork_list:
                query = f"site:{domain} {dork_suffix}"
                results = self._search_ddg(query, session, min(timeout, 10))

                if results:
                    # Check for credential leaks in results
                    has_creds = any(
                        re.search(p, str(r), re.IGNORECASE)
                        for p in CRED_PATTERNS
                        for r in results
                    )
                    final_sev = "CRITICAL" if has_creds else severity
                    final_cvss = 9.5 if has_creds else cvss

                    vulns.append(self.vuln(
                        name=f"Dork : {label}",
                        severity=final_sev,
                        cvss_score=final_cvss,
                        endpoint=domain,
                        description=(
                            f"La requête « {query} » retourne des résultats indexés. "
                            f"URLs trouvées : {', '.join(results[:3])}. "
                            "Ces informations sont publiquement accessibles via les moteurs de recherche."
                        ),
                        recommendation=(
                            "Ajoutez un fichier robots.txt restrictif. "
                            "Utilisez des balises <meta name='robots' content='noindex'> sur les pages sensibles. "
                            "Supprimez immédiatement tout credential exposé et révoquez les clés compromises."
                        ),
                        payload=query,
                        references=OSINT_REFS,
                    ))

                time.sleep(1)  # Evite le rate-limiting

            duration = int((time.time() - start) * 1000)
            return self.result(module, vulns, duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error(module, str(e), duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",     required=True)
    parser.add_argument("--depth",   default="normal")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(GoogleDorks().run(args.url, args.depth, args.timeout)))
