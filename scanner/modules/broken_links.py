"""
Broken Links — crawl le site et détecte les liens cassés (4xx, 5xx).
"""
import sys, os, argparse, time, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]


class BrokenLinks(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "broken_links"
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse
            import warnings
            warnings.filterwarnings("ignore")

            base = url if url.startswith(("http://", "https://")) else f"http://{url}"
            parsed = urlparse(base)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.verify = False

            max_pages = {"fast": 10, "normal": 30, "deep": 80}.get(depth, 30)

            visited: set = set()
            to_visit = [base]
            broken = []

            while to_visit and len(visited) < max_pages:
                current = to_visit.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                try:
                    r = session.get(current, timeout=8, allow_redirects=True)
                    if r.status_code >= 400:
                        broken.append((current, r.status_code))
                        continue

                    # Only crawl internal pages
                    if not r.headers.get("content-type", "").startswith("text/html"):
                        continue

                    soup = BeautifulSoup(r.text, "html.parser")
                    for tag in soup.find_all(["a", "link", "script", "img"], href=True):
                        href = tag.get("href") or tag.get("src") or ""
                        full = urljoin(current, href)
                        # Only follow internal links for crawling
                        if urlparse(full).netloc == parsed.netloc and full not in visited:
                            to_visit.append(full)

                    # Check external links too (just HEAD)
                    for a in soup.find_all("a", href=True):
                        href = urljoin(current, a["href"])
                        if urlparse(href).netloc != parsed.netloc and href not in visited:
                            visited.add(href)
                            try:
                                ext_r = session.head(href, timeout=5, allow_redirects=True)
                                if ext_r.status_code >= 400:
                                    broken.append((href, ext_r.status_code))
                            except Exception:
                                pass
                except Exception:
                    pass

            vulns = []
            server_errors = [(u, c) for u, c in broken if c >= 500]
            client_errors = [(u, c) for u, c in broken if 400 <= c < 500]

            if server_errors:
                sample = ", ".join(f"{u} [{c}]" for u, c in server_errors[:5])
                vulns.append(self.vuln(
                    name=f"Erreurs serveur détectées ({len(server_errors)} liens)",
                    severity="MEDIUM",
                    cvss_score=4.0,
                    endpoint=base,
                    description=(
                        f"{len(server_errors)} lien(s) retournant des erreurs serveur (5xx) détectés. "
                        f"Exemples : {sample}. "
                        "Les erreurs 5xx peuvent révéler des informations sur l'architecture interne."
                    ),
                    recommendation=(
                        "Corrigez ou supprimez les liens cassés. "
                        "Configurez des pages d'erreur personnalisées ne révélant pas d'informations techniques."
                    ),
                    references=OSINT_REFS,
                ))

            if client_errors:
                sample = ", ".join(f"{u} [{c}]" for u, c in client_errors[:5])
                vulns.append(self.vuln(
                    name=f"Liens cassés détectés ({len(client_errors)} liens 404)",
                    severity="LOW",
                    cvss_score=2.5,
                    endpoint=base,
                    description=(
                        f"{len(client_errors)} lien(s) cassé(s) (4xx) trouvés lors du crawl. "
                        f"Exemples : {sample}. "
                        "Les liens morts nuisent à l'expérience utilisateur et peuvent indiquer une maintenance insuffisante."
                    ),
                    recommendation=(
                        "Mettez en place une surveillance régulière des liens (ex: Google Search Console). "
                        "Supprimez ou redirigez (301) les URLs obsolètes."
                    ),
                    references=OSINT_REFS,
                ))

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
    print(json.dumps(BrokenLinks().run(args.url, args.depth, args.timeout)))
