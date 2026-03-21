"""
JavaScript Analyzer — analyse les fichiers JS pour détecter des secrets exposés.
"""
import sys, os, argparse, time, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

SECRET_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}",                               "AWS Access Key ID",         "CRITICAL", 9.8),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:\"'`]\s*[A-Za-z0-9/+=]{40}",
                                                          "AWS Secret Key",            "CRITICAL", 9.8),
    # Google
    (r"AIza[0-9A-Za-z\-_]{35}",                         "Google API Key",            "CRITICAL", 9.0),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                                                          "Google OAuth Client ID",    "HIGH",     7.5),
    # JWT
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                                                          "JWT Token exposé",          "HIGH",     7.5),
    # Generic secrets
    (r"(?i)(password|passwd|pwd)\s*[=:\"'`]\s*[\"'`]?([^\s\"'`;&]{8,})[\"'`]?",
                                                          "Mot de passe en clair",    "CRITICAL", 9.5),
    (r"(?i)(api[_\-]?key|apikey)\s*[=:\"'`]\s*[\"'`]?([A-Za-z0-9_\-]{16,})[\"'`]?",
                                                          "API Key exposée",           "HIGH",     8.5),
    (r"(?i)(secret[_\-]?key|secretkey)\s*[=:\"'`]\s*[\"'`]?([A-Za-z0-9_\-]{16,})[\"'`]?",
                                                          "Clé secrète exposée",       "CRITICAL", 9.5),
    (r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:\"'`]\s*[\"'`]?([A-Za-z0-9_\-\.]{20,})[\"'`]?",
                                                          "Token d'accès exposé",      "CRITICAL", 9.5),
    # Private key
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",     "Clé privée exposée",        "CRITICAL", 10.0),
    # Database URLs
    (r"(?i)(mongodb|mysql|postgres|redis):\/\/[^\"'\s]{10,}",
                                                          "URL de base de données",    "CRITICAL", 9.8),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24}",                        "Stripe Live Secret Key",    "CRITICAL", 9.8),
    # GitHub token
    (r"ghp_[A-Za-z0-9]{36}",                            "GitHub Personal Token",     "CRITICAL", 9.8),
    # Internal endpoints
    (r"(?i)internal[_\-]?api[_\-]?url\s*[=:\"'`]\s*[\"'`]?https?://[^\s\"'`]+",
                                                          "URL API interne exposée",   "HIGH",     7.0),
]

COMMENT_PATTERNS = [
    r"//\s*TODO[:\s].{10,}",
    r"//\s*FIXME[:\s].{10,}",
    r"//\s*HACK[:\s].{10,}",
    r"/\*[\s\S]*?(password|secret|key|token|credential)[\s\S]*?\*/",
]


class JavascriptAnalyzer(BaseModule):

    def _get_js_urls(self, base_url: str, session) -> list:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin
        try:
            r = session.get(base_url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            urls = []
            for tag in soup.find_all("script", src=True):
                src = urljoin(base_url, tag["src"])
                if src not in urls:
                    urls.append(src)
            return urls[:20]
        except Exception:
            return []

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "javascript_analyzer"
        try:
            import requests
            import warnings
            warnings.filterwarnings("ignore")

            base = url if url.startswith(("http://", "https://")) else f"http://{url}"
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.verify = False

            js_urls = self._get_js_urls(base, session)
            max_files = {"fast": 5, "normal": 10, "deep": 20}.get(depth, 10)

            vulns = []
            checked_patterns: set = set()

            for js_url in js_urls[:max_files]:
                try:
                    r = session.get(js_url, timeout=10)
                    content = r.text[:200000]  # max 200KB per file

                    for pattern, label, severity, cvss in SECRET_PATTERNS:
                        match = re.search(pattern, content)
                        if match:
                            key = f"{label}:{js_url}"
                            if key in checked_patterns:
                                continue
                            checked_patterns.add(key)

                            snippet = match.group(0)[:100].replace("\n", " ")
                            vulns.append(self.vuln(
                                name=f"{label} dans JavaScript",
                                severity=severity,
                                cvss_score=cvss,
                                endpoint=js_url,
                                description=(
                                    f"Un secret de type « {label} » a été détecté dans le fichier JavaScript. "
                                    f"Extrait : {snippet}... "
                                    "Ce secret est accessible à tout utilisateur consultant le site."
                                ),
                                recommendation=(
                                    "Ne jamais inclure de secrets dans le code JavaScript front-end. "
                                    "Utilisez des variables d'environnement côté serveur et une API proxy. "
                                    "Révoquez immédiatement les credentials compromis."
                                ),
                                payload=snippet,
                            ))

                    # Sensitive comments
                    for cpat in COMMENT_PATTERNS:
                        matches = re.findall(cpat, content, re.IGNORECASE)
                        for cm in matches[:2]:
                            snippet = cm[:100].strip()
                            vulns.append(self.vuln(
                                name="Commentaire sensible dans JavaScript",
                                severity="LOW",
                                cvss_score=3.1,
                                endpoint=js_url,
                                description=(
                                    f"Un commentaire potentiellement sensible a été trouvé dans le JS : {snippet}"
                                ),
                                recommendation=(
                                    "Supprimez tous les commentaires contenant des informations sensibles. "
                                    "Utilisez un minifier/obfuscator en production."
                                ),
                            ))

                except Exception:
                    pass

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
    print(json.dumps(JavascriptAnalyzer().run(args.url, args.depth, args.timeout)))
