"""
Email Harvester — scrape les adresses email exposées sur le site cible.
"""
import sys, os, argparse, time, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

CONTACT_PATHS = ["/", "/contact", "/contact-us", "/about", "/about-us",
                 "/team", "/equipe", "/staff", "/people", "/company"]


class EmailHarvester(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "email_harvester"
        try:
            import requests
            from urllib.parse import urlparse

            base = url if url.startswith(("http://", "https://")) else f"http://{url}"
            parsed = urlparse(base)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.verify = False

            emails: set = set()
            paths = CONTACT_PATHS if depth in ("normal", "deep") else CONTACT_PATHS[:3]

            for path in paths:
                try:
                    r = session.get(origin + path, timeout=8, allow_redirects=True)
                    found = EMAIL_RE.findall(r.text)
                    for e in found:
                        # Filtre les faux positifs évidents
                        if not any(e.endswith(ext) for ext in (".png", ".jpg", ".gif", ".css", ".js")):
                            emails.add(e.lower())
                except Exception:
                    pass

            vulns = []
            if emails:
                sample = sorted(emails)[:10]
                vulns.append(self.vuln(
                    name=f"Adresses email exposées ({len(emails)} trouvées)",
                    severity="LOW",
                    cvss_score=3.1,
                    endpoint=origin,
                    description=(
                        f"{len(emails)} adresse(s) email trouvée(s) en clair sur le site. "
                        f"Exemples : {', '.join(sample[:5])}. "
                        "Ces emails peuvent être utilisés pour du phishing ou de la reconnaissance."
                    ),
                    recommendation=(
                        "Obfusquez les adresses email avec du JavaScript ou des images. "
                        "Utilisez des formulaires de contact plutôt que des adresses email directes. "
                        "Mettez en place un CAPTCHA sur les formulaires de contact."
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
    print(json.dumps(EmailHarvester().run(args.url, args.depth, args.timeout)))
