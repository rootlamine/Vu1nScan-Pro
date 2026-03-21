"""
WHOIS Lookup — récupère les infos WHOIS du domaine cible.
"""
import sys, os, argparse, time, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]


class WhoisLookup(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "whois_lookup"
        try:
            import whois as pywhois
            from urllib.parse import urlparse

            parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
            domain = (parsed.netloc or parsed.path).split(":")[0].lstrip("www.")

            vulns = []
            try:
                w = pywhois.whois(domain)

                info_parts = []
                if w.registrar:
                    info_parts.append(f"Registrar : {w.registrar}")
                if w.creation_date:
                    cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    info_parts.append(f"Créé le : {cd}")
                if w.expiration_date:
                    ed = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                    info_parts.append(f"Expire le : {ed}")
                if w.name_servers:
                    ns = list(w.name_servers)[:3] if isinstance(w.name_servers, (list, set)) else [w.name_servers]
                    info_parts.append(f"Nameservers : {', '.join(str(n).lower() for n in ns)}")
                if w.country:
                    info_parts.append(f"Pays : {w.country}")
                if w.emails:
                    emails = list(w.emails) if isinstance(w.emails, (list, set)) else [w.emails]
                    info_parts.append(f"Emails exposés : {', '.join(str(e) for e in emails[:3])}")
                if w.org:
                    info_parts.append(f"Organisation : {w.org}")

                if info_parts:
                    vulns.append(self.vuln(
                        name="Informations WHOIS publiques",
                        severity="LOW",
                        cvss_score=2.0,
                        endpoint=domain,
                        description=(
                            "Les informations WHOIS du domaine sont accessibles publiquement et peuvent "
                            "faciliter la reconnaissance d'un attaquant. "
                            + " | ".join(info_parts)
                        ),
                        recommendation=(
                            "Activez la protection WHOIS (privacy protection) auprès de votre registrar "
                            "pour masquer les informations personnelles et organisationnelles."
                        ),
                        references=OSINT_REFS,
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
    print(json.dumps(WhoisLookup().run(args.url, args.depth, args.timeout)))
