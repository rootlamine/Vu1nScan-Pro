"""
Subdomain Enumeration — énumère les sous-domaines courants.
"""
import sys, os, argparse, time, json, socket
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]


WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "portal", "intranet", "dashboard", "app", "beta", "shop", "blog",
    "secure", "login", "auth", "cdn", "static", "assets", "media",
    "git", "jenkins", "jira", "confluence", "grafana", "prometheus",
]

EXTENDED = [
    "m", "mobile", "support", "help", "docs", "status", "monitor",
    "backup", "db", "database", "redis", "mysql", "postgres", "mongo",
    "internal", "private", "corp", "office", "hr", "finance",
]


class SubdomainEnum(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "subdomain_enum"
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
            domain = (parsed.netloc or parsed.path).split(":")[0].lstrip("www.")

            wordlist = WORDLIST + (EXTENDED if depth in ("normal", "deep") else [])

            found = []
            for sub in wordlist:
                fqdn = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    found.append((fqdn, ip))
                except socket.gaierror:
                    pass

            vulns = []
            if found:
                details = ", ".join(f"{f} ({ip})" for f, ip in found[:10])
                vulns.append(self.vuln(
                    name=f"Sous-domaines exposés ({len(found)} trouvés)",
                    severity="MEDIUM",
                    cvss_score=4.3,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    endpoint=domain,
                    description=(
                        f"{len(found)} sous-domaine(s) actif(s) découvert(s), élargissant la surface d'attaque. "
                        f"Trouvés : {details}."
                    ),
                    impact="Surface d'attaque élargie, environnements dev/staging potentiellement non sécurisés.",
                    evidence=f"{len(found)} sous-domaines résolus : {details}.",
                    recommendation=(
                        "Supprimez les sous-domaines non utilisés. Mettez en place un inventaire des actifs DNS. "
                        "Protégez les environnements de développement/staging avec une authentification."
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
    print(json.dumps(SubdomainEnum().run(args.url, args.depth, args.timeout)))
