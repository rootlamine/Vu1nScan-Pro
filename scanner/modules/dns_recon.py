"""
DNS Reconnaissance — énumère les enregistrements DNS et détecte les transferts de zone.
"""
import sys, os, argparse, time, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule


class DnsRecon(BaseModule):

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "dns_recon"
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.exception
            from urllib.parse import urlparse

            parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
            domain = (parsed.netloc or parsed.path).split(":")[0].lstrip("www.")

            vulns = []
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            records_found = {}

            for rtype in self.RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records_found[rtype] = [str(r) for r in answers]
                except Exception:
                    pass

            if records_found:
                info = " | ".join(
                    f"{t}: {', '.join(v[:2])}" for t, v in records_found.items()
                )
                vulns.append(self.vuln(
                    name="Enregistrements DNS exposés",
                    severity="LOW",
                    cvss_score=2.5,
                    endpoint=domain,
                    description=(
                        f"Les enregistrements DNS du domaine révèlent l'infrastructure réseau : {info}. "
                        "Ces informations peuvent faciliter la cartographie réseau par un attaquant."
                    ),
                    recommendation=(
                        "Limitez les enregistrements DNS aux stricts nécessaires. "
                        "N'exposez pas les adresses IP internes dans les enregistrements publics."
                    ),
                ))

            # Test zone transfer (AXFR) sur chaque nameserver
            ns_list = records_found.get("NS", [])
            for ns in ns_list[:3]:
                try:
                    ns_clean = ns.rstrip(".")
                    z = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=5))
                    if z:
                        names = [str(n) for n in z.nodes.keys()][:10]
                        vulns.append(self.vuln(
                            name="Transfert de zone DNS ouvert (AXFR)",
                            severity="CRITICAL",
                            cvss_score=9.1,
                            endpoint=f"{domain} via {ns_clean}",
                            description=(
                                f"Le nameserver {ns_clean} autorise les transferts de zone AXFR non authentifiés. "
                                f"Enregistrements exposés : {', '.join(names)}. "
                                "Un attaquant peut cartographier toute l'infrastructure interne."
                            ),
                            recommendation=(
                                "Désactivez le transfert de zone AXFR ou restreignez-le aux seuls "
                                "serveurs DNS secondaires autorisés via des ACLs IP."
                            ),
                            cve_id="CVE-1999-0532",
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
    print(json.dumps(DnsRecon().run(args.url, args.depth, args.timeout)))
